#!/usr/bin/env python3
"""
EVS PCAP to COD Converter
Converts EVS (Enhanced Voice Services) RTP packets from PCAP files to COD format.

ETSI TS 126 445 V18.0.0 (2024-06)
"""
import sys
import struct
import logging
import argparse
from pathlib import Path
from bitarray import bitarray
from scapy.packet import Packet
from scapy.contrib.rtcp import RTCP
from scapy.all import rdpcap, UDP, IP, RTP, Raw
from typing import Dict, List, Tuple, Set, Optional, IO
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Configure console
console = Console()

# Configure logging with Rich
logger = logging.getLogger(__name__)

# =============================================================================
# Bit Manipulation Utilities
# =============================================================================

def bytes_to_bitarray(data: bytes) -> bitarray:
    """
    Convert bytes to bitarray.
    
    Args:
        data: Input bytes
        
    Returns:
        bitarray representation with MSB first
    """
    return bitarray(endian='big', buffer=data)


def bitarray_to_bytes(bits: bitarray) -> bytes:
    """
    Convert bitarray to bytes with octet alignment.
    Implements padding per section A.2.2.1.4.1
    
    Args:
        bits: Input bitarray
        
    Returns:
        Bytes with padding to align to octet boundary
    """
    # Pad to byte boundary with zeros
    padding_needed = (8 - len(bits) % 8) % 8
    if padding_needed:
        bits = bits + bitarray('0' * padding_needed)
    
    return bits.tobytes()


# =============================================================================
# EVS Format Constants
# =============================================================================

# Compact format size mapping (Table A.1) - PRIMARY SOURCE FOR ALL CONSTANTS
COMPACT_SIZE_MAP: Dict[int, Dict[str, any]] = {
    48:   {"mode": "Primary", "rate": "2.4 kbps SID", "ft": 12},
    56:   {"mode": "Primary", "rate": "2.8 kbps", "ft": 0},
    136:  {"mode": "AMR-WB IO", "rate": "6.6 kbps", "ft": 0, "speech_bits": 132},
    144:  {"mode": "Primary", "rate": "7.2 kbps", "ft": 1},
    160:  {"mode": "Primary", "rate": "8.0 kbps", "ft": 2},
    184:  {"mode": "AMR-WB IO", "rate": "8.85 kbps", "ft": 1, "speech_bits": 177},
    192:  {"mode": "Primary", "rate": "9.6 kbps", "ft": 3},
    256:  {"mode": "AMR-WB IO", "rate": "12.65 kbps", "ft": 2, "speech_bits": 253},
    264:  {"mode": "Primary", "rate": "13.2 kbps", "ft": 4},
    288:  {"mode": "AMR-WB IO", "rate": "14.25 kbps", "ft": 3, "speech_bits": 285},
    320:  {"mode": "AMR-WB IO", "rate": "15.85 kbps", "ft": 4, "speech_bits": 317},
    328:  {"mode": "Primary", "rate": "16.4 kbps", "ft": 5},
    368:  {"mode": "AMR-WB IO", "rate": "18.25 kbps", "ft": 5, "speech_bits": 365},
    400:  {"mode": "AMR-WB IO", "rate": "19.85 kbps", "ft": 6, "speech_bits": 397},
    464:  {"mode": "AMR-WB IO", "rate": "23.05 kbps", "ft": 7, "speech_bits": 461},
    480:  {"mode": "AMR-WB IO", "rate": "23.85 kbps", "ft": 8, "speech_bits": 477},
    488:  {"mode": "Primary", "rate": "24.4 kbps", "ft": 6},
    640:  {"mode": "Primary", "rate": "32.0 kbps", "ft": 7},
    960:  {"mode": "Primary", "rate": "48.0 kbps", "ft": 8},
    1280: {"mode": "Primary", "rate": "64.0 kbps", "ft": 9},
    1920: {"mode": "Primary", "rate": "96.0 kbps", "ft": 10},
    2560: {"mode": "Primary", "rate": "128.0 kbps", "ft": 11}
}

# Derive IO_MODES from COMPACT_SIZE_MAP (AMR-WB IO modes only)
# Format: bits length: (FT code for ToC, number of speech bits K)
IO_MODES: Dict[int, Tuple[int, int]] = {
    size: (info["ft"], info["speech_bits"])
    for size, info in COMPACT_SIZE_MAP.items()
    if info["mode"] == "AMR-WB IO" and "speech_bits" in info
}

# Derive PROTECTED_SIZES from COMPACT_SIZE_MAP (all sizes are protected)
PROTECTED_SIZES: Set[int] = set(COMPACT_SIZE_MAP.keys())

# Frame type mappings (Tables A.4)
FT_PRIMARY: Dict[int, str] = {
    0x0: "2.8 kbps",
    0x1: "7.2 kbps",
    0x2: "8.0 kbps",
    0x3: "9.6 kbps",
    0x4: "13.2 kbps",
    0x5: "16.4 kbps",
    0x6: "24.4 kbps",
    0x7: "32.0 kbps",
    0x8: "48.0 kbps",
    0x9: "64.0 kbps",
    0xA: "96.0 kbps",
    0xB: "128.0 kbps",
    0xC: "2.4 kbps SID",
    0xD: "For future use",
    0xE: "SPEECH_LOST",
    0xF: "NO_DATA",
}

# Frame type mappings (Tables A.5)
FT_IO: Dict[int, str] = {
    0:  "6.6 kbps",
    1:  "8.85 kbps",
    2:  "12.65 kbps",
    3:  "14.25 kbps",
    4:  "15.85 kbps",
    5:  "18.25 kbps",
    6:  "19.85 kbps",
    7:  "23.05 kbps",
    8:  "23.85 kbps",
    9:  "2.0 kbps SID",
    10: "FOR_FUTURE_USE",
    11: "FOR_FUTURE_USE",
    12: "FOR_FUTURE_USE",
    13: "FOR_FUTURE_USE",
    14: "SPEECH_LOST",
    15: "NO_DATA",
}

# Build rate-to-size mapping
RATE_TO_SIZE_MAP: Dict[str, int] = {v["rate"]: size for size, v in COMPACT_SIZE_MAP.items()}
RATE_TO_SIZE_MAP['2.0 kbps SID'] = 40  # Per figure A.6

# Table A.2: 3-bit signaling element and EVS AMR-WB IO/AMR-WB CMR
COMPACT_CMR_AMR_WB: Dict[int, str] = {
    0: "EVS AMR-WB IO 6.60 kbps",
    1: "EVS AMR-WB IO 8.85 kbps",
    2: "EVS AMR-WB IO 12.65 kbps",
    3: "EVS AMR-WB IO 15.85 kbps",
    4: "EVS AMR-WB IO 18.25 kbps",
    5: "EVS AMR-WB IO 23.05 kbps",
    6: "EVS AMR-WB IO 23.85 kbps",
    7: "none (No Request)"
}


# Table A.3: Structure of the CMR byte (Header-Full)
# T: Type (3 bits, Keys: 0-7), D: Definition (4 bits, Keys: 0-15)
FULL_HEADER_CMR: Dict[int, Dict[int, str]] = {
    0: { # T=000: EVS Primary Narrowband (NB)
        0: "EVS Primary NB 5.9 kbps (VBR)",
        1: "EVS Primary NB 7.2 kbps",
        2: "EVS Primary NB 8.0 kbps",
        3: "EVS Primary NB 9.6 kbps",
        4: "EVS Primary NB 13.2 kbps",
        5: "EVS Primary NB 16.4 kbps",
        6: "EVS Primary NB 24.4 kbps"
    },
    1: { # T=001: EVS AMR-WB IO
        0: "EVS AMR-WB IO 6.60 kbps",
        1: "EVS AMR-WB IO 8.85 kbps",
        2: "EVS AMR-WB IO 12.65 kbps",
        3: "EVS AMR-WB IO 14.25 kbps",
        4: "EVS AMR-WB IO 15.85 kbps",
        5: "EVS AMR-WB IO 18.25 kbps",
        6: "EVS AMR-WB IO 19.85 kbps",
        7: "EVS AMR-WB IO 23.05 kbps",
        8: "EVS AMR-WB IO 23.85 kbps"
    },
    2: { # T=010: EVS Primary Wideband (WB)
        0: "EVS Primary WB 5.9 kbps (VBR)",
        1: "EVS Primary WB 7.2 kbps",
        2: "EVS Primary WB 8.0 kbps",
        3: "EVS Primary WB 9.6 kbps",
        4: "EVS Primary WB 13.2 kbps",
        5: "EVS Primary WB 16.4 kbps",
        6: "EVS Primary WB 24.4 kbps",
        7: "EVS Primary WB 32 kbps",
        8: "EVS Primary WB 48 kbps",
        9: "EVS Primary WB 64 kbps",
        10: "EVS Primary WB 96 kbps",
        11: "EVS Primary WB 128 kbps"
    },
    3: { # T=011: EVS Primary Super-Wideband (SWB)
        3: "EVS Primary SWB 9.6 kbps",
        4: "EVS Primary SWB 13.2 kbps",
        5: "EVS Primary SWB 16.4 kbps",
        6: "EVS Primary SWB 24.4 kbps",
        7: "EVS Primary SWB 32 kbps",
        8: "EVS Primary SWB 48 kbps",
        9: "EVS Primary SWB 64 kbps",
        10: "EVS Primary SWB 96 kbps",
        11: "EVS Primary SWB 128 kbps"
    },
    4: { # T=100: EVS Primary Fullband (FB)
        5: "EVS Primary FB 16.4 kbps",
        6: "EVS Primary FB 24.4 kbps",
        7: "EVS Primary FB 32 kbps",
        8: "EVS Primary FB 48 kbps",
        9: "EVS Primary FB 64 kbps",
        10: "EVS Primary FB 96 kbps",
        11: "EVS Primary FB 128 kbps"
    },
    5: { # T=101: EVS Primary WB Channel-Aware (CA)
        0: "EVS Primary WB 13.2 CA-L-O2",
        1: "EVS Primary WB 13.2 CA-L-O3",
        2: "EVS Primary WB 13.2 CA-L-O5",
        3: "EVS Primary WB 13.2 CA-L-O7",
        4: "EVS Primary WB 13.2 CA-H-O2",
        5: "EVS Primary WB 13.2 CA-H-O3",
        6: "EVS Primary WB 13.2 CA-H-O5",
        7: "EVS Primary WB 13.2 CA-H-O7"
    },
    6: { # T=110: EVS Primary SWB Channel-Aware (CA)
        0: "EVS Primary SWB 13.2 CA-L-O2",
        1: "EVS Primary SWB 13.2 CA-L-O3",
        2: "EVS Primary SWB 13.2 CA-L-O5",
        3: "EVS Primary SWB 13.2 CA-L-O7",
        4: "EVS Primary SWB 13.2 CA-H-O2",
        5: "EVS Primary SWB 13.2 CA-H-O3",
        6: "EVS Primary SWB 13.2 CA-H-O5",
        7: "EVS Primary SWB 13.2 CA-H-O7"
    },
    7: { # T=111: No Request / Reserved
        15: "NO_REQ (No Request)"
    }
}



# =============================================================================
# Format Conversion Functions
# =============================================================================

def convert_evs_compact_to_full_header(compact_payload: bytes) -> bytes:
    """
    Convert EVS Compact format to Header-Full format.
    
    Implements the conversion process per sections A.2.1 and A.2.2:
    1. Extract CMR bits (Section A.2.1.2.1)
    2. Perform bit re-shuffling (Section A.2.1.2.2)
    3. Build ToC byte (Section A.2.2.1.2)
    4. Convert speech bits back to bytes with octet alignment
    5. Avoid size collisions (Section A.2.2.1.4.2)
    
    Args:
        compact_payload: Raw bytes in Compact format
        
    Returns:
        Converted payload in Header-Full format
        
    Raises:
        ValueError: If payload size is not a valid EVS AMR-WB IO Compact size
    """
    payload_bits = len(compact_payload) * 8
    
    if payload_bits not in IO_MODES:
        raise ValueError(f"Payload size {payload_bits} is not a valid EVS AMR-WB IO Compact size.")

    ft_code, num_speech_bits = IO_MODES[payload_bits]
    bits = bytes_to_bitarray(compact_payload)

    # 1. Extract 3-bit CMR (Section A.2.1.2.1)
    cmr_bits = bits[:3]
    cmr_number = None

    try:
        # Convert bitarray to int
        cmr_number = int(cmr_bits.to01(), 2)
    except:
        pass
    
    # 2. Bit re-shuffling (Section A.2.1.2.2)
    # Compact IO structure: [CMR] [d(1)...d(last)] [d(0)] [Padding]
    # d(0) is located immediately after d(last)
    d0_index = 3 + num_speech_bits - 1
    d0 = bits[d0_index:d0_index+1]  # Get single bit as bitarray
    d1_to_last = bits[3:d0_index]
    
    # Reorder to Header-Full format: {d(0), d(1), ..., d(K-1)}
    standard_speech_bits = d0 + d1_to_last

    # 3. Build ToC byte (Section A.2.2.1.2)
    # H=0 (bit 0), F=0 (bit 1), EVS Mode=1 (bit 2), Q=1 (bit 3), FT=4 bits
    toc_byte_val = 0x30 | (ft_code & 0x0F)
    header_full_payload = bytearray([toc_byte_val])

    # 4. Convert speech bits back to bytes (includes octet alignment)
    speech_data = bitarray_to_bytes(standard_speech_bits)
    header_full_payload.extend(speech_data)

    # 5. Size collision avoidance (Section A.2.2.1.4.2)
    # Add zero bytes until no collision with protected sizes
    while (len(header_full_payload) * 8) in PROTECTED_SIZES:
        # Exception: 56-bit size is allowed for IO SID (Section A.2.1.3)
        if len(header_full_payload) * 8 == 56:
            break
        header_full_payload.append(0x00)

    return bytes(header_full_payload), cmr_number


# =============================================================================
# Packet Detection Functions
# =============================================================================

def is_rtcp(pkt: Packet) -> bool:
    """
    Check if a packet is RTCP based on version and payload type.
    
    Args:
        pkt: Scapy packet to check
        
    Returns:
        True if packet is RTCP, False otherwise
    """
    if UDP not in pkt or Raw not in pkt:
        return False

    data = bytes(pkt[Raw])
    if len(data) < 2:
        return False

    version = data[0] >> 6
    payload_type = data[1]

    return version == 2 and 200 <= payload_type <= 204


# =============================================================================
# Output File Manager
# =============================================================================

def build_channel_output_path(base_path: Path, channel: int) -> Path:
    """
    Build the output file path for a specific channel.

    For base_path = 'output.cod' and channel = 1, returns 'output_ch1.cod'.

    Args:
        base_path: Base output path provided by the user
        channel: 1-based channel number

    Returns:
        Path object for this channel's output file
    """
    return base_path.with_name(f"{base_path.stem}_ch{channel}{base_path.suffix}")


class OutputFileManager:
    """
    Manages one or more output COD file handles.

    In single-file mode  : all frames go to one file.
    In multi-file mode   : each channel gets its own file whose name is
                           derived from the base output path.
    """

    def __init__(self, base_path: Path, channels: int, multi_file: bool) -> None:
        self.base_path = base_path
        self.channels = channels
        self.multi_file = multi_file
        self._files: Dict[int, IO[bytes]] = {}  # channel (1-based) -> file handle

    def __enter__(self):
        if self.multi_file and self.channels > 1:
            for ch in range(1, self.channels + 1):
                path = build_channel_output_path(self.base_path, ch)
                f = open(path, 'wb')
                # Each per-channel COD file carries exactly 1 channel
                f.write(b"#!EVS_MC1.0\n")
                f.write(struct.pack(">I", 1))
                self._files[ch] = f
        else:
            f = open(self.base_path, 'wb')
            f.write(b"#!EVS_MC1.0\n")
            f.write(struct.pack(">I", self.channels))
            # All channels share key 0 (sentinel for single-file mode)
            self._files[0] = f
        return self

    def __exit__(self, *args):
        for f in self._files.values():
            f.close()

    def write_frame(self, data: bytes, channel: int) -> None:
        """
        Write frame data to the appropriate file.

        Args:
            data    : Frame bytes to write
            channel : 1-based channel number this frame belongs to
        """
        if self.multi_file and self.channels > 1:
            self._files[channel].write(data)
        else:
            self._files[0].write(data)

    def output_paths(self) -> List[Path]:
        """Return the list of output file paths that were opened."""
        if self.multi_file and self.channels > 1:
            return [build_channel_output_path(self.base_path, ch)
                    for ch in range(1, self.channels + 1)]
        return [self.base_path]


# =============================================================================
# Main Processing Logic
# =============================================================================

class EVSProcessor:
    """Process EVS packets from PCAP and convert to COD format."""
    
    def __init__(self, channels: int = 1, use_rich: bool = False, multi_file: bool = False) -> None:
        """
        Initialize the EVS processor.
        
        Args:
            channels  : Number of audio channels (default: 1 for mono)
            use_rich  : Whether to use rich formatting
            multi_file: Save each channel to its own COD file
        """
        self.channels = channels
        self.use_rich = use_rich
        self.multi_file = multi_file

        # Running channel counter for Compact packets (which carry one frame
        # each and are assigned channels in arrival order).
        self._compact_channel_counter = 0

        self.stats = {
            'total_packets': 0,
            'rtcp_packets': 0,
            'compact_packets': 0,
            'header_full_packets': 0,
            'frames_processed': 0,
            'warnings': 0,
            'errors': 0
        }
    
    def _format_log(self, message: str, **kwargs) -> str:
        """
        Format log message based on rich mode.
        
        Args:
            message: Message with rich markup
            
        Returns:
            Formatted message (with or without markup)
        """
        if not self.use_rich:
            # Strip rich markup tags for plain text output
            import re
            message = re.sub(r'\[/?[^\]]+\]', '', message)
        return message
    
    def process_compact_packet(
        self, 
        pkt_index: int, 
        pkt_marker: int, 
        rtp_payload: bytes, 
        payload_bits: int, 
        info: Dict[str, any]
    ) -> Tuple[bytes, int]:
        """
        Process a packet in Compact format.
        
        Args:
            pkt_index   : Index of packet in PCAP
            pkt_marker  : RTP marker bit
            rtp_payload : Raw RTP payload bytes
            payload_bits: Size of payload in bits
            info        : Packet info from COMPACT_SIZE_MAP
            
        Returns:
            Tuple of (converted frame data, 1-based channel number)
        """
        toc_byte = info['ft']
        speech_data = rtp_payload
        
        self.stats['compact_packets'] += 1

        # Assign channel in round-robin order across successive Compact packets
        channel = (self._compact_channel_counter % self.channels) + 1
        self._compact_channel_counter += 1
        
        # Convert AMR-WB IO from Compact to Header-Full
        if info['mode'] == "AMR-WB IO":
            cmr_desc = 'Unknown CMR'
            toc_with_speech_data, cmr_number = convert_evs_compact_to_full_header(speech_data)
            if cmr_number in COMPACT_CMR_AMR_WB:
                cmr_desc = COMPACT_CMR_AMR_WB[cmr_number]
            
            hex_data = toc_with_speech_data.hex()
            msg = self._format_log(
                f"[Pkt {pkt_index}] [cyan]Compact[/cyan] | Mode: [yellow]{info['mode']}[/yellow] | "
                f"Rate: [green]{info['rate']}[/green] | Size: {payload_bits}b ({len(rtp_payload)}B) | "
                f"CMR: {cmr_desc} | Ch: {channel} | Hex: {hex_data}"
            )
            logger.debug(msg, extra={"markup": True} if self.use_rich else {})
            return toc_with_speech_data, channel
        else:
            # Build storage ToC: always starts with H=0 and F=0
            storage_toc = toc_byte & 0x3F
            result = struct.pack("B", storage_toc) + speech_data
            hex_data = result.hex()
            msg = self._format_log(
                f"[Pkt {pkt_index}] [cyan]Compact[/cyan] | Mode: [yellow]{info['mode']}[/yellow] | "
                f"Rate: [green]{info['rate']}[/green] | Size: {payload_bits}b ({len(rtp_payload)}B) | "
                f"Ch: {channel} | Hex: {hex_data}"
            )
            logger.debug(msg, extra={"markup": True} if self.use_rich else {})
            return result, channel
    
    def process_header_full_packet(
        self, 
        pkt_index: int, 
        pkt_marker: int, 
        rtp_payload: bytes
    ) -> List[Tuple[bytes, int]]:
        """
        Process a packet in Header-Full format.
        
        Args:
            pkt_index  : Index of packet in PCAP
            pkt_marker : RTP marker bit
            rtp_payload: Raw RTP payload bytes
            
        Returns:
            List of (frame data, 1-based channel number) tuples
        """
        idx = 0
        
        self.stats['header_full_packets'] += 1
        
        cmr_desc = 'No CMR'
        if rtp_payload[idx] & 0x80:
            cmr_desc = 'Unknown CMR'
            
            # Figure A.4. CMR byte 
            cmr = rtp_payload[idx]
            H = cmr & 0x80 # bit 0 (MSB)
            T = (cmr >> 4) & 0x07 # bits 1-3
            D = cmr & 0x0f # bits 4-7

            try:
                cmr_desc = FULL_HEADER_CMR[T][D]
            except KeyError:
                if T == 7:
                    cmr_desc = 'Reserved'
                else:
                    cmr_desc = 'Not used'

            # Skip CMR byte if present
            idx += 1
        
        F = 1
        frame_count = 0
        tocs: List[Tuple[int, int, str, str, int]] = []
        
        # Parse all ToC bytes by Figure A.5 (A.2.2.1.2)
        while F:
            toc_byte = rtp_payload[idx]
            channel = (frame_count % self.channels) + 1
            F = toc_byte >> 6  # F bit indicates if more frames follow
            evs_mode = (toc_byte >> 5) & 0x01
            Q = (toc_byte >> 4) & 0x01  # Q bit indicates frame quality
            ft = toc_byte & 0x3F
            
            mode_str = "Primary" if evs_mode == 0 else "AMR-WB IO"
            rate_map = FT_PRIMARY if evs_mode == 0 else FT_IO
            ft_mode = ft & 0x0F
            rate = rate_map.get(ft_mode, 'Unknown')
            
            # Check for severely damaged frame in AMR-WB IO mode (Table A.5 Note)
            if evs_mode == 1 and Q == 0:
                self.stats['warnings'] += 1
                msg = self._format_log(
                    f"[Pkt {pkt_index}] [magenta]Header-Full[/magenta] | Frame: {frame_count} | "
                    f"[red]Q=0 - Frame severely damaged[/red] | Channel: {channel}"
                )
                logger.warning(msg, extra={"markup": True} if self.use_rich else {})
            
            tocs.append((toc_byte & 0x3F, evs_mode, mode_str, rate, channel))
            frame_count += 1
            idx += 1
        
        # Process speech data for each frame
        results: List[Tuple[bytes, int]] = []
        for frame_idx, (toc, evs_mode, mode_str, rate, channel) in enumerate(tocs):
            rate_map = FT_PRIMARY if evs_mode == 0 else FT_IO
            
            if rate == 'NO_DATA':
                msg = self._format_log(
                    f"[Pkt {pkt_index}] [magenta]Header-Full[/magenta] | "
                    f"Frame: {frame_idx + 1}/{frame_count} | Type: [dim]NO_DATA[/dim]"
                )
                logger.debug(msg, extra={"markup": True} if self.use_rich else {})
                continue
            
            if rate is None or rate == 'Unknown':
                self.stats['errors'] += 1
                msg = self._format_log(
                    f"[Pkt {pkt_index}] [magenta]Header-Full[/magenta] | "
                    f"Frame: {frame_idx + 1}/{frame_count} | [red]Unknown rate[/red]"
                )
                logger.error(msg, extra={"markup": True} if self.use_rich else {})
                continue
            
            try:
                frame_size = RATE_TO_SIZE_MAP[rate] // 8
                speech_data = rtp_payload[idx:idx + frame_size]
                idx += frame_size
                
                frame_output = struct.pack("B", toc) + speech_data
                results.append((frame_output, channel))
                self.stats['frames_processed'] += 1
                
                hex_data = frame_output.hex()
                msg = self._format_log(
                    f"[Pkt {pkt_index}] [magenta]Header-Full[/magenta] | "
                    f"Frame: {frame_idx + 1}/{frame_count} | Mode: [yellow]{mode_str}[/yellow] | "
                    f"Rate: [green]{rate}[/green] | Ch: {channel} | Hex: {hex_data}"
                )
                logger.debug(msg, extra={"markup": True} if self.use_rich else {})
                
            except KeyError:
                self.stats['errors'] += 1
                msg = self._format_log(
                    f"[Pkt {pkt_index}] [magenta]Header-Full[/magenta] | "
                    f"Frame: {frame_idx + 1}/{frame_count} | [red]Unknown rate '{rate}'[/red]"
                )
                logger.error(msg, extra={"markup": True} if self.use_rich else {})
                continue
        
        return results
    
    def process_pcap(self, pcap_file: Path, output_file: Path) -> None:
        """
        Main processing function: read PCAP and write COD file(s).
        
        Args:
            pcap_file  : Path to input PCAP file
            output_file: Base path for output COD file(s)
        """
        # Display header only if using rich
        if self.use_rich:
            console.print(Panel.fit(
                f"[bold cyan]EVS PCAP to COD Parser[/bold cyan]\n"
                f"[dim]ETSI TS 126 445 V18.0.0 (2024-06)[/dim]",
                border_style="cyan",
                box=box.DOUBLE
            ))
        
        multi_active = self.multi_file and self.channels > 1
        msg = self._format_log(
            f"Reading PCAP: [cyan]{pcap_file}[/cyan] | "
            f"Channels: [yellow]{self.channels}[/yellow] | "
            f"Multi-file: [yellow]{'yes' if multi_active else 'no'}[/yellow]"
        )
        logger.info(msg, extra={"markup": True} if self.use_rich else {})
        
        packets = rdpcap(str(pcap_file))
        self.stats['total_packets'] = len(packets)
        
        msg = self._format_log(f"Total packets in PCAP: [cyan]{len(packets)}[/cyan]")
        logger.info(msg, extra={"markup": True} if self.use_rich else {})

        with OutputFileManager(output_file, self.channels, self.multi_file) as out:
            if self.use_rich:
                self._process_with_progress(packets, out)
            else:
                self._process_without_progress(packets, out)

            output_paths = out.output_paths()

        # Log the files that were written
        for path in output_paths:
            msg = self._format_log(f"Successfully written to: [green]{path}[/green]")
            logger.info(msg, extra={"markup": True} if self.use_rich else {})
        
        # Display statistics summary
        if self.use_rich:
            self._display_summary()
        else:
            self._display_simple_summary()
    
    def _process_with_progress(self, packets: List, out: OutputFileManager) -> None:
        """Process packets with rich progress bar."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Processing packets...", total=len(packets))
            for pkt_index, pkt in enumerate(packets):
                progress.update(task, advance=1)
                self._process_single_packet(pkt_index, pkt, out)
    
    def _process_without_progress(self, packets: List, out: OutputFileManager) -> None:
        """Process packets without rich progress bar."""
        for pkt_index, pkt in enumerate(packets):
            self._process_single_packet(pkt_index, pkt, out)
    
    def _process_single_packet(self, pkt_index: int, pkt: Packet, out: OutputFileManager) -> None:
        """Process a single packet and dispatch frames to the output manager."""
        if UDP not in pkt or not pkt[UDP].payload:
            return
        
        # Check if packet is RTCP
        if is_rtcp(pkt):
            self.stats['rtcp_packets'] += 1
            msg = self._format_log(f"[Pkt {pkt_index}] [dim]Type: RTCP[/dim]")
            logger.debug(msg, extra={"markup": True} if self.use_rich else {})
            return
        
        rtp_pkt = RTP(pkt[UDP].load)
        marker = rtp_pkt.marker
            
        rtp_payload = rtp_pkt.load
        
        if not rtp_payload:
            return
        
        payload_bits = len(rtp_payload) * 8
        first_byte = rtp_payload[0]
        
        # Determine if format is Compact or Header-Full
        is_compact = payload_bits in COMPACT_SIZE_MAP
        
        # Special case: 56-bit size requires MSB check
        if payload_bits == 56:
            is_compact = (first_byte & 0x80) == 0
        
        # Process based on format type
        if is_compact:
            info = COMPACT_SIZE_MAP[payload_bits]
            frame_data, channel = self.process_compact_packet(
                pkt_index, marker, rtp_payload, payload_bits, info
            )
            out.write_frame(frame_data, channel)
        else:
            frame_results = self.process_header_full_packet(pkt_index, marker, rtp_payload)
            for frame_data, channel in frame_results:
                out.write_frame(frame_data, channel)
    
    def _display_simple_summary(self) -> None:
        """Display simple text-based summary without rich formatting."""
        print("\n--- Processing Summary ---")
        print(f"Total Packets:       {self.stats['total_packets']}")
        print(f"RTCP Packets:        {self.stats['rtcp_packets']}")
        print(f"Compact Format:      {self.stats['compact_packets']}")
        print(f"Header-Full Format:  {self.stats['header_full_packets']}")
        print(f"Frames Processed:    {self.stats['frames_processed']}")
        
        if self.stats['warnings'] > 0:
            print(f"Warnings:            {self.stats['warnings']}")
        
        if self.stats['errors'] > 0:
            print(f"Errors:              {self.stats['errors']}")
    
    def _display_summary(self) -> None:
        """Display processing statistics in a nice table."""
        table = Table(title="Processing Summary", box=box.ROUNDED, border_style="cyan")
        
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", style="magenta", justify="right")
        
        table.add_row("Total Packets", str(self.stats['total_packets']))
        table.add_row("RTCP Packets", str(self.stats['rtcp_packets']))
        table.add_row("Compact Format", str(self.stats['compact_packets']))
        table.add_row("Header-Full Format", str(self.stats['header_full_packets']))
        table.add_row("Frames Processed", str(self.stats['frames_processed']))
        
        if self.stats['warnings'] > 0:
            table.add_row("Warnings", f"[yellow]{self.stats['warnings']}[/yellow]")
        
        if self.stats['errors'] > 0:
            table.add_row("Errors", f"[red]{self.stats['errors']}[/red]")
        
        console.print()
        console.print(table)


# =============================================================================
# CLI Interface
# =============================================================================

def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Convert EVS RTP packets from PCAP files to COD format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.pcap output.cod
  %(prog)s input.pcap output.cod --debug --rich
  %(prog)s input.pcap output.cod --channels 2 --rich
  %(prog)s input.pcap output.cod --channels 2 --save-multi-files
  %(prog)s -i input.pcap -o output.cod -c 2 -d --rich --save-multi-files
        """
    )
    
    parser.add_argument(
        'pcap_path',
        type=str,
        nargs='?',
        help='Path to input PCAP file'
    )
    
    parser.add_argument(
        'output_path',
        type=str,
        nargs='?',
        help='Path to output COD file'
    )
    
    parser.add_argument(
        '-i', '--input',
        dest='pcap_path_alt',
        type=str,
        help='Path to input PCAP file (alternative syntax)'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_path_alt',
        type=str,
        help='Path to output COD file (alternative syntax)'
    )
    
    parser.add_argument(
        '-c', '--channels',
        type=int,
        default=1,
        help='Number of audio channels (default: 1)'
    )
    
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug logging (shows detailed packet information)'
    )
    
    parser.add_argument(
        '--rich',
        action='store_true',
        help='Enable rich/pretty console output with colors and progress bars'
    )

    parser.add_argument(
        '--save-multi-files',
        action='store_true',
        dest='save_multi_files',
        help=(
            'When the stream has multiple channels, save each channel to its own '
            'COD file instead of interleaving them in a single file. '
            'Output files are named <output>_ch1.cod, <output>_ch2.cod, etc. '
            'Has no effect when --channels is 1.'
        )
    )
    
    args = parser.parse_args()
    
    # Setup logging based on arguments
    log_level = logging.DEBUG if args.debug else logging.INFO
    
    # Configure logging handler based on --rich flag
    if args.rich:
        # Rich handler with colors and formatting
        logging.basicConfig(
            level=log_level,
            format="%(message)s",
            handlers=[RichHandler(
                console=console,
                rich_tracebacks=True,
                markup=True,
                show_time=False,
                show_path=False
            )]
        )
    else:
        # Standard logging without rich formatting
        logging.basicConfig(
            level=log_level,
            format='%(levelname)s: %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
    
    # Handle both positional and flag-based arguments
    pcap_path = args.pcap_path or args.pcap_path_alt
    output_path = args.output_path or args.output_path_alt
    
    # Validate arguments
    if not pcap_path or not output_path:
        parser.print_help()
        sys.exit(1)
    
    # Validate channels
    if args.channels < 1:
        if args.rich:
            console.print("[red]Error:[/red] Channels must be at least 1")
        else:
            print("Error: Channels must be at least 1", file=sys.stderr)
        sys.exit(1)

    # Warn if --save-multi-files is used with a single channel (no-op)
    if args.save_multi_files and args.channels == 1:
        msg = "--save-multi-files has no effect when --channels is 1"
        if args.rich:
            console.print(f"[yellow]Warning:[/yellow] {msg}")
        else:
            print(f"Warning: {msg}", file=sys.stderr)
    
    pcap_path_obj = Path(pcap_path)
    output_path_obj = Path(output_path)
    
    # Check if input file exists
    if not pcap_path_obj.exists():
        if args.rich:
            console.print(f"[red]Error:[/red] Input file not found: {pcap_path_obj}")
        else:
            print(f"Error: Input file not found: {pcap_path_obj}", file=sys.stderr)
        sys.exit(1)
    
    # Process the file
    try:
        processor = EVSProcessor(
            channels=args.channels,
            use_rich=args.rich,
            multi_file=args.save_multi_files,
        )
        processor.process_pcap(pcap_path_obj, output_path_obj)
        
        # Build a human-readable description of what was written
        if args.save_multi_files and args.channels > 1:
            file_desc = ", ".join(
                str(build_channel_output_path(output_path_obj, ch))
                for ch in range(1, args.channels + 1)
            )
        else:
            file_desc = str(output_path_obj)

        if args.rich:
            if not args.debug:
                console.print(
                    f"\n[green]✓[/green] Successfully converted [cyan]{pcap_path_obj}[/cyan] "
                    f"→ [cyan]{file_desc}[/cyan] (channels: {args.channels})"
                )
        else:
            if not args.debug:
                print(f"Successfully converted {pcap_path_obj} → {file_desc} (channels: {args.channels})")
        
    except Exception as e:
        if args.rich:
            console.print(f"[red]Error:[/red] {e}")
            if args.debug:
                console.print_exception()
        else:
            logger.error(f"Error processing file: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
