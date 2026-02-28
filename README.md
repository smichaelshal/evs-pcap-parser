# EVS PCAP to COD Parser

> EVS (Enhanced Voice Services) RTP packet parser from PCAP files to COD format.
> Compliant with **ETSI TS 126 445 V18.0.0 (2024-06)**.


[ETSI TS 126 445 V18.0.0 Annex A - RTP Payload Format and SDP Parameters](https://www.etsi.org/deliver/etsi_ts/126400_126499/126445/18.01.00_60/ts_126445v180100p.pdf#page=636)

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
  - [Positional Syntax](#positional-syntax)
  - [Flag-Based Syntax](#flag-based-syntax)
  - [Examples](#examples)
- [CLI Options](#cli-options)
- [Output File Formats](#output-file-formats)
  - [Single-File Mode](#single-file-mode)
  - [Multi-File Mode](#multi-file-mode)
- [EVS Format Support](#evs-format-support)
  - [Compact Format](#compact-format)
  - [Header-Full Format](#header-full-format)
  - [Supported Bit Rates](#supported-bit-rates)
- [Architecture](#architecture)
  - [Module Overview](#module-overview)
  - [Key Classes](#key-classes)
  - [Processing Pipeline](#processing-pipeline)
- [Format Conversion Details](#format-conversion-details)
  - [Compact to Header-Full Conversion](#compact-to-header-full-conversion)
  - [Size Collision Avoidance](#size-collision-avoidance)
- [Statistics & Logging](#statistics--logging)
- [Error Handling](#error-handling)

---

## Overview

This tool reads a PCAP capture file containing RTP streams with EVS-encoded audio, identifies and parses each EVS frame (in either Compact or Header-Full format), and writes the decoded frames to one or more `.cod` output files suitable for use with EVS decoders.

Key features:

- Supports both **EVS Primary** and **EVS AMR-WB IO** codec modes
- Handles both **Compact** and **Header-Full** RTP payload formats
- Multi-channel interleaving or per-channel file splitting
- Optional rich terminal output with progress bars and colored logs
- RTCP packet detection and skipping

---

## Installation

Install the required Python dependencies:

```bash
pip install scapy bitarray rich
```

Python 3.8+ is recommended.

---

## Usage

### Positional Syntax

```bash
python evs_pcap_parser.py <input.pcap> <output.cod>
```

### Flag-Based Syntax

```bash
python evs_pcap_parser.py -i <input.pcap> -o <output.cod>
```

Both syntaxes can be mixed. Flag-based arguments take precedence for `-i` / `-o`.

### Examples

```bash
# Basic conversion
python evs_pcap_parser.py input.pcap output.cod

# With debug logging and rich UI
python evs_pcap_parser.py input.pcap output.cod --debug --rich

# Two-channel stream, interleaved into a single COD file
python evs_pcap_parser.py input.pcap output.cod --channels 2 --rich

# Two-channel stream, split into separate files (output_ch1.cod, output_ch2.cod)
python evs_pcap_parser.py input.pcap output.cod --channels 2 --save-multi-files

# All options combined
python evs_pcap_parser.py -i input.pcap -o output.cod -c 2 -d --rich --save-multi-files
```

### COD to PCM and Alternatives
The script itself is not enough to produce PCM, to convert `COD` to PCM you can use `EVS_dec` provided by [3GPP](https://www.3gpp.org/ftp/Specs/archive/26_series/26.443).
For example:

```bash
./EVS_dec -mime -no_delay_cmp 48 input.cod output.pcm
```

You can convert PCM to WAV using ffmpeg:
```bash
ffmpeg -f s16le -ar 48k -ac 1 -i input.pcm output.wav
```


Another option is to use [SigSRF](https://github.com/signalogic/SigSRF_SDK/tree/master
) software, they are great but cost money but also come in a free demo version, they allow much more advanced use with many features, and another important thing they have is material samples (pcaps). You can use mediaTest and mediaMin to generate `COD` and `WAV` files.

```bash
# pcap to wav
mediaMin -cx86 -i/home/sigsrf_sdk_demo/Signalogic/apps/mediaTest/pcaps/mediaplayout_adelesinging_AMRWB_2xEVS.pcapng -d0x41c01 -r0.5

# pcap to cod
mediaTest -cx86 -iinput.pcap -ooutput.cod
```

In cases of using only AMR-NB and AMR-WB the excellent script [pcap_parser.py](https://github.com/Spinlogic/AMR-WB_extractor/tree/master) does a good job, for the EVS case it is better to use the current script.


---

## CLI Options

| Option | Short | Default | Description |
|---|---|---|---|
| `pcap_path` | | *(required)* | Path to input PCAP file (positional) |
| `output_path` | | *(required)* | Path to output COD file (positional) |
| `--input` | `-i` | - | Input PCAP file (alternative to positional) |
| `--output` | `-o` | - | Output COD file (alternative to positional) |
| `--channels` | `-c` | `1` | Number of audio channels |
| `--debug` | `-d` | `False` | Enable verbose debug logging (per-packet details) |
| `--rich` | | `False` | Enable colored console output and progress bars |
| `--save-multi-files` | | `False` | Save each channel to its own file (ignored if `--channels 1`) |

---

## Output File Formats

All output files begin with a standard EVS multichannel header:

```
#!EVS_MC1.0\n
<number_of_channels: uint32 big-endian>
```

Each frame is then written sequentially as raw bytes.

### Single-File Mode

All channels are interleaved into a single output file. The header records the total channel count.

```
output.cod
```

### Multi-File Mode

Enabled with `--save-multi-files` when `--channels > 1`. Each channel is written to a separate file named:

```
<output_stem>_ch<N><output_suffix>
```

For example, with `-o output.cod -c 2 --save-multi-files`:

```
output_ch1.cod
output_ch2.cod
```

Each per-channel file has its own `#!EVS_MC1.0` header indicating `1` channel.

---

## EVS Format Support

### Compact Format

Compact format frames are identified by their total payload size in bits matching a known value from **Table A.1** of ETSI TS 126 445. No separate header byte is present.

- The RTP payload itself is the frame data.
- A special case exists for **56-bit** payloads: if the MSB of the first byte is `0`, it is Compact; otherwise it is Header-Full.
- **AMR-WB IO** Compact frames contain a 3-bit CMR field and require bit re-shuffling before storage (see [Compact to Header-Full Conversion](#compact-to-header-full-conversion)).
- **Primary** Compact frames are stored directly after prepending a ToC byte.

### Header-Full Format

Header-Full packets may carry one or more frames. Each begins with:

1. An optional **CMR byte** (present if MSB = 1).
2. One or more **ToC bytes** (Table of Contents), each indicating mode, quality, frame type, and whether more frames follow (`F` bit).
3. **Speech data** bytes for each frame, sized according to the declared bit rate.

Channels are assigned to frames in round-robin order across the ToC entries.

### Supported Bit Rates

#### EVS Primary

| Bit Rate | Frame Size (bits) | FT Code |
|---|---|---|
| 2.8 kbps | 56 | 0x0 |
| 7.2 kbps | 144 | 0x1 |
| 8.0 kbps | 160 | 0x2 |
| 9.6 kbps | 192 | 0x3 |
| 13.2 kbps | 264 | 0x4 |
| 16.4 kbps | 328 | 0x5 |
| 24.4 kbps | 488 | 0x6 |
| 32.0 kbps | 640 | 0x7 |
| 48.0 kbps | 960 | 0x8 |
| 64.0 kbps | 1280 | 0x9 |
| 96.0 kbps | 1920 | 0xA |
| 128.0 kbps | 2560 | 0xB |
| 2.4 kbps SID | 48 | 0xC |

#### EVS AMR-WB IO

| Bit Rate | Frame Size (bits) | Speech Bits | FT Code |
|---|---|---|---|
| 6.6 kbps | 136 | 132 | 0 |
| 8.85 kbps | 184 | 177 | 1 |
| 12.65 kbps | 256 | 253 | 2 |
| 14.25 kbps | 288 | 285 | 3 |
| 15.85 kbps | 320 | 317 | 4 |
| 18.25 kbps | 368 | 365 | 5 |
| 19.85 kbps | 400 | 397 | 6 |
| 23.05 kbps | 464 | 461 | 7 |
| 23.85 kbps | 480 | 477 | 8 |

---

## Architecture

### Module Overview

```
evs_pcap_parser.py
├── Bit Manipulation Utilities
|   ├── bytes_to_bitarray()
|   └── bitarray_to_bytes()
├── EVS Format Constants
|   ├── COMPACT_SIZE_MAP       - Table A.1: all valid Compact payload sizes
|   ├── IO_MODES               - Derived: AMR-WB IO sizes → (FT code, speech bits)
|   ├── PROTECTED_SIZES        - Derived: set of all valid Compact sizes
|   ├── FT_PRIMARY             - Table A.4: Primary frame type codes
|   ├── FT_IO                  - Table A.5: AMR-WB IO frame type codes
|   ├── COMPACT_CMR_AMR_WB     - Table A.2: Compact CMR 3-bit signaling
|   └── FULL_HEADER_CMR        - Table A.3: Header-Full CMR byte structure
├── Format Conversion
|   └── convert_evs_compact_to_full_header()
├── Packet Detection
|   └── is_rtcp()
├── Output File Manager
|   ├── OutputFileManager      - Context manager for one or many COD files
|   └── build_channel_output_path()
├── EVSProcessor               - Main processing orchestration
|   ├── process_pcap()
|   ├── process_compact_packet()
|   ├── process_header_full_packet()
|   └── _process_single_packet()
└── CLI
    └── main()
```

### Key Classes

#### `EVSProcessor`

The central processing class. Instantiated once per run.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `channels` | `int` | `1` | Number of audio channels |
| `use_rich` | `bool` | `False` | Enable rich console output |
| `multi_file` | `bool` | `False` | Write channels to separate files |

Exposes `process_pcap(pcap_file, output_file)` as the main entry point.

#### `OutputFileManager`

A context manager that abstracts writing to one or multiple COD files.

| Method | Description |
|---|---|
| `write_frame(data, channel)` | Write frame bytes to the file for the given 1-based channel |
| `output_paths()` | Returns list of `Path` objects for all written files |

### Processing Pipeline

```
PCAP file
    |
    ▼
rdpcap() - load all packets
    |
    ▼  for each packet:
is_rtcp()? ──yes──► skip
    |
    no
    ▼
RTP parse (Scapy)
    |
    ▼
payload_bits in COMPACT_SIZE_MAP?
    ├─ yes ──► process_compact_packet()
    |              ├─ AMR-WB IO? → convert_evs_compact_to_full_header()
    |              └─ Primary?   → prepend ToC byte
    |
    └─ no  ──► process_header_full_packet()
                   ├─ parse optional CMR byte
                   ├─ parse ToC chain (F-bit loop)
                   └─ extract speech data per frame
    |
    ▼
OutputFileManager.write_frame(data, channel)
    |
    ▼
COD file(s)
```

---

## Format Conversion Details

### Compact to Header-Full Conversion

AMR-WB IO frames received in Compact format must be converted to Header-Full format before storage. The conversion follows **Section A.2.1.2** of ETSI TS 126 445:

1. **Extract 3-bit CMR** - bits `[0:3]` of the Compact payload.
2. **Extract speech bits** - Compact IO layout places `d(0)` after `d(last)`:
   ```
   Compact:      [CMR(3)] [d(1)...d(K-1)] [d(0)] [Padding]
   Header-Full:  [d(0)] [d(1)...d(K-1)]
   ```
3. **Build ToC byte** - `H=0`, `F=0`, `EVS Mode=1`, `Q=1`, `FT=<ft_code>`:
   ```
   toc_byte = 0x30 | (ft_code & 0x0F)
   ```
4. **Octet-align speech bits** - pad with trailing zeros to the next byte boundary.
5. **Size collision avoidance** - append zero bytes if the resulting payload length (in bits) collides with a protected Compact size (see below).

### Size Collision Avoidance

Per **Section A.2.2.1.4.2**, the converted Header-Full payload must not have the same byte length as any valid Compact format size, to prevent misdetection. Zero bytes are appended until the size is no longer in `PROTECTED_SIZES`. The 56-bit size is exempt (it is valid for IO SID frames).

---

## Statistics & Logging

After processing, a summary is printed:

| Metric | Description |
|---|---|
| Total Packets | All packets read from the PCAP |
| RTCP Packets | RTCP packets detected and skipped |
| Compact Format | Packets identified as EVS Compact |
| Header-Full Format | Packets identified as EVS Header-Full |
| Frames Processed | Individual EVS frames written to output |
| Warnings | e.g., `Q=0` damaged frames in AMR-WB IO mode |
| Errors | Unknown rates or malformed frames |

With `--rich`, the summary is displayed as a formatted table. Without `--rich`, it is printed as plain text.

With `--debug`, each packet and frame logs:
- Packet index
- Format type (Compact / Header-Full)
- Mode (Primary / AMR-WB IO)
- Bit rate
- Payload size
- Assigned channel
- Raw hex bytes of the stored frame

---

## Error Handling

| Condition | Behavior |
|---|---|
| Input PCAP not found | Exits with error message and code `1` |
| `--channels < 1` | Exits with validation error |
| `--save-multi-files` with `--channels 1` | Prints a warning; flag is ignored |
| Unknown frame type in Header-Full | Logs an error, skips the frame |
| `NO_DATA` frame type | Silently skipped (debug log only) |
| `Q=0` in AMR-WB IO frame | Logs a warning, frame is still processed |
| Unexpected exception during processing | Logs error; with `--debug`, prints full traceback |

## Contact

For issues and questions, please open an issue on the project repository.

### Notes:
- The tool only deals with exporting EVS from RTP packets and therefore does not deal with "special" features of RTP, for example rfc7198, rfc8108. To support "special" features, you need to fix the pcap in advance and then transfer it to the tool or alternatively use the tool's logic in your own software.

- The tool is intended for research and learning purposes and therefore does not attempt to be efficient or provide a comprehensive solution, it only extracts to EVS RTP and print logs

## References

- [ETSI TS 126 445](https://www.etsi.org/deliver/etsi_ts/126400_126499/126445/) - EVS Codec Specification
- [RFC 3550](https://tools.ietf.org/html/rfc3550) - RTP: A Transport Protocol for Real-Time Applications
- [RFC 4867](https://tools.ietf.org/html/rfc4867) - RTP Payload Format for AMR and AMR-WB

---

**Version**: 1.0.0
**Last Updated**: 2026
**Author**: Michael Shalitin
