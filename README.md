# Npcap Homework

A Windows console program that passively captures Ethernet frames on one selected
adapter. It displays source and destination MAC addresses, the raw two-byte
Type/Length field, and the first byte after that field. It does not write packet files.
See [HOMEWORK.md](HOMEWORK.md) for the assignment and [report/report.tex](report/report.tex)
for the experiment report.

Course submission URL: **[to be filled in]**.

## Build and run

- Windows 10 or 11, Visual Studio with **Desktop development with C++**, and CMake
  3.25 or later. Use a recent MSVC toolset with C++23 support. The lab was tested
  with Visual Studio 2026 x64.
- Install the [Npcap runtime](https://npcap.com/#download) to run live captures.
  Download the [Npcap SDK 1.17](https://npcap.com/dist/npcap-sdk-1.17.zip)
  separately and extract it under `external/npcap-sdk-1.17` so that
  `external/npcap-sdk-1.17/Include/pcap.h` exists. For another location, pass
  `-DNPCAP_SDK_ROOT=<path>` to CMake. No Npcap binaries are redistributed here.

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
.\build\Release\npcap-homework.exe
```

Select an Ethernet adapter by number. Enter at the empty prompt quits; Ctrl+C
ends a capture. If Npcap was installed with administrator-only capture, use an
elevated terminal. An Npcap driver service without its user-mode DLL is
insufficient: repair the runtime if the program cannot load `wpcap.dll`.

For a one-terminal live demo, run `python demo.py` after the Release build.
It matches an Npcap adapter to a Windows IPv4 default gateway and sends two
rounds of four pings (32- and 256-byte ICMP payloads). It highlights the local MAC,
direction, Type/Length and next byte, compares original frame length with
the captured snapshot, and decodes the first observed header. A responsive
gateway yields 16 frames. Set `NO_COLOR=1` for plain-text output.

```powershell
.\build\Release\npcap-homework.exe --list
# Example only: substitute your Ethernet adapter number and IPv4 gateway.
.\build\Release\npcap-homework.exe --interface 3 --count 4 --filter "icmp and host 192.168.1.1"
# In a second terminal after the capture banner appears:
ping -4 -n 2 192.168.1.1
```

If the gateway answers, expect two request rows and two reply rows. Compare
the direction of the MACs with Windows' adapter and neighbor tables. A normal
IPv4 header with no options gives `0x0800  0x45`. Omit `--count` for a continuous
capture, or omit `--filter` to show all captured Ethernet traffic. A filter is
a single quoted libpcap expression. Interface numbers are local to the current
device enumeration. Add `--details` to also show the original frame length
reported by Npcap and the number of bytes actually captured.

## Interpretation and scope

| Captured offsets (zero-based) | Output |
| --- | --- |
| 0–5 | Destination MAC |
| 6–11 | Source MAC |
| 12–13 | Big-endian Type/Length value |
| 14 | First captured byte immediately after Type/Length |

The raw Type/Length value is not necessarily an EtherType: values up to 1500
can represent IEEE 802.3 lengths. On a tagged frame, the outer field can be
`0x8100`; the next byte is part of the tag control information, not an IP byte.
The decoder works from the captured length (`caplen`), not the original frame
length (`len`). Fewer than 14 bytes cannot provide both MACs and Type/Length
and are counted as short; exactly 14 bytes produce `--` in the last column.

The app accepts only `DLT_EN10MB`. Npcap loopback and any raw 802.11 adapters
using a different link type are rejected before decoding. Capture uses a 64-byte
snapshot and non-promiscuous mode. This is a teaching display, not a wire-rate
monitor or a guarantee of lossless capture. Use a narrow filter on busy links.

## Build the report

Edit the identity placeholders near the top of `report/report.tex`. With
TeX Live (XeLaTeX, `acmart`, `ctex` and Fandol fonts):

```powershell
New-Item -ItemType Directory -Force .temp/report, output/pdf | Out-Null
latexmk -xelatex -interaction=nonstopmode -halt-on-error '-outdir=.temp/report' report/report.tex
Copy-Item .temp/report/report.pdf output/pdf/npcap-homework-report.pdf
```
