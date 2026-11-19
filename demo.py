"""Present a two-round live Ethernet capture against the local IPv4 gateway."""

from collections import Counter
import ctypes
from dataclasses import dataclass
from ipaddress import IPv4Address
import os
from pathlib import Path
from queue import Empty, Queue
import re
import subprocess
import sys
from threading import Thread
from time import monotonic
from typing import TextIO


ROOT = Path(__file__).resolve().parent
GCC_CAPTURE = ROOT / "build" / "gcc" / "npcap-homework.exe"
MSVC_CAPTURE = ROOT / "build" / "Release" / "npcap-homework.exe"
CAPTURE = GCC_CAPTURE if GCC_CAPTURE.is_file() else MSVC_CAPTURE
ADAPTER = re.compile(r"^\s*\[(\d+)\] ([^\n]*)\n[ \t]+\\Device\\NPF_(\{[0-9A-F-]+\})$",
                     re.IGNORECASE | re.MULTILINE)
MAC = r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}"
FRAME = re.compile(rf"^\s*(\d+)\s+({MAC})\s+({MAC})\s+(0x[0-9A-F]{{4}})\s+"
                   r"(0x[0-9A-F]{2}|--)\s+(\d+)\s+(\d+)$")
ROUNDS = (32, 256)
PROBES = 4


@dataclass(frozen=True)
class Adapter:
    index: str
    name: str
    mac: str
    address: IPv4Address
    gateway: IPv4Address
    runtime: str


@dataclass(frozen=True)
class Frame:
    number: int
    source: str
    destination: str
    type_length: str
    next_byte: str
    original: int
    captured: int

    def direction(self, local_mac: str) -> str:
        if self.source == local_mac:
            return "TX >"
        if self.destination == local_mac:
            return "< RX"
        return "OTHER"


def enable_color() -> bool:
    if "NO_COLOR" in os.environ or not sys.stdout.isatty():
        return False
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetStdHandle.restype = ctypes.c_void_p
    handle = ctypes.c_void_p(kernel.GetStdHandle(-11))  # STD_OUTPUT_HANDLE
    mode = ctypes.c_uint32()
    return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode))
                and kernel.SetConsoleMode(handle, mode.value | 0x0004))  # VT processing


@dataclass(frozen=True)
class Display:
    color: bool

    def tint(self, text: str, style: str) -> str:
        return f"\x1b[{style}m{text}\x1b[0m" if self.color else text

    def heading(self, title: str) -> None:
        print(self.tint(title, "1;96"), flush=True)

    def table(self) -> None:
        header: str = (f"{'#':>3}  {'DIR':<5}  {'SOURCE MAC':<17}  {'DESTINATION MAC':<17}  "
                       f"{'TYPE':>6}  {'NEXT':>4}  {'FRAME B':>7}  {'CAP B':>5}")
        print(self.tint(header, "1"))
        print(self.tint("-" * len(header), "2"))

    def row(self, frame: Frame, local_mac: str) -> None:
        side: str = frame.direction(local_mac)
        direction: str = self.tint(f"{side:<5}", {"TX >": "1;96", "< RX": "1;92"}.get(side, "2"))
        source: str = self.tint(frame.source, "96") if frame.source == local_mac else frame.source
        dest: str = self.tint(frame.destination, "92") if frame.destination == local_mac else frame.destination
        ethertype: str = self.tint(frame.type_length, "1;93")
        next_byte: str = self.tint(f"{frame.next_byte:>4}", "1;95")
        length: str = f"{frame.original:7}  {frame.captured:5}"
        print(f"{frame.number:3}  {direction}  {source}  {dest}  {ethertype}  {next_byte}  {length}",
              flush=True)


def choose_adapter() -> Adapter:
    listed: subprocess.CompletedProcess[str] = subprocess.run(
        [str(CAPTURE), "--list"], stdout=subprocess.PIPE, encoding="utf-8",
        check=True, timeout=15,
    )
    adapters: dict[str, tuple[str, str]] = {
        guid.upper(): (index, label) for index, label, guid in ADAPTER.findall(listed.stdout)
    }
    gateways: subprocess.CompletedProcess[str] = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "Get-NetIPConfiguration | Where-Object IPv4DefaultGateway | ForEach-Object { "
         "'{0}|{1}|{2}|{3}' -f $_.NetAdapter.InterfaceGuid, $_.NetAdapter.MacAddress, "
         "$_.IPv4Address[0].IPAddress, $_.IPv4DefaultGateway[0].NextHop }"],
        capture_output=True, encoding="ascii", errors="replace", check=True, timeout=15,
    )
    for line in gateways.stdout.splitlines():
        fields: list[str] = line.strip().split("|")
        if len(fields) != 4:
            continue
        guid, mac, address, gateway = fields
        mac = mac.replace("-", ":").upper()
        if guid.upper() in adapters and re.fullmatch(MAC, mac) and address and gateway:
            index, label = adapters[guid.upper()]
            return Adapter(index, label, mac, IPv4Address(address), IPv4Address(gateway),
                           listed.stdout.splitlines()[0])
    raise RuntimeError("No Npcap Ethernet adapter matched an IPv4 gateway on this PC.")


def read_output(stream: TextIO, lines: Queue[str | None]) -> None:
    try:
        for line in stream:
            lines.put(line)
    finally:
        lines.put(None)


def read_frame(line: str) -> Frame | None:
    match: re.Match[str] | None = FRAME.fullmatch(line)
    if match is None:
        return None
    number, source, dest, type_length, next_byte, original, captured = match.groups()
    return Frame(int(number), source, dest, type_length, next_byte, int(original), int(captured))


def stop_process(process: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    process.wait()


def counts(frames: list[Frame], adapter: Adapter) -> Counter[str]:
    return Counter(frame.direction(adapter.mac) for frame in frames)


def capture_round(adapter: Adapter, payload: int, display: Display) -> list[Frame]:
    expression: str = (f"icmp and host {adapter.address} and host {adapter.gateway} "
                       "and (icmp[0] = 8 or icmp[0] = 0)")
    frames: list[Frame] = []
    ping: subprocess.Popen[bytes] | None = None
    with subprocess.Popen(
        [str(CAPTURE), "--interface", adapter.index, "--count", str(2 * PROBES),
         "--filter", expression, "--details"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
    ) as capture:
        assert capture.stdout is not None
        lines: Queue[str | None] = Queue()
        reader = Thread(target=read_output, args=(capture.stdout, lines), daemon=True)
        reader.start()
        deadline: float = monotonic() + 8.0
        try:
            while True:
                line: str | None = lines.get(timeout=max(0.0, deadline - monotonic()))
                if line is None:
                    if capture.wait(timeout=2):
                        raise RuntimeError(f"Capture exited with status {capture.returncode}.")
                    return frames
                line = line.rstrip()
                if line.endswith("Cap bytes"):
                    display.table()
                    ping = subprocess.Popen(
                        ["ping.exe", "-4", "-n", str(PROBES), "-w", "800",
                         "-l", str(payload), str(adapter.gateway)],
                        stdout=subprocess.DEVNULL,
                    )
                elif (frame := read_frame(line)) is not None:
                    frames.append(frame)
                    display.row(frame, adapter.mac)
                elif line.startswith(("Error:", "Npcap warning:")):
                    print(line, flush=True)
        except Empty:
            print("Round timed out: showing the frames that actually arrived.", flush=True)
            return frames
        finally:
            if ping is not None:
                stop_process(ping)
            stop_process(capture)
            reader.join()


def show_summary(frames: list[Frame], adapter: Adapter, display: Display) -> None:
    directions: Counter[str] = counts(frames, adapter)
    truncated: int = sum(frame.captured < frame.original for frame in frames)
    print()
    display.heading("03 / CAPTURE SUMMARY")
    print(f"  {len(frames)} frames  |  {directions['TX >']} outbound  |  {directions['< RX']} inbound"
          f"  |  {truncated} shorter snapshots")
    if not frames:
        return
    lengths: str = ", ".join(f"{original} -> {captured} B"
                             for original, captured in sorted({(f.original, f.captured) for f in frames}))
    print(f"  Frame -> snapshot: {lengths} (frame length as reported by Npcap)")
    sample: Frame = frames[0]
    last_offset: int = 13 if sample.next_byte == "--" else 14
    print(f"  First frame, bytes 0-{last_offset} in Ethernet order:")
    print(f"    {sample.destination.replace(':', ' ')} | {sample.source.replace(':', ' ')} | "
          f"{display.tint(sample.type_length[2:4] + ' ' + sample.type_length[4:], '1;93')} | "
          f"{display.tint(sample.next_byte.removeprefix('0x'), '1;95')}")
    print("    destination MAC   | source MAC        | type  | next byte")
    if sample.type_length == "0x0800" and sample.next_byte == "0x45":
        print("  0x0800 = IPv4; 0x45 = version 4, header length 5 x 4 = 20 bytes.")


def demo() -> int:
    if not CAPTURE.is_file():
        raise RuntimeError("Build the Release executable first; see README.md.")
    display = Display(enable_color())
    display.heading("NPCAP LAB  /  LIVE ETHERNET CAPTURE")
    adapter: Adapter = choose_adapter()
    print()
    display.heading("01 / CAPTURE SETUP")
    print(f"  Adapter [{adapter.index}] {adapter.name}")
    print(f"  Local   {adapter.address}   MAC {adapter.mac}")
    print(f"  Gateway {adapter.gateway}   Filter: IPv4 ICMP echo")
    print(f"  {adapter.runtime}")
    print("  Capture is live; no packet file is written.")
    print()
    display.heading("02 / LIVE FRAMES")
    print("  TX > outbound   < RX inbound   FRAME B original   CAP B captured")
    frames: list[Frame] = []
    complete: bool = True
    for index, payload in enumerate(ROUNDS, start=1):
        print()
        display.heading(f"  ROUND {index}/{len(ROUNDS)}   {PROBES} pings   ICMP payload {payload} bytes")
        observed: list[Frame] = capture_round(adapter, payload, display)
        frames.extend(observed)
        directions: Counter[str] = counts(observed, adapter)
        complete = complete and directions["TX >"] == directions["< RX"] == PROBES
        print(f"  Round result: {directions['TX >']}/{PROBES} TX, {directions['< RX']}/{PROBES} RX")
    show_summary(frames, adapter, display)
    if not complete:
        print("  Incomplete: some expected frames were not seen. The gateway may not answer ICMP.")
    return 0 if complete else 1


def main() -> int:
    try:
        return demo()
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Demo error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
