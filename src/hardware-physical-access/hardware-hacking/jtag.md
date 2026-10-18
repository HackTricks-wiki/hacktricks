# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** is a tool you can load on an Arduino-compatible MCU or, experimentally, a Raspberry Pi to brute-force unknown JTAG pinouts and enumerate instruction registers.<sup>[[3]](#references)</sup>

- Arduino: connect digital pins D2–D11 to up to 10 suspected JTAG pads/testpoints, and Arduino GND to target GND. Power the target separately unless you know the rail is safe. Prefer 3.3 V logic (e.g., Arduino Due) or use a level shifter/series resistors when probing 1.8–3.3 V targets.
- Raspberry Pi: the Pi build exposes fewer usable GPIOs (so scans are slower); check the repo for the current pin map and constraints.

Once flashed, open the serial monitor at 115200 baud and send `h` for help. Typical flow:

- `l` find loopbacks to avoid false positives
- `r` toggle internal pull‑ups if needed
- `s` scan for TCK/TMS/TDI/TDO (and sometimes TRST/SRST)
- `y` brute‑force IR to discover undocumented opcodes
- `x` boundary‑scan snapshot of pin states

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



If a valid TAP is found you will see lines starting with `FOUND!` indicating discovered pins.

### JTAGenum Safety Tips

- Always share ground, and never drive unknown pins above target Vtref. If in doubt, add 100–470 Ω series resistors on candidate pins.
- If the device uses SWD/SWJ instead of 4‑wire JTAG, JTAGenum may not detect it; try SWD tools or an adapter that supports SWJ‑DP.

## Safer pin hunting and hardware setup

- Identify Vtref and GND first with a multimeter. Many adapters need Vtref to set I/O voltage.
- Level shifting: prefer bidirectional level shifters designed for push‑pull signals (JTAG lines are not open‑drain). Avoid auto‑direction I2C shifters for JTAG.
- Useful adapters: FT2232H/FT232H boards (e.g., Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (vendor‑specific), ESP‑USB‑JTAG (on ESP32‑Sx). Connect at minimum TCK, TMS, TDI, TDO, GND and Vtref; optionally TRST and SRST.

## First contact with OpenOCD (scan and IDCODE)

OpenOCD is the de‑facto OSS for JTAG/SWD. With a supported adapter you can scan the chain and read IDCODEs:<sup>[[1]](#references)</sup>

- Generic example with a J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 built‑in USB‑JTAG (no external probe required):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- If you get "all ones/zeros" IDCODE, check wiring, power, Vtref, and that the port isn’t locked by fuses/option bytes.
- See OpenOCD low‑level `irscan`/`drscan` for manual TAP interaction when bringing up unknown chains.<sup>[[1]](#references)</sup>

## Halting the CPU and dumping memory/flash

Once the TAP is recognized and a target script is chosen, you can halt the core and dump memory regions or internal flash. Examples (adjust target, base addresses and sizes):<sup>[[1]](#references)</sup>

- Generic target after init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefer SBA when available):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, program or read via OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Memory-Dumping Tips

- Use `mdw/mdh/mdb` to sanity‑check memory before long dumps.
- For multi‑device chains, set BYPASS on non‑targets or use a board file that defines all TAPs.

## SWD access to an unsupported Cortex-M target

An exposed SWCLK/SWDIO pair, common ground, compatible I/O voltage, and optional reset line can give OpenOCD access to an MCU's internal memory when debug/readout protection is not active. SWD is a separate transport from four-wire JTAG, so a working JTAG pin scan is not required. If OpenOCD lacks a target configuration, define its CoreSight DAP and Cortex-M target rather than assuming the debug port is unusable. The DAP ID and flash layout must come from the actual device, not another member of its family.<sup>[[4]](#references)[[6]](#references)</sup>

For the documented BAT32G135 example, a Raspberry Pi with the BCM2835 GPIO bit-bang driver used GPIO 9 for SWCLK, 11 for SWDIO, and 10 for system reset. The peripheral base and timing coefficients below are for that Pi setup; verify the target's voltage, Pi model, and pin mapping before using them.<sup>[[6]](#references)</sup>

```tcl
adapter driver bcm2835gpio
bcm2835gpio peripheral_base 0x20000000
bcm2835gpio speed_coeffs 113714 28
adapter gpio swclk -chip 0 9
adapter gpio swdio -chip 0 11
adapter gpio srst -chip 0 10
transport select swd
reset_config srst_only srst_push_pull
```

A separate target file supplies the SWJ-DP, an explicit DAP, and the Cortex-M target. In the observed device, `0x0bc11477` was the SWD DPIDR. OpenOCD no longer creates the DAP implicitly; also use lowercase Tcl `source`, not the capitalized `Source` printed in the article.<sup>[[4]](#references)[[6]](#references)</sup>

```tcl
source [find target/swj-dp.tcl]
set CHIPNAME BAT32G135
swj_newdap $CHIPNAME cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id 0x0bc11477
dap create $CHIPNAME.dap -chain-position $CHIPNAME.cpu
target create $CHIPNAME.cpu cortex_m -endian little -dap $CHIPNAME.dap
```

Start `openocd -f pi-swd.cfg -f target.cfg` and check that the log reports the expected SWD DPIDR and Cortex-M core. The Telnet command port is 4444, GDB is 3333, and Tcl RPC is 6666 in this configuration. From the OpenOCD prompt, `halt` then `dump_image firmware.bin 0 65536` copies the example's 64 KiB internal flash; choose address and length from the target memory map. `gdb-multiarch` can connect with `target extended-remote :3333`. For [firmware analysis](../firmware-analysis/#analyzing-the-firmware), load a raw Cortex-M image at the mapped base address and check its initial stack pointer and vector table before trusting disassembly.<sup>[[5]](#references)[[6]](#references)</sup>

### Reflashing through a memory-mapped flash controller

A working DAP does **not** imply OpenOCD has a flash driver for the MCU. When no driver exists, the vendor's flash-controller sequence can instead be performed with OpenOCD memory writes or its Tcl RPC interface. This is controller-specific: do not reuse register addresses or unlock values on a different MCU. Preserve and verify the original dump before erasing, because removing the vector table can leave the core in HardFault until valid firmware is restored.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

On the BAT32G135, the published erase sequence sets `FLERMD` (`0x4002000c`) to `0x08`, `FLPROT` (`0x40020020`) to `0xf1`, then writes `0x55` and `0xaa` to `FLOPMD1`/`FLOPMD2`. A word write of `0xffffffff` at the flash-sector start triggers erase. Poll the `FLSTS` completion flag at `0x40020000`, clear it, and restore `FLERMD=0` and `FLPROT=0xf0`. Programming reverses the mode keys (`0xaa`, `0x55`) and writes **one byte** to the flash address per operation, polling and clearing the status flag each time. OpenOCD's `mww` and `mwb` commands provide the required word/byte writes.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

The [published BAT32 script](https://github.com/voidstarsec/pifex-sw/blob/main/examples/jtag/bat32flash.py) automates these writes for a 64 KiB image. Despite the article calling it a Telnet client, the actual script connects to **Tcl RPC on 127.0.0.1:6666**, not Telnet on 4444. Its `-o f -f firmware.bin` path erases first, then programs in `0x200`-byte chunks with byte-wise flash writes. It assumes a sequential image starting at zero (`start_addr` is ignored in favor of a global address) and polls without a timeout, so check image size and keep an original dump before running it. Re-dump the programmed region and compare it byte-for-byte with the intended image; the reported test also confirmed a patched UART string executed after reflashing.<sup>[[6]](#references)[[7]](#references)</sup>

## Boundary‑scan tricks (EXTEST/SAMPLE)

Even when the CPU debug access is locked, boundary‑scan may still be exposed. With UrJTAG/OpenOCD you can:<sup>[[1]](#references)</sup>
- SAMPLE to snapshot pin states while the system runs (find bus activity, confirm pin mapping).
- EXTEST to drive pins (e.g., bit‑bang external SPI flash lines via the MCU to read it offline if board wiring allows).

Minimal UrJTAG flow with an FT2232x adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
You need the device BSDL to know boundary register bit ordering. Beware that some vendors lock boundary‑scan cells in production.

## Modern targets and notes

- ESP32‑S3/C3 include a native USB‑JTAG bridge; OpenOCD can speak directly over USB without an external probe. Very convenient for triage and dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) is widely supported by OpenOCD; prefer SBA for memory access when the core cannot be halted safely.
- Many MCUs implement debug authentication and lifecycle states. If JTAG appears dead but power is correct, the device may be fused to a closed state or requires an authenticated probe.

## Defenses and hardening (what to expect on real devices)

- Permanently disable or lock JTAG/SWD in production (e.g., STM32 RDP level 2, ESP eFuses that disable PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Require authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM‑managed challenge‑response) while keeping manufacturing access.
- Don’t route easy test pads; bury test vias, remove/populate resistors to isolate TAP, use connectors with keying or pogo‑pin fixtures.
- Power‑on debug lock: gate the TAP behind early ROM enforcing secure boot.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-based JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
- [4] [OpenOCD User’s Guide – DAP declaration](https://openocd.org/doc/html/TAP-Declaration.html#index-DAP-declaration)
- [5] [OpenOCD User’s Guide – General commands](https://openocd.org/doc/html/General-Commands.html)
- [6] [VoidStar Security – Brushing Up Part 3](https://voidstarsec.com/blog/brushing-up-part-3)
- [7] [VoidStar Security – BAT32 flash script](https://github.com/voidstarsec/pifex-sw/blob/main/examples/jtag/bat32flash.py)

{{#include ../../banners/hacktricks-training.md}}
