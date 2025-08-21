# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) is a tool you can load on an Arduino-compatible MCU or (experimentally) a Raspberry Pi to brute‑force unknown JTAG pinouts and even enumerate instruction registers.

- Arduino: connect digital pins D2–D11 to up to 10 suspected JTAG pads/testpoints, and Arduino GND to target GND. Power the target separately unless you know the rail is safe. Prefer 3.3 V logic (e.g., Arduino Due) or use a level shifter/series resistors when probing 1.8–3.3 V targets.
- Raspberry Pi: the Pi build exposes fewer usable GPIOs (so scans are slower); check the repo for the current pin map and constraints.

Once flashed, open the serial monitor at 115200 baud and send `h` for help. Typical flow:

- `l` find loopbacks to avoid false positives
- `r` toggle internal pull‑ups if needed
- `s` scan for TCK/TMS/TDI/TDO (and sometimes TRST/SRST)
- `y` brute‑force IR to discover undocumented opcodes
- `x` boundary‑scan snapshot of pin states

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



If a valid TAP is found you will see lines starting with `FOUND!` indicating discovered pins.

Tips
- Always share ground, and never drive unknown pins above target Vtref. If in doubt, add 100–470 Ω series resistors on candidate pins.
- If the device uses SWD/SWJ instead of 4‑wire JTAG, JTAGenum may not detect it; try SWD tools or an adapter that supports SWJ‑DP.

## Safer pin hunting and hardware setup

- Identify Vtref and GND first with a multimeter. Many adapters need Vtref to set I/O voltage.
- Level shifting: prefer bidirectional level shifters designed for push‑pull signals (JTAG lines are not open‑drain). Avoid auto‑direction I2C shifters for JTAG.
- Useful adapters: FT2232H/FT232H boards (e.g., Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (vendor‑specific), ESP‑USB‑JTAG (on ESP32‑Sx). Connect at minimum TCK, TMS, TDI, TDO, GND and Vtref; optionally TRST and SRST.

## First contact with OpenOCD (scan and IDCODE)

OpenOCD is the de‑facto OSS for JTAG/SWD. With a supported adapter you can scan the chain and read IDCODEs:

- Generic example with a J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 built‑in USB‑JTAG (no external probe required):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- If you get "all ones/zeros" IDCODE, check wiring, power, Vtref, and that the port isn’t locked by fuses/option bytes.
- See OpenOCD low‑level `irscan`/`drscan` for manual TAP interaction when bringing up unknown chains.

## Halting the CPU and dumping memory/flash

Once the TAP is recognized and a target script is chosen, you can halt the core and dump memory regions or internal flash. Examples (adjust target, base addresses and sizes):

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
- ESP32‑S3, program or read via OpenOCD helper:
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

Tips
- Use `mdw/mdh/mdb` to sanity‑check memory before long dumps.
- For multi‑device chains, set BYPASS on non‑targets or use a board file that defines all TAPs.

## Boundary‑scan tricks (EXTEST/SAMPLE)

Even when the CPU debug access is locked, boundary‑scan may still be exposed. With UrJTAG/OpenOCD you can:
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

- ESP32‑S3/C3 include a native USB‑JTAG bridge; OpenOCD can speak directly over USB without an external probe. Very convenient for triage and dumps.
- RISC‑V debug (v0.13+) is widely supported by OpenOCD; prefer SBA for memory access when the core cannot be halted safely.
- Many MCUs implement debug authentication and lifecycle states. If JTAG appears dead but power is correct, the device may be fused to a closed state or requires an authenticated probe.

## Defenses and hardening (what to expect on real devices)

- Permanently disable or lock JTAG/SWD in production (e.g., STM32 RDP level 2, ESP eFuses that disable PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Require authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM‑managed challenge‑response) while keeping manufacturing access.
- Don’t route easy test pads; bury test vias, remove/populate resistors to isolate TAP, use connectors with keying or pogo‑pin fixtures.
- Power‑on debug lock: gate the TAP behind early ROM enforcing secure boot.

## References

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
