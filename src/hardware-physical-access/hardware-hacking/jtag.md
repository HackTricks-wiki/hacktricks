# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Safer pin hunting and hardware setup

- Identify Vtref and GND first with a multimeter. Many adapters need Vtref to set I/O voltage.
- Level shifting: prefer bidirectional level shifters designed for push‑pull signals (JTAG lines are not open‑drain). Avoid auto‑direction I2C shifters for JTAG.
- Useful adapters: FT2232H/FT232H boards (e.g., Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (vendor‑specific), ESP‑USB‑JTAG (on ESP32‑Sx). Connect at minimum TCK, TMS, TDI, TDO, GND and Vtref; optionally TRST and SRST.

For an undocumented header, identify GND by continuity to a known ground plane **while the target is unpowered**. After switching to voltage mode and powering it, do not classify every high pin as Vtref: high digital inputs can look similar on a meter. Trace candidate rails to nearby decoupling capacitors and compare their power-up/power-down waveforms on an oscilloscope. A slower capacitor-shaped rise or fall is evidence for a supply/reference net, but verify the voltage and wiring before connecting a level-shifted probe. On PiFex, an external lower-voltage target reference can be selected through `VCCA_IN` instead of its default 3.3 V setting.<sup>[[4]](#references)</sup>

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

## GPIO pin discovery with go-jtagenum

On a powered target with a verified common ground and compatible I/O voltage, `go-jtagenum` can enumerate candidate JTAG signals from Raspberry Pi GPIOs. The `-pins` JSON maps labels to **GPIO numbers**, not physical header positions.<sup>[[5]](#references)</sup> In the SSD example, the first IDCODE scan also reported an implausibly long chain of changing values: a changing candidate TDO line alone is not proof of a valid TAP. Recheck a plausible result with a BYPASS scan, which shifts a known bit pattern from TDI through the one-bit bypass register to TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

For that board, BYPASS confirmed `TCK=10`, `TMS=14`, `TDI=9`, and `TDO=15`; the extra pins were only **possible** nTRST candidates. If a candidate returns all zeroes or an inconsistent pattern, check contact, target power, pull-ups, and clock/reset delays before assigning it a signal.<sup>[[4]](#references)[[5]](#references)</sup> The tool also accepts `-known-pins` with `test_bypass` to retest a recovered mapping.<sup>[[5]](#references)</sup>

## Characterize an undocumented TAP with UrJTAG

A discovered pinout does not identify the instruction-register (IR) opcodes or data-register (DR) widths needed for debugging. With a UrJTAG build that supports the Raspberry Pi GPIO cable, set the recovered mapping and run `idcode`, `detect`, then `discover`. The SSD example returned one TAP, a four-bit IR, and different DR widths for different IR values. A `-1` DR length or “TDO stuck at 0” is not a usable register definition; inspect timing, wiring, and the selected instruction rather than assigning it a width.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

This is TAP reconnaissance, not automatic CPU identification: compare the resulting IDCODE with device documentation and supported OpenOCD targets. UrJTAG's local manufacturer database may label an otherwise valid ID as unknown.<sup>[[4]](#references)</sup>

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

## Bring an undocumented target into OpenOCD

Once the TAP ID and IR length are known, inspect OpenOCD's `cpu/`, `target/`, and `board/` scripts for a **matching CPU architecture**, then make separate adapter and target configurations.<sup>[[4]](#references)[[6]](#references)</sup> The following Pi GPIO mapping and ARCv2 target are the tested SSD example, not a universal JTAG configuration. The ARC target choice and debug settings were assumptions that succeeded for this device; substitute the target's measured ID, IR length, architecture, and GPIO numbers on another board.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Run `openocd -f raspberrypi-io.cfg -f target.cfg` and confirm that TAP examination succeeds before reading memory. The example opened Telnet on port `4444` and a GDB server on `3333`; a recognized IDCODE alone does not prove that the selected CPU target can be examined or debugged.<sup>[[4]](#references)</sup> Raspberry Pi GPIOs need not be the pins labeled JTAG on a breakout board when the adapter permits `adapter gpio` remapping.<sup>[[4]](#references)[[6]](#references)</sup>

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

For an undocumented memory map, the SSD research checked a 1 MiB dump for recognizable controller strings, then used an architecture-capable GDB through OpenOCD to inspect `$pc`, disassembly, and registers. Those live addresses guided a second region dump, which was checked against matching instructions in an ARC-capable Ghidra build. Strings alone are only a plausibility check, not proof that the image is complete or mapped correctly.<sup>[[4]](#references)</sup> See [firmware analysis](../firmware-analysis/) for broader static-analysis steps.

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
- [4] [VoidStar Security — JTAG Hacking with a Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG enumeration](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD User’s Guide — Debug Adapter Configuration](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)

{{#include ../../banners/hacktricks-training.md}}
