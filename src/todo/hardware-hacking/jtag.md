# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) ist ein Tool, das du auf einen Arduino-kompatiblen MCU oder (experimentell) einen Raspberry Pi laden kannst, um unbekannte JTAG-Pinouts per Brute-Force zu ermitteln und sogar Instruction Registers zu enumerieren.

- Arduino: Verbinde die digitalen Pins D2–D11 mit bis zu 10 vermuteten JTAG-Pads/Testpunkten und Arduino GND mit der GND-Leitung des Targets. Versorge das Target separat, sofern du nicht weißt, dass die Versorgungsschiene sicher ist. Bevorzuge 3,3-V-Logik (z. B. Arduino Due) oder verwende beim Prüfen von 1,8–3,3-V-Targets einen Level Shifter/Serienwiderstände.
- Raspberry Pi: Der Pi-Build stellt weniger nutzbare GPIOs bereit (daher sind Scans langsamer); prüfe das Repo auf das aktuelle Pin-Mapping und die Einschränkungen.

Nach dem Flashen öffnest du den Serial Monitor mit 115200 Baud und sendest `h` für Hilfe. Typischer Ablauf:

- `l` Loopbacks finden, um False Positives zu vermeiden
- `r` interne Pull-ups bei Bedarf umschalten
- `s` nach TCK/TMS/TDI/TDO (und manchmal TRST/SRST) scannen
- `y` IR per Brute-Force durchsuchen, um undokumentierte Opcodes zu entdecken
- `x` Boundary-Scan-Snapshot der Pin-Zustände

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pin-Zustände](<../../images/image (939).png>)

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pin-Zustände](<../../images/image (578).png>)

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pin-Zustände](<../../images/image (774).png>)



Wenn ein gültiger TAP gefunden wird, siehst du Zeilen, die mit `FOUND!` beginnen und die entdeckten Pins anzeigen.

Tipps
- Verbinde immer die Masse und treibe unbekannte Pins niemals über das Target-Vtref. Füge im Zweifel 100–470-Ω-Serienwiderstände an den vermuteten Pins hinzu.
- Wenn das Gerät statt 4-Wire-JTAG SWD/SWJ verwendet, erkennt JTAGenum es möglicherweise nicht; probiere SWD-Tools oder einen Adapter, der SWJ-DP unterstützt.

## Sicherere Pin-Suche und Hardware-Setup

- Identifiziere Vtref und GND zuerst mit einem Multimeter. Viele Adapter benötigen Vtref, um die I/O-Spannung einzustellen.
- Level Shifting: Bevorzuge bidirektionale Level Shifter, die für Push-Pull-Signale ausgelegt sind (JTAG-Leitungen sind nicht Open-Drain). Vermeide Auto-Direction-I2C-Shifter für JTAG.
- Nützliche Adapter: FT2232H/FT232H-Boards (z. B. Tigard), CMSIS-DAP, J-Link, ST-LINK (herstellerspezifisch), ESP-USB-JTAG (bei ESP32-Sx). Verbinde mindestens TCK, TMS, TDI, TDO, GND und Vtref; optional TRST und SRST.

## Erster Kontakt mit OpenOCD (Scan und IDCODE)

OpenOCD ist das De-facto-OSS für JTAG/SWD. Mit einem unterstützten Adapter kannst du die Chain scannen und IDCODEs auslesen:

- Generisches Beispiel mit einem J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Integriertes USB‑JTAG des ESP32‑S3 (keine externe Probe erforderlich):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notizen
- Wenn du eine IDCODE mit "nur Einsen/Nullen" erhältst, überprüfe die Verkabelung, die Stromversorgung, Vtref und ob der Port nicht durch Fuses/Option Bytes gesperrt ist.
- Siehe OpenOCD low-level `irscan`/`drscan` für die manuelle TAP-Interaktion beim Initialisieren unbekannter Chains.<sup>[[1]](#references)</sup>

## Anhalten der CPU und Auslesen von Speicher/Flash

Sobald der TAP erkannt und ein Target-Skript ausgewählt wurde, kannst du den Core anhalten und Speicherbereiche oder den internen Flash auslesen. Beispiele (Target, Basisadressen und Größen anpassen):

- Generisches Target nach der Initialisierung:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (SBA bevorzugen, sofern verfügbar):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, über den OpenOCD helper programmieren oder auslesen:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tipps
- Verwende `mdw/mdh/mdb`, um den Speicher vor langen Dumps auf Plausibilität zu prüfen.
- Bei Chains mit mehreren Geräten: Setze BYPASS für nicht relevante Ziele oder verwende eine Board-Datei, die alle TAPs definiert.

## Boundary-scan tricks (EXTEST/SAMPLE)

Auch wenn der CPU-Debugzugriff gesperrt ist, kann Boundary-scan weiterhin exponiert sein. Mit UrJTAG/OpenOCD kannst du:
- SAMPLE verwenden, um Pin-Zustände während des laufenden Systems zu erfassen (Busaktivität finden, Pin-Mapping bestätigen).
- EXTEST verwenden, um Pins anzusteuern (z. B. externe SPI-Flash-Leitungen über den MCU per bit-bang anzusteuern und den Flash offline auszulesen, sofern die Verdrahtung des Boards dies ermöglicht).

Minimaler UrJTAG-Ablauf mit einem FT2232x-Adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
You need the device BSDL to know boundary register bit ordering. Beware that some vendors lock boundary-scan cells in production.

## Moderne Ziele und Hinweise

- ESP32‑S3/C3 include a native USB‑JTAG bridge; OpenOCD can speak directly over USB without an external probe. Very convenient for Triage und Dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) is widely supported by OpenOCD; prefer SBA for memory access when the core cannot be halted safely.
- Many MCUs implement debug authentication and lifecycle states. If JTAG appears dead but power is correct, the device may be fused to a closed state or requires an authenticated probe.

## Schutzmaßnahmen und Hardening (was auf realen Geräten zu erwarten ist)

- Permanently disable or lock JTAG/SWD in production (e.g., STM32 RDP level 2, ESP eFuses that disable PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Require authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM‑managed challenge‑response) while keeping manufacturing access.
- Don’t route easy test pads; bury test vias, remove/populate resistors to isolate TAP, use connectors with keying or pogo‑pin fixtures.
- Power‑on debug lock: gate the TAP behind early ROM enforcing secure boot.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
