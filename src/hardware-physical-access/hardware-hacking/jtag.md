# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** ist ein Tool, das auf einem Arduino-kompatiblen MCU oder experimentell auf einem Raspberry Pi ausgeführt werden kann, um unbekannte JTAG-Pinbelegungen per brute-force zu ermitteln und Instruction Registers aufzulisten.<sup>[[3]](#references)</sup>

- Arduino: Verbinde die digitalen Pins D2–D11 mit bis zu 10 vermuteten JTAG-Pads/Testpunkten und Arduino GND mit Target-GND. Versorge das Target separat mit Strom, sofern du nicht sicher bist, dass die Versorgungsschiene sicher ist. Verwende bevorzugt 3,3-V-Logik (z. B. Arduino Due) oder einen Pegelwandler/Serienwiderstände, wenn du Targets mit 1,8–3,3 V untersuchst.
- Raspberry Pi: Beim Pi-Build stehen weniger nutzbare GPIOs zur Verfügung (daher sind Scans langsamer); prüfe im Repo die aktuelle Pinbelegung und Einschränkungen.

Öffne nach dem Flashen den seriellen Monitor mit 115200 Baud und sende `h`, um die Hilfe aufzurufen. Typischer Ablauf:

- `l` Loopbacks finden, um Fehlalarme zu vermeiden
- `r` interne Pull-ups bei Bedarf umschalten
- `s` nach TCK/TMS/TDI/TDO (und manchmal TRST/SRST) suchen
- `y` IR per brute-force durchsuchen, um undokumentierte Opcodes zu entdecken
- `x` Boundary-Scan-Schnappschuss der Pinzustände

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Wenn ein gültiger TAP gefunden wird, erscheinen Zeilen, die mit `FOUND!` beginnen und die entdeckten Pins anzeigen.

### JTAGenum: Sicherheitshinweise

- Verbinde immer die Masse und lege an unbekannte Pins niemals eine Spannung über Vtref des Targets an. Verwende im Zweifelsfall Serienwiderstände von 100–470 Ω an den infrage kommenden Pins.
- Wenn das Gerät statt 4-Draht-JTAG SWD/SWJ verwendet, erkennt JTAGenum es möglicherweise nicht; probiere SWD-Tools oder einen Adapter mit SWJ-DP-Unterstützung.

## Sicherere Suche nach Pins und Hardware-Setup

- Ermittle zuerst Vtref und GND mit einem Multimeter. Viele Adapter benötigen Vtref, um die I/O-Spannung einzustellen.
- Pegelwandlung: Bevorzuge bidirektionale Pegelwandler, die für Push-Pull-Signale ausgelegt sind (JTAG-Leitungen sind nicht Open-Drain). Vermeide I2C-Pegelwandler mit automatischer Richtungsumschaltung für JTAG.
- Nützliche Adapter: FT2232H/FT232H-Boards (z. B. Tigard), CMSIS-DAP, J-Link, ST-LINK (herstellerspezifisch), ESP-USB-JTAG (bei ESP32-Sx). Verbinde mindestens TCK, TMS, TDI, TDO, GND und Vtref; optional TRST und SRST.

## Erster Kontakt mit OpenOCD (Scan und IDCODE)

OpenOCD ist die De-facto-OSS für JTAG/SWD. Mit einem unterstützten Adapter kannst du die Kette scannen und IDCODEs auslesen:<sup>[[1]](#references)</sup>

- Allgemeines Beispiel mit einem J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 mit integriertem USB‑JTAG (keine externe Probe erforderlich):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Hinweise

- Wenn du eine IDCODE mit „nur Einsen/Nullen“ erhältst, überprüfe die Verkabelung, die Stromversorgung, Vtref und ob der Port durch Fuses/Option Bytes gesperrt ist.
- Siehe die OpenOCD-Befehle `irscan`/`drscan` auf niedriger Ebene für die manuelle TAP-Interaktion beim Einrichten unbekannter Chains.<sup>[[1]](#references)</sup>

## Anhalten der CPU und Auslesen von Speicher/Flash

Sobald der TAP erkannt und ein Target-Script ausgewählt wurde, kannst du den Core anhalten und Speicherbereiche oder den internen Flash auslesen. Beispiele (Target, Basisadressen und Größen entsprechend anpassen):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, über den OpenOCD-Helper programmieren oder auslesen:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Tipps zum Memory-Dumping

- Verwende `mdw/mdh/mdb`, um den Speicher vor langen Dumps auf Plausibilität zu prüfen.
- Setze bei Chains mit mehreren Geräten BYPASS für Nicht-Zielgeräte oder verwende eine Board-Datei, die alle TAPs definiert.

## Boundary-Scan-Tricks (EXTEST/SAMPLE)

Auch wenn der CPU-Debugzugriff gesperrt ist, kann Boundary-Scan weiterhin verfügbar sein. Mit UrJTAG/OpenOCD kannst du:<sup>[[1]](#references)</sup>
- SAMPLE verwenden, um Pin-Zustände während des Systembetriebs zu erfassen (Busaktivität finden, Pinbelegung bestätigen).
- EXTEST verwenden, um Pins anzusteuern (z. B. externe SPI-Flash-Leitungen über den MCU per Bit-Banging ansteuern, um den Flash offline auszulesen, sofern die Verdrahtung des Boards dies zulässt).

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
Du benötigst das BSDL des Geräts, um die Bit-Reihenfolge des Boundary-Registers zu kennen. Beachte, dass einige Hersteller Boundary-Scan-Zellen in der Produktion sperren.

## Moderne Targets und Hinweise

- ESP32‑S3/C3 enthalten eine native USB‑JTAG-Bridge; OpenOCD kann ohne externen Probe direkt über USB kommunizieren. Sehr praktisch für Triage und Dumps.<sup>[[2]](#references)</sup>
- RISC‑V-Debug (v0.13+) wird von OpenOCD weitgehend unterstützt; verwende für den Speicherzugriff vorzugsweise SBA, wenn der Core nicht sicher angehalten werden kann.
- Viele MCUs implementieren Debug-Authentifizierung und Lifecycle-Zustände. Wenn JTAG nicht zu funktionieren scheint, obwohl die Stromversorgung korrekt ist, könnte das Gerät auf einen geschlossenen Zustand gefused sein oder einen authentifizierten Probe erfordern.

## Abwehrmaßnahmen und Härtung (was bei realen Geräten zu erwarten ist)

- JTAG/SWD in der Produktion dauerhaft deaktivieren oder sperren (z. B. STM32 RDP Level 2, ESP eFuses, die PAD JTAG deaktivieren, NXP/Nordic APPROTECT/DPAP).
- Authentifizierten Debug erfordern (ARMv8.2‑A ADIv6 Debug Authentication, vom OEM verwaltetes Challenge-Response-Verfahren) und gleichzeitig den Zugriff für die Fertigung ermöglichen.
- Keine leicht zugänglichen Testpads vorsehen; Test-Vias verbergen, Widerstände entfernen/bestücken, um den TAP zu isolieren, und Steckverbinder mit Verpolungsschutz oder Pogo-Pin-Vorrichtungen verwenden.
- Debug-Sperre beim Einschalten: Den TAP hinter einer frühen ROM-Phase sperren, die Secure Boot durchsetzt.

## References

- [1] [OpenOCD-Benutzerhandbuch – JTAG-Befehle und Konfiguration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG-Debugging (USB‑JTAG, OpenOCD-Verwendung)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-basierter JTAG-Pinout-Scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
