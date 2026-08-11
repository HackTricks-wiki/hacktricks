# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** ist ein Tool, das du auf einem Arduino-kompatiblen MCU oder experimentell auf einem Raspberry Pi laden kannst, um unbekannte JTAG-Pinouts per Brute-Force zu ermitteln und Instruction Registers zu enumerieren.<sup>[[3]](#references)</sup>

- Arduino: Verbinde die digitalen Pins D2–D11 mit bis zu 10 vermuteten JTAG-Pads/Testpunkten und Arduino GND mit der GND-Leitung des Zielgeräts. Versorge das Zielgerät separat, sofern du nicht weißt, dass die Versorgungsschiene sicher ist. Bevorzuge 3,3-V-Logik (z. B. Arduino Due) oder verwende beim Prüfen von Zielen mit 1,8–3,3 V einen Level Shifter bzw. Serienwiderstände.
- Raspberry Pi: Der Pi-Build stellt weniger nutzbare GPIOs bereit (daher sind Scans langsamer); prüfe das Repo auf die aktuelle Pinbelegung und die Einschränkungen.

Öffne nach dem Flashen den seriellen Monitor mit 115200 Baud und sende `h`, um Hilfe anzuzeigen. Typischer Ablauf:

- `l` Loopbacks finden, um False Positives zu vermeiden
- `r` interne Pull-ups bei Bedarf umschalten
- `s` nach TCK/TMS/TDI/TDO (und manchmal TRST/SRST) scannen
- `y` IR per Brute-Force durchsuchen, um undokumentierte Opcodes zu entdecken
- `x` Boundary-Scan-Snapshot der Pinzustände

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pinzustände](<../../images/image (939).png>)

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pinzustände](<../../images/image (578).png>)

![JTAG - JTAGenum: x Boundary-Scan-Snapshot der Pinzustände](<../../images/image (774).png>)



Wenn ein gültiger TAP gefunden wird, siehst du Zeilen, die mit `FOUND!` beginnen und die entdeckten Pins anzeigen.

### Sicherheitstipps für JTAGenum

- Verbinde immer die Masse und treibe unbekannte Pins niemals mit einer Spannung über dem Vtref des Zielgeräts. Im Zweifelsfall füge an den vermuteten Pins Serienwiderstände mit 100–470 Ω hinzu.
- Wenn das Gerät anstelle von 4-Draht-JTAG SWD/SWJ verwendet, erkennt JTAGenum es möglicherweise nicht; versuche es mit SWD-Tools oder einem Adapter, der SWJ-DP unterstützt.

## Sicherere Suche nach Pins und Hardware-Setup

- Identifiziere zuerst Vtref und GND mit einem Multimeter. Viele Adapter benötigen Vtref, um die I/O-Spannung einzustellen.
- Level Shifting: Bevorzuge bidirektionale Level Shifter, die für Push-Pull-Signale ausgelegt sind (JTAG-Leitungen sind nicht Open-Drain). Vermeide Auto-Direction-I2C-Shifter für JTAG.
- Nützliche Adapter: FT2232H/FT232H-Boards (z. B. Tigard), CMSIS-DAP, J-Link, ST-LINK (herstellerspezifisch), ESP-USB-JTAG (bei ESP32-Sx). Verbinde mindestens TCK, TMS, TDI, TDO, GND und Vtref; optional TRST und SRST.

## Erster Kontakt mit OpenOCD (Scan und IDCODE)

OpenOCD ist das De-facto-OSS für JTAG/SWD. Mit einem unterstützten Adapter kannst du die Chain scannen und IDCODEs auslesen:<sup>[[1]](#references)</sup>

- Allgemeines Beispiel mit einem J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Integriertes USB-JTAG des ESP32‑S3 (keine externe Probe erforderlich):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Hinweise

- Wenn du eine „all ones/zeros“-IDCODE erhältst, überprüfe die Verkabelung, die Stromversorgung, Vtref und ob der Port durch Fuses/Option Bytes gesperrt ist.
- Siehe OpenOCD `irscan`/`drscan` auf niedriger Ebene für die manuelle TAP-Interaktion beim Inbetriebnehmen unbekannter Chains.<sup>[[1]](#references)</sup>

## Anhalten der CPU und Dumpen von Speicher/Flash

Sobald der TAP erkannt und ein Target-Script ausgewählt wurde, kannst du den Core anhalten und Speicherbereiche oder internen Flash dumpen. Beispiele (Target, Basisadressen und Größen anpassen):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, programmieren oder auslesen über den OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Tipps zum Memory-Dumping

- Verwende `mdw/mdh/mdb`, um den Speicher vor langen Dumps auf Plausibilität zu prüfen.
- Setze bei Chains mit mehreren Devices BYPASS für nicht relevante Targets oder verwende eine Board-Datei, die alle TAPs definiert.

## Boundary-scan-Tricks (EXTEST/SAMPLE)

Auch wenn der CPU-Debug-Zugriff gesperrt ist, kann Boundary-scan weiterhin freigelegt sein. Mit UrJTAG/OpenOCD kannst du:<sup>[[1]](#references)</sup>
- SAMPLE verwenden, um Pin-Zustände während des laufenden Systems zu erfassen (Bus-Aktivität finden, Pin-Zuordnung bestätigen).
- EXTEST verwenden, um Pins anzusteuern (z. B. externe SPI-Flash-Leitungen über den MCU per Bit-Banging anzusteuern und den Flash offline auszulesen, sofern die Verdrahtung des Boards dies ermöglicht).

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
Du benötigst die BSDL des Geräts, um die Bit-Reihenfolge des Boundary-Registers zu kennen. Beachte, dass manche Hersteller Boundary-Scan-Zellen in der Produktion sperren.

## Moderne Ziele und Hinweise

- ESP32-S3/C3 enthalten eine native USB-JTAG-Bridge; OpenOCD kann direkt über USB kommunizieren, ohne einen externen Probe. Sehr praktisch für Triage und Dumps.<sup>[[2]](#references)</sup>
- RISC-V-Debugging (v0.13+) wird von OpenOCD weithin unterstützt; bevorzuge SBA für den Speicherzugriff, wenn der Core nicht sicher angehalten werden kann.
- Viele MCUs implementieren Debug-Authentifizierung und Lifecycle-Zustände. Wenn JTAG trotz korrekter Stromversorgung nicht reagiert, könnte das Gerät in einen geschlossenen Zustand gefused worden sein oder einen authentifizierten Probe erfordern.

## Schutzmaßnahmen und Härtung (was bei echten Geräten zu erwarten ist)

- JTAG/SWD in der Produktion dauerhaft deaktivieren oder sperren (z. B. STM32 RDP Level 2, ESP-eFuses, die PAD JTAG deaktivieren, NXP/Nordic APPROTECT/DPAP).
- Authentifiziertes Debugging voraussetzen (ARMv8.2-A ADIv6 Debug Authentication, vom OEM verwaltetes Challenge-Response), während der Fertigungszugriff erhalten bleibt.
- Keine leicht zugänglichen Testpads vorsehen; Test-Vias vergraben, Widerstände entfernen/bestücken, um den TAP zu isolieren, und Steckverbinder mit Kodierung oder Pogo-Pin-Fixtures verwenden.
- Debug-Sperre beim Einschalten: Den TAP hinter einem frühen ROM sperren, das Secure Boot erzwingt.

## References

- [1] [OpenOCD-Benutzerhandbuch – JTAG-Befehle und Konfiguration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3-JTAG-Debugging (USB-JTAG, OpenOCD-Nutzung)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-basierter JTAG-Pinout-Scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
