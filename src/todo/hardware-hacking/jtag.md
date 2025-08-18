# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) ist ein Tool, das Sie auf einem Arduino-kompatiblen MCU oder (experimentell) einem Raspberry Pi laden können, um unbekannte JTAG-Pinouts zu brute-forcen und sogar Instruktionsregister zu enumerieren.

- Arduino: Verbinden Sie die digitalen Pins D2–D11 mit bis zu 10 verdächtigen JTAG-Pads/Testpunkten und Arduino GND mit dem Ziel-GND. Versorgen Sie das Ziel separat, es sei denn, Sie wissen, dass die Schiene sicher ist. Bevorzugen Sie 3,3 V Logik (z. B. Arduino Due) oder verwenden Sie einen Pegelwandler/Serienwiderstände, wenn Sie 1,8–3,3 V Ziele abfragen.
- Raspberry Pi: Der Pi-Bau bietet weniger nutzbare GPIOs (daher sind Scans langsamer); überprüfen Sie das Repo für die aktuelle Pinbelegung und Einschränkungen.

Sobald geflasht, öffnen Sie den seriellen Monitor bei 115200 Baud und senden Sie `h` für Hilfe. Typischer Ablauf:

- `l` Schleifen finden, um Fehlalarme zu vermeiden
- `r` interne Pull-Ups umschalten, falls erforderlich
- `s` nach TCK/TMS/TDI/TDO (und manchmal TRST/SRST) scannen
- `y` IR brute-forcen, um undokumentierte Opcodes zu entdecken
- `x` Boundary-Scan-Snapshot der Pin-Zustände

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)

Wenn ein gültiger TAP gefunden wird, sehen Sie Zeilen, die mit `FOUND!` beginnen und entdeckte Pins anzeigen.

Tipps
- Teilen Sie immer die Masse und treiben Sie niemals unbekannte Pins über das Ziel-Vtref. Im Zweifelsfall fügen Sie 100–470 Ω Serienwiderstände an den Kandidatenpins hinzu.
- Wenn das Gerät SWD/SWJ anstelle von 4-Draht-JTAG verwendet, erkennt JTAGenum es möglicherweise nicht; versuchen Sie SWD-Tools oder einen Adapter, der SWJ-DP unterstützt.

## Sichereres Pin-Jagen und Hardware-Setup

- Identifizieren Sie zuerst Vtref und GND mit einem Multimeter. Viele Adapter benötigen Vtref, um die I/O-Spannung einzustellen.
- Pegelverschiebung: Bevorzugen Sie bidirektionale Pegelwandler, die für Push-Pull-Signale ausgelegt sind (JTAG-Leitungen sind nicht Open-Drain). Vermeiden Sie Auto-Richtungs-I2C-Wandler für JTAG.
- Nützliche Adapter: FT2232H/FT232H-Boards (z. B. Tigard), CMSIS-DAP, J-Link, ST-LINK (herstellerspezifisch), ESP-USB-JTAG (auf ESP32-Sx). Verbinden Sie mindestens TCK, TMS, TDI, TDO, GND und Vtref; optional TRST und SRST.

## Erster Kontakt mit OpenOCD (Scan und IDCODE)

OpenOCD ist das de-facto OSS für JTAG/SWD. Mit einem unterstützten Adapter können Sie die Kette scannen und IDCODEs lesen:

- Generisches Beispiel mit einem J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 integrierter USB‑JTAG (kein externes Prüfgerät erforderlich):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notizen
- Wenn Sie "alle Einsen/Nullen" IDCODE erhalten, überprüfen Sie die Verkabelung, die Stromversorgung, Vtref und ob der Port nicht durch Sicherungen/Optionsbytes gesperrt ist.
- Siehe OpenOCD Low-Level `irscan`/`drscan` für manuelle TAP-Interaktion beim Hochfahren unbekannter Ketten.

## Anhalten der CPU und Dumpen von Speicher/Flash

Sobald der TAP erkannt wird und ein Zielskript ausgewählt ist, können Sie den Kern anhalten und Speicherbereiche oder internen Flash dumpen. Beispiele (passen Sie Ziel, Basisadressen und Größen an):

- Generisches Ziel nach der Initialisierung:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (bevorzugen Sie SBA, wenn verfügbar):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmieren oder lesen über OpenOCD-Helfer:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tipps
- Verwenden Sie `mdw/mdh/mdb`, um den Speicher vor langen Dumps zu überprüfen.
- Bei Mehrgeräteketten setzen Sie BYPASS auf Nicht-Ziele oder verwenden Sie eine Board-Datei, die alle TAPs definiert.

## Boundary-Scan-Tricks (EXTEST/SAMPLE)

Selbst wenn der CPU-Debugzugang gesperrt ist, kann der Boundary-Scan weiterhin verfügbar sein. Mit UrJTAG/OpenOCD können Sie:
- SAMPLE, um den Zustand der Pins während des Betriebs des Systems zu erfassen (Busaktivität finden, Pin-Zuordnung bestätigen).
- EXTEST, um Pins zu steuern (z. B. externe SPI-Flash-Leitungen über den MCU bit-bangen, um sie offline zu lesen, wenn die Board-Verkabelung dies zulässt).

Minimaler UrJTAG-Flow mit einem FT2232x-Adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Du benötigst die BSDL des Geräts, um die Bitreihenfolge der Boundary-Register zu kennen. Beachte, dass einige Anbieter Boundary-Scan-Zellen in der Produktion sperren.

## Moderne Ziele und Hinweise

- ESP32‑S3/C3 verfügen über eine native USB‑JTAG-Brücke; OpenOCD kann direkt über USB ohne externen Proben sprechen. Sehr praktisch für Triage und Dumps.
- RISC‑V-Debug (v0.13+) wird von OpenOCD weitgehend unterstützt; bevorzuge SBA für den Speicherzugriff, wenn der Kern nicht sicher angehalten werden kann.
- Viele MCUs implementieren Debug-Authentifizierung und Lebenszykluszustände. Wenn JTAG tot erscheint, aber die Stromversorgung korrekt ist, könnte das Gerät in einen geschlossenen Zustand gefused sein oder erfordert eine authentifizierte Probe.

## Abwehrmaßnahmen und Härtung (was man bei echten Geräten erwarten kann)

- JTAG/SWD in der Produktion dauerhaft deaktivieren oder sperren (z. B. STM32 RDP Level 2, ESP eFuses, die PAD JTAG deaktivieren, NXP/Nordic APPROTECT/DPAP).
- Authentifizierte Debugging-Anforderungen (ARMv8.2‑A ADIv6 Debug-Authentifizierung, OEM-gesteuertes Challenge-Response) bei gleichzeitiger Beibehaltung des Zugangs zur Fertigung.
- Keine einfachen Testpads routen; Testvias vergraben, Widerstände entfernen/platzieren, um TAP zu isolieren, Connectoren mit Codierung oder Pogo-Pin-Befestigungen verwenden.
- Power-on-Debug-Sperre: Schalte den TAP hinter einem frühen ROM, das den sicheren Bootvorgang durchsetzt.

## Referenzen

- OpenOCD Benutzerhandbuch – JTAG-Befehle und Konfiguration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG-Debugging (USB‑JTAG, OpenOCD-Nutzung). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
