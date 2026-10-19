# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Sicherere Pin-Suche und Hardware-Setup

- Identifiziere zuerst Vtref und GND mit einem Multimeter. Viele Adapter benötigen Vtref, um die I/O-Spannung einzustellen.
- Pegelwandlung: Verwende vorzugsweise bidirektionale Pegelwandler für Push-Pull-Signale (JTAG-Leitungen sind keine Open-Drain-Leitungen). Vermeide automatische I2C-Pegelwandler für JTAG.
- Nützliche Adapter: FT2232H/FT232H-Boards (z. B. Tigard), CMSIS-DAP, J-Link, ST-LINK (herstellerspezifisch), ESP-USB-JTAG (bei ESP32-Sx). Verbinde mindestens TCK, TMS, TDI, TDO, GND und Vtref; optional TRST und SRST.

Bei einem undokumentierten Header identifizierst du GND über die Durchgangsprüfung zu einer bekannten Massefläche, **während das Zielgerät nicht mit Strom versorgt wird**. Wechsle danach in den Spannungsmessmodus und schalte das Gerät ein. Ordne nicht jeden Pin mit hoher Spannung als Vtref ein: Hohe digitale Eingänge können auf einem Multimeter ähnlich aussehen. Verfolge mögliche Versorgungsschienen bis zu nahegelegenen Entkopplungskondensatoren und vergleiche ihre Ein- und Ausschaltverläufe mit einem Oszilloskop. Ein langsamer, kondensatorähnlicher Spannungsanstieg oder -abfall deutet auf eine Versorgungs- oder Referenzleitung hin. Überprüfe jedoch Spannung und Verdrahtung, bevor du eine pegelgewandelte Sonde anschließt. Bei PiFex kann über `VCCA_IN` eine externe Referenzspannung mit niedrigerer Spannung für das Zielgerät ausgewählt werden, anstelle der standardmäßigen Einstellung von 3,3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** ist ein Tool, das du auf einen Arduino-kompatiblen MCU oder versuchsweise auf einen Raspberry Pi laden kannst, um unbekannte JTAG-Pinbelegungen per Brute-Force zu ermitteln und Instruction-Register aufzuzählen.<sup>[[3]](#references)</sup>

- Arduino: Verbinde die digitalen Pins D2–D11 mit bis zu 10 vermuteten JTAG-Pads/Testpunkten und Arduino GND mit der Ziel-GND-Leitung. Versorge das Zielgerät separat mit Strom, sofern du nicht sicher bist, dass die Schiene unbedenklich ist. Bevorzuge 3,3-V-Logik (z. B. Arduino Due) oder verwende einen Pegelwandler/Serienwiderstände, wenn du Ziele mit 1,8–3,3 V abfragst.
- Raspberry Pi: Der Pi-Build stellt weniger nutzbare GPIOs bereit (daher sind Scans langsamer); prüfe im Repo die aktuelle Pinbelegung und die Einschränkungen.

Öffne nach dem Flashen den seriellen Monitor mit 115200 Baud und sende `h`, um die Hilfe aufzurufen. Typischer Ablauf:

- `l` Schleifenverbindungen finden, um Fehlalarme zu vermeiden
- `r` bei Bedarf interne Pull-ups umschalten
- `s` nach TCK/TMS/TDI/TDO (und manchmal TRST/SRST) suchen
- `y` IR per Brute-Force durchsuchen, um undokumentierte Opcodes zu entdecken
- `x` Boundary-Scan-Schnappschuss der Pinzustände

![JTAG - JTAGenum: x Boundary-Scan-Schnappschuss der Pinzustände](<../../images/image (939).png>)

![JTAG - JTAGenum: x Boundary-Scan-Schnappschuss der Pinzustände](<../../images/image (578).png>)

![JTAG - JTAGenum: x Boundary-Scan-Schnappschuss der Pinzustände](<../../images/image (774).png>)



Wenn ein gültiger TAP gefunden wird, werden Zeilen mit `FOUND!` angezeigt, die auf die ermittelten Pins hinweisen.

### Sicherheitshinweise zu JTAGenum

- Verwende immer eine gemeinsame Masse und treibe unbekannte Pins niemals mit einer Spannung über dem Vtref des Zielgeräts. Füge im Zweifelsfall Serienwiderstände von 100–470 Ω an den vermuteten Pins ein.
- Wenn das Gerät statt 4-Leiter-JTAG SWD/SWJ verwendet, erkennt JTAGenum es möglicherweise nicht. Probiere SWD-Tools oder einen Adapter mit SWJ-DP-Unterstützung aus.

## GPIO-Pin-Ermittlung mit go-jtagenum

Bei einem eingeschalteten Zielgerät mit überprüfter gemeinsamer Masse und kompatibler I/O-Spannung kann `go-jtagenum` mögliche JTAG-Signale über Raspberry-Pi-GPIOs ermitteln. Das JSON-Objekt `-pins` ordnet Bezeichnungen **GPIO-Nummern** zu, nicht den physischen Positionen am Header.<sup>[[5]](#references)</sup> Im SSD-Beispiel wurde beim ersten IDCODE-Scan außerdem eine unglaubwürdig lange Kette wechselnder Werte ausgegeben: Eine wechselnde TDO-Kandidatenleitung allein beweist kein gültiges TAP. Überprüfe ein plausibles Ergebnis erneut mit einem BYPASS-Scan, bei dem ein bekanntes Bitmuster von TDI durch das Ein-Bit-Bypass-Register zu TDO geschoben wird.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Für diese Platine bestätigte BYPASS `TCK=10`, `TMS=14`, `TDI=9` und `TDO=15`; die zusätzlichen Pins waren lediglich **mögliche** nTRST-Kandidaten. Wenn ein Kandidat nur Nullen oder ein inkonsistentes Muster zurückgibt, überprüfe Kontakt, Target-Stromversorgung, Pull-ups sowie Takt- und Reset-Verzögerungen, bevor du ihm ein Signal zuordnest.<sup>[[4]](#references)[[5]](#references)</sup> Das Tool akzeptiert auch `-known-pins` mit `test_bypass`, um eine rekonstruierte Zuordnung erneut zu testen.<sup>[[5]](#references)</sup>

## Einen undokumentierten TAP mit UrJTAG charakterisieren

Ein ermitteltes Pinout gibt weder die Opcodes des Instruction Registers (IR) noch die Breiten der Data Registers (DR) an, die fürs Debugging benötigt werden. Verwende einen UrJTAG-Build, der das Raspberry-Pi-GPIO-Kabel unterstützt, trage die rekonstruierte Zuordnung ein und führe `idcode`, `detect` und anschließend `discover` aus. Das SSD-Beispiel ermittelte einen TAP, ein vier Bit breites IR und unterschiedliche DR-Breiten für verschiedene IR-Werte. Eine DR-Länge von `-1` oder die Meldung „TDO stuck at 0“ ergibt keine brauchbare Registerdefinition. Überprüfe Timing, Verkabelung und die ausgewählte Instruktion, statt dem Register eine Breite zuzuweisen.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Das ist TAP-Reconnaissance, keine automatische CPU-Identifizierung: Vergleiche den resultierenden IDCODE mit der Gerätedokumentation und den unterstützten OpenOCD-Targets. UrJTAGs lokale Herstellerdatenbank kann eine ansonsten gültige ID als unbekannt kennzeichnen.<sup>[[4]](#references)</sup>

## Erster Kontakt mit OpenOCD (Scan und IDCODE)

OpenOCD ist das De-facto-OSS für JTAG/SWD. Mit einem unterstützten Adapter kannst du die Kette scannen und IDCODEs auslesen:<sup>[[1]](#references)</sup>

- Allgemeines Beispiel mit einem J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Integriertes USB-JTAG des ESP32-S3 (keine externe Sonde erforderlich):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Hinweise

- Wenn du einen IDCODE erhältst, der nur aus Einsen oder Nullen besteht, überprüfe die Verdrahtung, die Stromversorgung, Vtref und ob der Port durch Fuses/Option Bytes gesperrt ist.
- Sieh dir OpenOCDs Low-Level-Befehle `irscan`/`drscan` für die manuelle TAP-Interaktion an, wenn du unbekannte Chains initialisierst.<sup>[[1]](#references)</sup>

## Ein undokumentiertes Target in OpenOCD einbinden

Sobald TAP-ID und IR-Länge bekannt sind, sieh dir OpenOCDs Skripte in `cpu/`, `target/` und `board/` nach einer **passenden CPU-Architektur** an und erstelle dann separate Adapter- und Target-Konfigurationen.<sup>[[4]](#references)[[6]](#references)</sup> Das folgende Pi-GPIO-Mapping und das ARCv2-Target sind das getestete SSD-Beispiel, keine universelle JTAG-Konfiguration. Die Wahl des ARC-Targets und die Debug-Einstellungen waren Annahmen, die für dieses Gerät funktioniert haben; verwende auf einem anderen Board stattdessen die gemessene ID, IR-Länge, Architektur und GPIO-Nummern des Targets.<sup>[[4]](#references)</sup>

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

Führe `openocd -f raspberrypi-io.cfg -f target.cfg` aus und bestätige, dass die TAP-Untersuchung erfolgreich ist, bevor du den Speicher ausliest. Im Beispiel wurde Telnet auf Port `4444` und ein GDB-Server auf `3333` geöffnet; ein erkannter IDCODE allein beweist nicht, dass das ausgewählte CPU-Target untersucht oder debuggt werden kann.<sup>[[4]](#references)</sup> Raspberry-Pi-GPIOs müssen nicht den Pins entsprechen, die auf einem Breakout-Board als JTAG gekennzeichnet sind, wenn der Adapter `adapter gpio`-Remapping unterstützt.<sup>[[4]](#references)[[6]](#references)</sup>

## Anhalten der CPU und Dump von Speicher/Flash

Sobald das TAP erkannt und ein Target-Skript ausgewählt wurde, kannst du den Core anhalten und Speicherbereiche oder den internen Flash dumpen. Beispiele (Target, Basisadressen und Größen anpassen):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, programmieren oder mit einem OpenOCD-Hilfsprogramm auslesen:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Tipps zum Memory-Dumping

- Verwende `mdw/mdh/mdb`, um den Speicher vor langen Dumps auf Plausibilität zu prüfen.
- Setze bei Chains mit mehreren Geräten BYPASS für nicht angezielte Geräte oder verwende eine Board-Datei, die alle TAPs definiert.

Bei einer nicht dokumentierten Memory-Map prüfte die SSD-Recherche einen 1-MiB-Dump auf erkennbare Controller-Strings und verwendete dann ein architekturfähiges GDB über OpenOCD, um `$pc`, Disassembly und Register zu untersuchen. Diese Live-Adressen leiteten einen zweiten Region-Dump an, der mit passenden Instruktionen in einem ARC-fähigen Ghidra-Build abgeglichen wurde. Strings allein sind nur eine Plausibilitätsprüfung, kein Beweis dafür, dass das Image vollständig oder korrekt gemappt ist.<sup>[[4]](#references)</sup> Siehe [firmware analysis](../firmware-analysis/) für umfassendere Schritte zur statischen Analyse.

## Boundary-Scan-Tricks (EXTEST/SAMPLE)

Auch wenn der CPU-Debug-Zugriff gesperrt ist, kann Boundary-Scan weiterhin verfügbar sein. Mit UrJTAG/OpenOCD kannst du:<sup>[[1]](#references)</sup>
- SAMPLE verwenden, um Pin-Zustände während des Systembetriebs aufzunehmen (Busaktivität finden, Pin-Mapping bestätigen).
- EXTEST verwenden, um Pins anzusteuern (z. B. externe SPI-Flash-Leitungen über den MCU bit-bangen, um den Flash auszulesen, falls die Board-Verdrahtung dies ermöglicht).

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
Sie benötigen die BSDL des Geräts, um die Bitreihenfolge des Boundary-Registers zu kennen. Beachten Sie, dass manche Hersteller Boundary-Scan-Zellen in der Produktion sperren.

## Moderne Ziele und Hinweise

- ESP32‑S3/C3 verfügen über eine native USB‑JTAG-Bridge; OpenOCD kann ohne externe Probe direkt über USB kommunizieren. Sehr praktisch für Triage und Dumps.<sup>[[2]](#references)</sup>
- RISC‑V Debug (v0.13+) wird von OpenOCD umfassend unterstützt; bevorzugen Sie SBA für den Speicherzugriff, wenn der Core nicht sicher angehalten werden kann.
- Viele MCUs implementieren Debug-Authentifizierung und Lifecycle-Status. Wenn JTAG nicht zu funktionieren scheint, obwohl die Stromversorgung korrekt ist, könnte das Gerät auf einen geschlossenen Status gefused sein oder eine authentifizierte Probe erfordern.

## Abwehrmaßnahmen und Härtung (was bei echten Geräten zu erwarten ist)

- JTAG/SWD in der Produktion dauerhaft deaktivieren oder sperren (z. B. STM32 RDP Level 2, ESP eFuses, die PAD JTAG deaktivieren, NXP/Nordic APPROTECT/DPAP).
- Authentifiziertes Debugging voraussetzen (ARMv8.2‑A ADIv6 Debug Authentication, vom OEM verwaltete Challenge-Response), während der Zugang für die Fertigung erhalten bleibt.
- Leicht zugängliche Test-Pads vermeiden; Test-Vias vergraben, Widerstände entfernen/bestücken, um den TAP zu isolieren, sowie Steckverbinder mit Verpolungsschutz oder Pogo-Pin-Fixtures verwenden.
- Debug-Sperre beim Einschalten: Den TAP hinter einem frühen ROM blockieren, das Secure Boot durchsetzt.

## References

- [1] [OpenOCD-Benutzerhandbuch – JTAG-Befehle und Konfiguration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG-Debugging (USB‑JTAG, OpenOCD-Nutzung)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-basierter JTAG-Pinout-Scanner](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — JTAG-Hacking mit einem Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO-JTAG-Enumeration](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD-Benutzerhandbuch — Konfiguration des Debug-Adapters](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
