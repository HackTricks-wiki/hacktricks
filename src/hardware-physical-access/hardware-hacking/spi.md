# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchroner serieller Bus, der häufig für die Kommunikation über kurze Distanzen zwischen integrierten Schaltkreisen verwendet wird. Ein Controller liefert den Takt und wählt über ein Chip-Select-Signal ein Peripheriegerät aus, beispielsweise einen EEPROM, Sensor oder ein Steuergerät.<sup>[[1]](#references)</sup>

Mehrere Peripheriegeräte können sich Takt- und Datenleitungen teilen; normalerweise hat jedes Peripheriegerät einen eigenen Chip-Select. Der Controller steuert die Übertragungen; Peripheriegeräte kommunizieren über den SPI-Bus normalerweise nicht direkt miteinander. Die Polarität und das Timing von Chip-Select sind gerätespezifisch. Eine aktive Auswahl bei Low-Pegel ist üblich, aber nicht universell. SPI definiert weder Geräteerkennung und Adressierung noch Befehle oder eine einheitliche maximale Übertragungslänge. Ziehe daher immer das Datenblatt des Zielgeräts zu Rate.<sup>[[1]](#references)</sup>

MOSI/COPI überträgt Daten vom Controller zum Peripheriegerät und MISO/CIPO Daten vom Peripheriegerät zum Controller. Beide Richtungen können gleichzeitig Daten übertragen. Wie Befehl, Adresse und Dummy-Zyklen mit den zurückgegebenen Daten zusammenhängen, wird vom Peripheriegerät festgelegt – nicht von SPI – und hängt von der Taktpolarität und -phase (Modi 0–3) ab. Gehe nicht davon aus, dass die Ausgabe genau einen Takt nach dem Ende der Eingabe beginnt.<sup>[[1]](#references)</sup>

## Firmware aus EEPROMs auslesen

Das Auslesen der Firmware kann bei ihrer Analyse und beim Auffinden von Schwachstellen hilfreich sein. Das passende Image ist möglicherweise online nicht verfügbar oder unterscheidet sich je nach Modell, Hardware-Revision oder Version. Durch das direkte Auslesen vom physischen Gerät erhältst du daher ein exaktes Ziel für die Analyse.

Eine serielle Konsole kann hilfreich sein, aber ihr Dateisystem ist möglicherweise schreibgeschützt und auf dem Ziel fehlen eventuell Analysewerkzeuge, einschließlich Dienstprogrammen zum Senden und Empfangen von Testdatenverkehr oder zum einfachen Extrahieren von Binärdateien. Ein Offline-Image bewahrt das vollständige Flash-Layout und ermöglicht das Extrahieren des Dateisystems und Reverse Engineering, ohne das laufende Ziel zu verändern.

Bei einer autorisierten physischen Untersuchung kann ein verifiziertes Dump auch kontrollierte Modifikations- und Reflash-Tests unterstützen. Dazu gehört das Ändern von Dateien oder das Einschleusen eines Test-Payloads/einer Backdoor, um Persistenz auf Firmware-Ebene nachzuweisen. Sichere mehrere übereinstimmende Auslesungen und das Original-Image, bevor du etwas schreibst: Eine falsche Spannung, Chip-Auswahl, ein falsches Layout oder Image kann das Gerät unbrauchbar machen.

### CH341A EEPROM-Programmiergerät und -Lesegerät

Mit diesem günstigen USB-Tool lassen sich kompatible serielle EEPROMs und SPI-Flash-Geräte auslesen und neu flashen. Es wird häufig mit SPI-NOR-Flash-Chips verwendet, die PC-BIOS-/UEFI-Firmware speichern, und ist bei zeitlich begrenztem physischem Zugriff praktisch.

![drawing](../../images/board_image_ch341a.jpg)

Verbinde den Flash-Speicher mit dem CH341A und anschließend das Programmiergerät mit dem Computer. Wird das Programmiergerät selbst nicht erkannt, überprüfe das USB-Kabel, die OS-Berechtigungen und den passenden CH341A-Treiber, bevor du das Zielgerät untersuchst. Überprüfe anhand der Datenblätter oder mit einem Messgerät die Spannung des Chips, Pin 1, die Adapterverdrahtung und die Ausgangsspannung des Programmiergeräts – verlasse dich **nicht** auf eine Regel wie „VCC gegenüber dem USB-Anschluss platzieren“. Eine falsche Ausrichtung oder 5 V an einem 3,3-/1,8-V-Bauteil können es zerstören. Auslesevorgänge in der Schaltung können ebenfalls fehlschlagen, wenn der Rest der Platine den Bus belastet oder mit Strom versorgt.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Verwende zum Auslesen des Chips Software wie `flashrom` oder G-Flash. G-Flash ist eine einfache GUI und kann kompatible Geräte automatisch erkennen. Das kann bei einer schnellen Erfassung praktisch sein, aber überprüfe das erkannte Modell und die Spannung selbst. Gib das genaue Programmiergerät und, falls erforderlich, das genaue Chip-Modell an. Lies den Chip mindestens zweimal aus und vergleiche die Hashes, bevor du ein Dump als zuverlässig einstufst.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nach dem Auslesen der Firmware kann die Analyse anhand der Binärdateien erfolgen. Mit Tools wie strings, hexdump, xxd, binwalk usw. lassen sich viele Informationen über die Firmware sowie das gesamte Dateisystem extrahieren.

Für eine erste Sichtung kann Binwalk nach bekannten Signaturen suchen und unterstützte eingebettete Inhalte extrahieren:

```
binwalk -e <filename>
```

Die Ausgabedatei kann die Endung `.bin`, `.rom` oder eine andere haben; anhand der Endung lässt sich das Format nicht bestimmen.

> [!CAUTION]
> Beachte, dass das Extrahieren von Firmware ein heikler Prozess ist und viel Geduld erfordert. Bei unsachgemäßer Handhabung kann die Firmware beschädigt oder sogar vollständig gelöscht werden, sodass das Gerät unbrauchbar wird. Es wird empfohlen, sich vor dem Extrahieren der Firmware mit dem jeweiligen Gerät vertraut zu machen.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

In manchen Datenblättern sind die Pins des Targets mit `DI` und `DO` bezeichnet: Bei einer herkömmlichen Flash-Verbindung mit einer Datenleitung wird **MOSI/COPI des Controllers mit DI** und **MISO/CIPO des Controllers mit DO** verbunden. Prüfe das Datenblatt des Targets, da Dual-/Quad-I/O-Bausteine dieselben Pins in anderen Modi anders verwenden.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

Unter Windows oder Linux kannst du das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers mit einem Befehl wie diesem auszulesen:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Die aktuelle Bus Pirate-Dokumentation zeigt außerdem die optionalen Parameter `serialspeed` und `spispeed`. Beginne mit einer niedrigen Geschwindigkeit, wenn lange Kabel oder die Belastung im eingebauten Zustand zu instabilen Lesevorgängen führen.<sup>[[3]](#references)</sup>

### Lesen im eingebauten Zustand, wenn der Controller den Flash-Bus mitbenutzt

Ein SOIC-Clip kann die Flash-Versorgungsspannung in den Rest der Platine einspeisen. Wird der MCU dadurch mit Strom versorgt und greift auf denselben Chip zu, können seine SPI-Übertragungen mit denen des externen Programmiergeräts kollidieren. Ein Ergebnis wie `No EEPROM/flash device found` beweist daher nicht, dass der Flash fehlt oder nicht unterstützt wird. Prüfe zuerst Pinbelegung, Spannung und Kontakt und stelle dann fest, ob auch der Controller auf der Platine aktiv ist.<sup>[[4]](#references)</sup>

Wenn ein Reset-Testpad vorhanden ist, bestätige mit einem Multimeter dessen Polarität und Spannung, bevor du es aktivierst. Wird der MCU im Reset gehalten, kann der Flash zugänglich bleiben, während der konkurrierende SPI-Host gestoppt wird. Alternativ kannst du den Chip auslöten oder die Lesezugriffe des MCU passiv aufzeichnen. Letzteres ermöglicht weder den Zugriff auf ungelesene Bereiche noch das Schreiben auf den Chip; zusätzliche Messleitungen können außerdem einen schnellen Bus stören. Ein Eingriff am Oszillator oder Boot-Modus ist zielspezifisch und kein Ersatz für die Prüfung von Schaltplan und Signalen.<sup>[[4]](#references)</sup>

Wird der MCU inaktiv gehalten, kann ein Raspberry Pi mit aktivierter `spidev`-Schnittstelle den Flash über flashroms `linux_spi`-Programmiergerät auslesen. Passe `-p` für einen anderen Adapter an. Wiederhole den Lesevorgang und vergleiche die Hashes, bevor du dem Ergebnis vertraust. SFDP-Autodetektion und ein erfolgreiches Auslesen belegen **nicht**, dass Lösch-, Schreib- oder Schreibschutzvorgänge bei einem ansonsten nicht unterstützten Bauteil funktionieren.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### SPI-Flash-Lesevorgänge mit einem Logikanalysator rekonstruieren

Wenn aktives Auslesen nicht möglich ist, zeichne während des Bootvorgangs oder einer ausgewählten UI-Aktion Chip-Select, Clock, Daten vom Controller zum Flash und Daten vom Flash zum Controller auf. Identifiziere in PulseView zuerst das aktive Chip-Select-Intervall und den Clock, konfiguriere dann die Datenkanäle des SPI-Decoders anhand des Flash-Pinouts und überprüfe, ob auf einen plausiblen Befehl mit Adresse zurückgegebene Bytes folgen. Exportiere die **MISO/Flash-Ausgabe**-Bytes mit der Binary Decoder Output View und bewahre die decodierten Leseadressen auf, damit jede Antwort an ihrem entsprechenden Flash-Offset abgelegt werden kann. Wenn du nur menügesteuerte Lesevorgänge aufzeichnest, erhältst du nur die angeforderten Bereiche, kein vollständiges Flash-Abbild. Füge Antworten nicht zusammen, als wären sie zusammenhängend, ohne die Adressen zu prüfen.<sup>[[4]](#references)</sup>

Wenn ein Dump eher Grafiken als ausführbaren Code zu enthalten scheint, fahre mit der [Triage roher Display-Assets](../firmware-analysis/#raw-display-assets-in-external-flash) fort.<sup>[[4]](#references)</sup>

#### Scapy und gemischte SPI/QSPI-Aufzeichnungen

Unterscheide bei nicht beschrifteten Probes MOSI von MISO anhand der Leitung, die vor den Antwortdaten den Opcode überträgt, und überprüfe den Befehl anschließend anhand des Flash-Datenblatts. Impulse mit einer Dauer unterhalb eines Clock-Zyklus können Probe-Rauschen statt abgetasteter Bits sein, und zusätzliche Clip-Verkabelung kann Hochgeschwindigkeitsaufzeichnungen unzuverlässig machen.<sup>[[5]](#references)</sup>

Der SPI-CSV-Export von Saleae verwendet `enable` und `disable`, um ein Chip-Select-Intervall zu markieren; MOSI/MISO-Bytes stehen in `result`-Zeilen. Gruppiere die Bytes nach Intervall, bevor du sie decodierst. Werden alle MISO-Daten zusammengefügt, gehen die Transaktionsadressen verloren.<sup>[[5]](#references)</sup> Ein Scapy-`Packet` kann den MOSI-Header mit einem `ByteEnumField`-Opcode sowie bedingten Adress- und Dummy-Feldern modellieren. Bei 24-Bit-NOR-Lesevorgängen enthält `0x03` einen Opcode und drei Adressbytes, während `0x0B` ein Dummy-Byte hinzufügt. `len(req.self_build())` liefert die Länge des modellierten Headers: Bei einem Single-Lane-Lesevorgang ist `miso[header_length:]` die Flash-Antwort, während MOSI-Daten nach dem Header controllerseitige Don't-Care-Daten sind.<sup>[[5]](#references)</sup> Lege die Antworten anhand ihrer decodierten Adressen in einem mit `0xFF` gefüllten Abbild ab und erfasse die abgedeckten Offsets separat. Ein nicht beobachtetes Byte ist kein Beleg dafür, dass der Flash dort den Wert `0xFF` enthielt.<sup>[[5]](#references)[[6]](#references)</sup>

Ein `0x6B`-Lesevorgang (1-1-4) im W25Q-Stil verwendet eine Lane für Opcode und Adresse, aber IO0–IO3 für die Antwortdaten. Aktivität an den früheren Pins `/WP` und `/HOLD` ist ein stärkerer Hinweis auf einen Wechsel in den Quad-Modus als eine höhere Clock-Frequenz allein; ein Single-Lane-Analysator kann die Quad-Antwort falsch decodieren.<sup>[[5]](#references)</sup> Exportiere diese Phase mit einem QSPI-Analysator, der auf die Lane-Breiten und Dummy-Zyklen des Befehls eingestellt ist, und füge anschließend die Single- und Quad-Lane-Lesevorgänge anhand der Flash-Adresse zusammen.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` erkennt beide Exportformate automatisch, verwirft Lesevorgänge, die mit der falschen Lane-Breite decodiert wurden, und meldet die Abdeckung der Lesevorgänge.<sup>[[6]](#references)</sup> Führe nach der Installation der Abhängigkeiten im Repository die Aufzeichnungen mit folgendem Befehl zusammen:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Das Ergebnis bleibt eine lückenhafte Beobachtung und ist kein vollständiger Chip-Dump.<sup>[[5]](#references)[[6]](#references)</sup> Um Schreibvorgänge separat zu untersuchen, korrelieren Sie `0x06`-Write-Enable-Befehle, `0x05`-Statusabfragen, Lösch-Opcodes und `0x02`-Page-Program-Befehle. Die Page-Program-Daten folgen auf MOSI auf die Adresse und sind in einer ausschließlich lesenden Rekonstruktion nicht enthalten.<sup>[[5]](#references)</sup> Analysieren Sie das resultierende Image mit [Firmware-Analyse](../firmware-analysis/) und behalten Sie dabei die Informationen zur Leseabdeckung bei.

## References

- [1] [Analog Devices — Einführung in die SPI-Schnittstelle](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-Handbuch — CH341A-SPI-Programmiergerät und Lese-/Schreiboptionen](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus-Pirate-Dokumentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Hardware Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Scapy für Hardware-Reverse-Engineering erweitern](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI-Trace-Erfassung und -Rekonstruktion](https://github.com/wrongbaud/spidump)
- [7] [QSPI Analyzer für Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
