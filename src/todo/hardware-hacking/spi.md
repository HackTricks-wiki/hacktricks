# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchroner serieller Bus, der häufig für die Kommunikation über kurze Entfernungen zwischen integrierten Schaltkreisen verwendet wird. Ein Controller stellt den Takt bereit und wählt ein Peripheriegerät, beispielsweise ein EEPROM, einen Sensor oder ein Steuergerät, über ein Chip-Select-Signal aus.<sup>[[1]](#references)</sup>

Mehrere Peripheriegeräte können sich die Takt- und Datenleitungen teilen, normalerweise mit einem separaten Chip-Select pro Peripheriegerät. Der Controller koordiniert die Übertragungen; Peripheriegeräte kommunizieren normalerweise nicht direkt über den SPI-Bus miteinander. Chip-Select-Polarität und Timing sind gerätespezifisch; eine Active-Low-Auswahl ist üblich, aber nicht universell. SPI definiert weder Discovery noch Adressierung, Befehle oder eine einzelne maximale Übertragungslänge. Konsultiere daher immer das Datenblatt des Zielgeräts.<sup>[[1]](#references)</sup>

MOSI/COPI überträgt Daten vom Controller zum Peripheriegerät, während MISO/CIPO Daten vom Peripheriegerät zum Controller überträgt. Beide Richtungen können gleichzeitig verschoben werden. Die Beziehung zwischen einem Befehl, einer Adresse, Dummy-Zyklen und den zurückgegebenen Daten wird vom Peripheriegerät definiert – nicht von SPI – und hängt von der Taktpolarität und -phase (Modi 0–3) ab. Gehe nicht davon aus, dass die Ausgabe genau einen Takt nach dem Ende der Eingabe beginnt.<sup>[[1]](#references)</sup>

## Firmware aus EEPROMs dumpen

Das Dumpen von Firmware kann für deren Analyse und die Suche nach Schwachstellen hilfreich sein. Das korrekte Image ist möglicherweise online nicht verfügbar oder unterscheidet sich je nach Modell, Hardware-Revision oder Version. Durch das direkte Extrahieren vom physischen Gerät erhältst du ein exaktes Untersuchungsziel.

Eine serielle Konsole kann hilfreich sein, aber ihr Dateisystem ist möglicherweise schreibgeschützt und auf dem Zielgerät fehlen eventuell Analyse-Tools, einschließlich der Dienstprogramme, die zum Senden und Empfangen von Testdaten oder zum bequemen Extrahieren von Binaries erforderlich sind. Ein Offline-Image bewahrt das vollständige Flash-Layout und ermöglicht die Extraktion des Dateisystems sowie Reverse Engineering, ohne das laufende Zielgerät zu verändern.

Während einer autorisierten physischen Untersuchung kann ein verifiziertes Dump auch kontrollierte Änderungen und Reflashing-Tests unterstützen. Dazu gehört das Ändern von Dateien oder das Injizieren eines Test-Payloads/einer backdoor, um Persistenz auf Firmware-Ebene zu demonstrieren. Bewahre mehrere übereinstimmende Reads und das ursprüngliche Image vor jedem Schreibvorgang auf: Eine falsche Spannung, Chipauswahl, Anordnung oder ein falsches Image kann das Gerät unbrauchbar machen.

### CH341A EEPROM Programmer und Reader

Dieses kostengünstige USB-Tool kann kompatible serielle EEPROM- und SPI-Flash-Geräte dumpen und reflashen. Es wird häufig mit SPI-NOR-Flash-Chips verwendet, die PC-BIOS/UEFI-Firmware speichern, und ist bei zeitlich begrenztem physischem Zugriff praktisch.

![Zeichnung](../../images/board_image_ch341a.jpg)

Verbinde den Flash-Speicher mit dem CH341A und anschließend den Programmer mit dem Computer. Wenn der Programmer selbst nicht erkannt wird, überprüfe vor der Fehlersuche am Zielchip das USB-Kabel, die Betriebssystemberechtigungen und den passenden CH341A-Treiber. Überprüfe die Spannung des Chips, Pin 1, die Adapterverdrahtung und den Ausgang des Programmers anhand der Datenblätter oder mit einem Messgerät – verlasse dich **nicht** auf eine Regel wie das Platzieren von VCC gegenüber dem USB-Anschluss. Eine falsche Ausrichtung oder eine an ein 3,3/1,8-V-Bauteil angelegte Spannung von 5 V kann es zerstören. In-Circuit-Reads können ebenfalls fehlschlagen, weil der Rest der Platine den Bus belastet oder mit Strom versorgt.<sup>[[2]](#references)</sup>

![Zeichnung](../../images/connect_wires_ch341a.jpg) ![Zeichnung](../../images/eeprom_plugged_ch341a.jpg)

Verwende Software wie `flashrom` oder G-Flash, um den Chip auszulesen. G-Flash ist eine minimale GUI und kann kompatible Geräte automatisch erkennen, was bei einer schnellen Akquisition praktisch sein kann. Überprüfe das erkannte Modell und die Spannung jedoch selbst. Gib den exakten Programmer und, falls erforderlich, das exakte Chipmodell an. Führe mindestens zwei Reads durch und vergleiche deren Hashes, bevor du einen Dump als zuverlässig betrachtest.<sup>[[2]](#references)</sup>

![Zeichnung](../../images/connected_status_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse anhand der Binärdateien durchgeführt werden. Tools wie strings, hexdump, xxd, binwalk usw. können verwendet werden, um zahlreiche Informationen über die Firmware sowie über das gesamte Dateisystem zu extrahieren.

Für eine erste Triage kann Binwalk nach bekannten Signaturen suchen und unterstützte eingebettete Inhalte extrahieren:
```
binwalk -e <filename>
```
Die Ausgabedatei kann `.bin`, `.rom` oder eine andere Erweiterung verwenden; die Erweiterung legt das Format nicht fest.

> [!CAUTION]
> Beachte, dass die Firmware-Extraktion ein empfindlicher Prozess ist und viel Geduld erfordert. Jede unsachgemäße Handhabung kann die Firmware potenziell beschädigen oder sogar vollständig löschen und das Gerät unbrauchbar machen. Es wird empfohlen, das jeweilige Gerät zu untersuchen, bevor versucht wird, die Firmware zu extrahieren.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Einige Datenblätter beschriften die Zielpins mit `DI` und `DO`: Bei einer herkömmlichen Flash-Verbindung mit einer einzelnen Datenleitung verbindet sich der Controller **MOSI/COPI mit DI** und der Controller **MISO/CIPO mit DO**. Überprüfe das Datenblatt des Zielbausteins, da Dual-/Quad-I/O-Bausteine dieselben Pins in anderen Modi wiederverwenden.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Beachte, dass selbst wenn das PINOUT des Pirate Bus Pins für MOSI und MISO zum Verbinden mit SPI angibt, einige SPIs möglicherweise...](<../../images/image (360).png>)

Unter Windows oder Linux kannst du das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers mit einem Befehl ähnlich dem folgenden zu dumpen:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Die aktuelle Bus Pirate-Dokumentation zeigt außerdem die optionalen Parameter `serialspeed` und `spispeed`. Beginne vorsichtig, wenn lange Kabel oder die Belastung im eingebauten Schaltkreis die Lesevorgänge instabil machen.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Einführung in die SPI-Schnittstelle](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-Handbuch — CH341A-SPI-Programmierer und Optionen zum Lesen/Schreiben](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus-Pirate-Dokumentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
