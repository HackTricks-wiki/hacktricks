# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchroner serieller Bus, der häufig für die Kommunikation über kurze Distanzen zwischen integrierten Schaltkreisen verwendet wird. Ein Controller stellt den Takt bereit und wählt über ein Chip-Select-Signal ein Peripheriegerät aus, etwa ein EEPROM, einen Sensor oder ein Steuergerät.<sup>[[1]](#references)</sup>

Mehrere Peripheriegeräte können sich die Takt- und Datenleitungen teilen, normalerweise mit einem separaten Chip-Select pro Peripheriegerät. Der Controller steuert die Übertragungen; Peripheriegeräte kommunizieren normalerweise nicht direkt über den SPI-Bus miteinander. Polarität und Timing des Chip-Select sind gerätespezifisch; eine aktive Auswahl bei Low-Pegel ist üblich, aber nicht universell. SPI legt weder Erkennung, Adressierung und Befehle noch eine maximale Übertragungslänge fest. Konsultiere daher immer das Datenblatt des Zielgeräts.<sup>[[1]](#references)</sup>

MOSI/COPI überträgt Daten vom Controller zum Peripheriegerät und MISO/CIPO Daten vom Peripheriegerät zum Controller. Beide Richtungen können gleichzeitig Daten verschieben. Die Beziehung zwischen einem Befehl, einer Adresse, Dummy-Zyklen und den zurückgegebenen Daten wird vom Peripheriegerät definiert – nicht von SPI – und hängt von der Taktpolarität und -phase (Modi 0–3) ab. Gehe nicht davon aus, dass die Ausgabe genau einen Takt nach Ende der Eingabe beginnt.<sup>[[1]](#references)</sup>

## Firmware von EEPROMs dumpen

Das Dumpen von Firmware kann bei ihrer Analyse und beim Finden von Schwachstellen hilfreich sein. Das richtige Image ist möglicherweise online nicht verfügbar oder unterscheidet sich je nach Modell, Hardware-Revision oder Version. Daher liefert das direkte Extrahieren vom physischen Gerät ein exaktes Ziel für die Bewertung.

Eine serielle Konsole kann hilfreich sein, aber ihr Dateisystem ist möglicherweise schreibgeschützt und auf dem Zielgerät fehlen eventuell Analysetools, darunter Dienstprogramme zum Senden und Empfangen von Testdatenverkehr oder zum bequemen Extrahieren von Binärdateien. Ein Offline-Image bewahrt das vollständige Flash-Layout und ermöglicht das Extrahieren des Dateisystems und Reverse Engineering, ohne das laufende Zielgerät zu verändern.

Bei einer autorisierten physischen Untersuchung kann ein verifiziertes Dump auch kontrollierte Änderungen und Reflash-Tests unterstützen. Dazu gehört, Dateien zu ändern oder eine Test-Payload bzw. eine Backdoor einzuschleusen, um die Persistenz auf Firmware-Ebene nachzuweisen. Bewahre vor jedem Schreibvorgang mehrere übereinstimmende Reads und das Original-Image auf: Eine falsche Spannung, Chipauswahl, ein falsches Layout oder Image kann das Gerät unbrauchbar machen.

### CH341A EEPROM-Programmiergerät und -Lesegerät

Dieses kostengünstige USB-Tool kann kompatible serielle EEPROMs und SPI-Flash-Geräte dumpen und neu flashen. Es wird häufig mit SPI-NOR-Flash-Chips verwendet, die PC-BIOS-/UEFI-Firmware speichern, und ist bei zeitlich begrenztem physischem Zugriff praktisch.

![drawing](../../images/board_image_ch341a.jpg)

Verbinde den Flash-Speicher mit dem CH341A und anschließend das Programmiergerät mit dem Computer. Wenn das Programmiergerät selbst nicht erkannt wird, überprüfe das USB-Kabel, die Betriebssystemberechtigungen und den passenden CH341A-Treiber, bevor du das Zielgerät untersuchst. Prüfe die Spannung des Chips, Pin 1, die Verdrahtung des Adapters und die Ausgabe des Programmiergeräts anhand der Datenblätter oder mit einem Messgerät – verlasse dich **nicht** auf eine Regel wie „VCC gegenüber dem USB-Anschluss platzieren“. Eine falsche Ausrichtung oder eine Spannung von 5 V an einem Bauteil mit 3,3/1,8 V kann es zerstören. Reads in der Schaltung können ebenfalls fehlschlagen, weil der Rest der Platine den Bus belastet oder mit Strom versorgt.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Verwende Software wie `flashrom` oder G-Flash, um den Chip auszulesen. G-Flash ist eine minimale GUI und kann kompatible Geräte automatisch erkennen, was bei einer schnellen Erfassung praktisch sein kann. Überprüfe das erkannte Modell und die Spannung jedoch selbst. Gib das genaue Programmiergerät und, falls erforderlich, das genaue Chipmodell an; führe mindestens zwei Reads durch und vergleiche ihre Hashes, bevor du ein Dump als zuverlässig einstufst.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse anhand der Binärdateien erfolgen. Mit Tools wie strings, hexdump, xxd, binwalk usw. lassen sich viele Informationen über die Firmware sowie das gesamte Dateisystem extrahieren.

Für die erste Triage kann Binwalk nach bekannten Signaturen suchen und unterstützte eingebettete Inhalte extrahieren:

```
binwalk -e <filename>
```

Die Ausgabedatei kann die Endung `.bin`, `.rom` oder eine andere haben; die Dateiendung legt das Format nicht fest.

> [!CAUTION]
> Beachte, dass das Auslesen der Firmware ein heikler Vorgang ist und viel Geduld erfordert. Bei unsachgemäßer Handhabung kann die Firmware beschädigt oder sogar vollständig gelöscht werden, wodurch das Gerät unbrauchbar wird. Es wird empfohlen, sich mit dem jeweiligen Gerät vertraut zu machen, bevor du versuchst, die Firmware auszulesen.

### Bus Pirate + flashrom

![CH341A EEPROM-Programmiergerät und -Lesegerät - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Einige Datenblätter bezeichnen die Pins des Zielgeräts mit `DI` und `DO`: Bei einer herkömmlichen Flash-Verbindung mit einer Datenleitung wird **MOSI/COPI des Controllers mit DI** und **MISO/CIPO des Controllers mit DO** verbunden. Prüfe das Datenblatt des Zielgeräts, da Bauteile mit Dual-/Quad-I/O diese Pins in anderen Modi anderweitig verwenden.

![CH341A EEPROM-Programmiergerät und -Lesegerät - Bus Pirate + flashrom: Beachte, dass die PINBELEGUNG des Bus Pirate zwar Pins für den Anschluss von MOSI und MISO an SPI angibt, einige SPI-Bauteile jedoch möglicherweise...](<../../images/image (360).png>)

Unter Windows oder Linux kannst du das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers mit einem Befehl wie diesem auszulesen:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Die aktuelle Bus Pirate-Dokumentation zeigt außerdem die optionalen Parameter `serialspeed` und `spispeed`. Beginne mit einer niedrigen Geschwindigkeit, wenn lange Kabel oder die Belastung durch die Schaltung zu instabilen Lesevorgängen führen.<sup>[[3]](#references)</sup>

### In-circuit-Lesevorgänge, wenn der Controller denselben Flash-Bus nutzt

Ein SOIC-Clip kann die Versorgung des Flash-Bausteins auf den Rest der Platine übertragen. Wird der MCU dadurch mit Strom versorgt und greift auf denselben Chip zu, können seine SPI-Übertragungen mit denen des externen Programmiergeräts kollidieren. Die Meldung `No EEPROM/flash device found` beweist daher nicht, dass der Flash fehlt oder nicht unterstützt wird. Prüfe zuerst Pinbelegung, Spannung und Kontakt und stelle dann fest, ob auch der Controller auf der Platine aktiv ist.<sup>[[4]](#references)</sup>

Wenn ein Reset-Testpad verfügbar ist, prüfe dessen Polarität und Spannung mit einem Multimeter, bevor du es aktivierst. Wird der MCU im Reset gehalten, kann der Flash zugänglich bleiben, während der konkurrierende SPI-Host angehalten wird. Alternativ kann der Chip ausgelötet oder die Kommunikation des MCU passiv aufgezeichnet werden. Letzteres ermöglicht weder den Zugriff auf ungelesene Bereiche noch das Beschreiben des Chips; zusätzliche Messleitungen können außerdem einen schnellen Bus stören. Ein Eingriff am Oszillator oder Boot-Modus ist targetspezifisch und kein Ersatz dafür, Schaltplan und Signale zu prüfen.<sup>[[4]](#references)</sup>

Bei inaktivem MCU kann ein Raspberry Pi mit aktiviertem `spidev`-Interface über flashroms `linux_spi`-Programmiergerät lesen. Ändere `-p` für einen anderen Adapter. Wiederhole den Lesevorgang und vergleiche die Hashes, bevor du dem Ergebnis vertraust. Die SFDP-Autodetektion und ein erfolgreicher Lesevorgang belegen **nicht**, dass Lösch-, Schreib- oder Schreibschutzoperationen bei einem ansonsten nicht unterstützten Baustein funktionieren.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### SPI-Flash-Lesevorgänge mit einem Logikanalysator rekonstruieren

Wenn aktives Auslesen nicht möglich ist, erfasse Chip-Select, Clock, Daten vom Controller zum Flash und Daten vom Flash zum Controller während des Bootens oder einer ausgewählten UI-Aktion. Identifiziere in PulseView zuerst das aktive Chip-Select-Intervall und den Clock, konfiguriere dann die Datenkanäle des SPI-Decoders anhand des Flash-Pinouts und überprüfe, ob ein plausibler Befehl und eine Adresse gefolgt von zurückgegebenen Bytes erscheinen. Exportiere die **MISO/Flash-Ausgabe**-Bytes mit der Binary Decoder Output View und bewahre die decodierten Leseadressen auf, damit jede Antwort ihrem entsprechenden Flash-Offset zugeordnet werden kann. Wenn du nur menügesteuerte Lesevorgänge erfasst, erhältst du nur die angeforderten Bereiche und kein vollständiges Flash-Abbild. Füge Antworten nicht einfach zusammen, als wären sie zusammenhängend, ohne die Adressen zu prüfen.<sup>[[4]](#references)</sup>

Wenn ein Dump eher Grafiken als ausführbaren Code zu enthalten scheint, fahre mit der [Triage von Bildschirminhalten als Rohdaten](../firmware-analysis/#raw-display-assets-in-external-flash) fort.<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Einführung in die SPI-Schnittstelle](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-Handbuch — CH341A-SPI-Programmiergerät und Lese-/Schreiboptionen](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate-Dokumentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Hardware-Hacking-Kenntnisse auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
