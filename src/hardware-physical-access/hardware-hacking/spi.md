# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchroner serieller Bus, der häufig für die Kommunikation über kurze Distanzen zwischen integrierten Schaltkreisen verwendet wird. Ein Controller stellt den Takt bereit und wählt über ein Chip-Select-Signal ein Peripheriegerät aus, etwa ein EEPROM, einen Sensor oder ein Steuergerät.<sup>[[1]](#references)</sup>

Mehrere Peripheriegeräte können sich die Takt- und Datenleitungen teilen. Üblicherweise gibt es für jedes Peripheriegerät ein eigenes Chip-Select-Signal. Der Controller steuert die Übertragungen; Peripheriegeräte kommunizieren normalerweise nicht direkt über den SPI-Bus miteinander. Chip-Select-Polarität und -Timing sind gerätespezifisch; eine aktive Low-Auswahl ist üblich, aber nicht universell. SPI definiert weder Erkennung und Adressierung noch Befehle oder eine maximale Übertragungslänge. Konsultieren Sie daher immer das Datenblatt des Zielgeräts.<sup>[[1]](#references)</sup>

MOSI/COPI überträgt Daten vom Controller zum Peripheriegerät, MISO/CIPO vom Peripheriegerät zum Controller. Beide Richtungen können gleichzeitig übertragen werden. Wie Befehl, Adresse und Dummy-Zyklen mit den zurückgegebenen Daten zusammenhängen, wird vom Peripheriegerät und nicht von SPI festgelegt und hängt von der Taktpolarität und -phase (Modi 0–3) ab. Gehen Sie nicht davon aus, dass die Ausgabe exakt einen Takt nach Ende der Eingabe beginnt.<sup>[[1]](#references)</sup>

## Firmware von EEPROMs dumpen

Das Dumpen von Firmware kann bei ihrer Analyse und beim Auffinden von Schwachstellen hilfreich sein. Das passende Image ist möglicherweise online nicht verfügbar oder unterscheidet sich je nach Modell, Hardware-Revision oder Version. Daher liefert das direkte Auslesen vom physischen Gerät ein exaktes Ziel für die Analyse.

Eine serielle Konsole kann hilfreich sein, aber ihr Dateisystem ist möglicherweise schreibgeschützt, und auf dem Zielgerät fehlen womöglich Analysetools, darunter Dienstprogramme zum Senden und Empfangen von Testdatenverkehr oder zum bequemen Extrahieren von Binärdateien. Ein Offline-Image bewahrt das vollständige Flash-Layout und ermöglicht das Extrahieren des Dateisystems und Reverse Engineering, ohne das laufende Zielgerät zu verändern.

Bei einer autorisierten physischen Sicherheitsüberprüfung kann ein verifiziertes Dump auch kontrollierte Modifikations- und Reflash-Tests unterstützen. Dazu gehört, Dateien zu ändern oder eine Test-Payload/Backdoor einzuschleusen, um Firmware-Persistenz nachzuweisen. Bewahren Sie mehrere übereinstimmende Lesevorgänge und das Original-Image auf, bevor Sie etwas schreiben: Eine falsche Spannung, Chipauswahl, ein falsches Layout oder Image kann das Gerät unbrauchbar machen.

### CH341A EEPROM-Programmer und -Lesegerät

Dieses günstige USB-Tool kann kompatible serielle EEPROMs und SPI-Flash-Bausteine auslesen und neu flashen. Es wird häufig mit SPI-NOR-Flash-Chips verwendet, auf denen PC-BIOS/UEFI-Firmware gespeichert ist, und ist bei zeitlich begrenztem physischem Zugriff praktisch.

![Zeichnung](../../images/board_image_ch341a.jpg)

Schließen Sie den Flash-Speicher an den CH341A und anschließend den Programmer an den Computer an. Wird der Programmer selbst nicht erkannt, überprüfen Sie das USB-Kabel, die Betriebssystemberechtigungen und den passenden CH341A-Treiber, bevor Sie das Zielgerät untersuchen. Prüfen Sie Spannung, Pin 1, Adapterverdrahtung und Programmer-Ausgang anhand der Datenblätter oder mit einem Messgerät — verlassen Sie sich **nicht** auf eine Regel wie „VCC liegt gegenüber dem USB-Anschluss“. Falsche Ausrichtung oder 5 V an einem Baustein mit 3,3/1,8 V können ihn zerstören. Auch das Auslesen in der Schaltung kann scheitern, weil der Rest der Platine den Bus belastet oder mit Strom versorgt.<sup>[[2]](#references)</sup>

![Zeichnung](../../images/connect_wires_ch341a.jpg) ![Zeichnung](../../images/eeprom_plugged_ch341a.jpg)

Verwenden Sie zum Auslesen des Chips Software wie `flashrom` oder G-Flash. G-Flash ist eine minimalistische GUI und kann kompatible Geräte automatisch erkennen. Das kann bei einer schnellen Erfassung praktisch sein, doch überprüfen Sie das erkannte Modell und die Spannung selbst. Geben Sie den exakten Programmer und, falls erforderlich, das genaue Chipmodell an. Führen Sie mindestens zwei Lesevorgänge durch und vergleichen Sie ihre Hashes, bevor Sie ein Dump als zuverlässig betrachten.<sup>[[2]](#references)</sup>

![Zeichnung](../../images/connected_status_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse anhand der Binärdateien erfolgen. Tools wie strings, hexdump, xxd und binwalk können viele Informationen über die Firmware sowie das gesamte Dateisystem extrahieren.

Für eine erste Untersuchung kann Binwalk nach bekannten Signaturen suchen und unterstützte eingebettete Inhalte extrahieren:

```
binwalk -e <filename>
```

Die Ausgabedatei kann die Erweiterung `.bin`, `.rom` oder eine andere haben; die Erweiterung gibt das Format nicht an.

> [!CAUTION]
> Beachte, dass das Extrahieren von Firmware ein heikler Vorgang ist und viel Geduld erfordert. Bei unsachgemäßer Handhabung kann die Firmware beschädigt oder sogar vollständig gelöscht werden, sodass das Gerät unbrauchbar wird. Es wird empfohlen, sich vor dem Extrahieren der Firmware mit dem jeweiligen Gerät vertraut zu machen.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

In manchen Datenblättern sind die Pins des Zielgeräts mit `DI` und `DO` beschriftet: Bei einer herkömmlichen Flash-Verbindung mit einer Datenleitung wird **MOSI/COPI des Controllers mit DI** und **MISO/CIPO des Controllers mit DO** verbunden. Prüfe das Datenblatt des Zielgeräts, da Bausteine mit Dual-/Quad-I/O diese Pins in anderen Modi wiederverwenden.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Beachte, dass das PINOUT des Bus Pirate zwar Pins zum Verbinden von MOSI und MISO mit SPI angibt, einige SPIs jedoch möglicherweise ...](<../../images/image (360).png>)

Unter Windows oder Linux kannst du das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers mit einem Befehl wie diesem auszulesen:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Neuere Bus-Pirate-Dokumentation zeigt auch optionale Parameter `serialspeed` und `spispeed`. Beginne mit niedrigen Werten, wenn lange Kabel oder die Belastung in der Schaltung zu instabilen Lesevorgängen führen.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Einführung in die SPI-Schnittstelle](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-Handbuch — CH341A-SPI-Programmiergerät und Lese-/Schreiboptionen](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus-Pirate-Dokumentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
