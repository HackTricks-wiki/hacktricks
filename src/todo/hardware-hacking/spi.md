# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchrones serielles Kommunikationsprotokoll, das in eingebetteten Systemen für die Kommunikation über kurze Distanzen zwischen ICs (Integrated Circuits) verwendet wird. Das SPI-Kommunikationsprotokoll nutzt eine Master-Slave-Architektur, die durch das Clock- und Chip-Select-Signal gesteuert wird. Eine Master-Slave-Architektur besteht aus einem Master (normalerweise einem Mikroprozessor), der externe Peripheriegeräte wie EEPROMs, Sensoren, Steuergeräte usw. verwaltet, die als Slaves betrachtet werden.

Mehrere Slaves können mit einem Master verbunden werden, aber Slaves können nicht miteinander kommunizieren. Slaves werden über zwei Pins verwaltet: Clock und Chip Select. Da SPI ein synchrones Kommunikationsprotokoll ist, folgen die Eingangs- und Ausgangspins den Clock-Signalen. Chip Select wird vom Master verwendet, um einen Slave auszuwählen und mit ihm zu interagieren. Wenn Chip Select high ist, ist das Slave-Gerät nicht ausgewählt, während der Chip bei einem Low-Signal ausgewählt ist und der Master mit dem Slave interagiert.

MOSI (Master Out, Slave In) und MISO (Master In, Slave Out) sind für das Senden und Empfangen von Daten zuständig. Daten werden über den MOSI-Pin an das Slave-Gerät gesendet, während Chip Select auf Low gehalten wird. Die Eingangsdaten enthalten gemäß dem Datenblatt des Slave-Geräteherstellers Anweisungen, Speicheradressen oder Daten. Bei einer gültigen Eingabe ist der MISO-Pin für die Übertragung von Daten an den Master zuständig. Die Ausgabedaten werden genau im nächsten Clock-Zyklus nach dem Ende der Eingabe gesendet. Die MISO-Pins übertragen Daten, bis die Daten vollständig übertragen wurden oder der Master den Chip-Select-Pin auf High setzt (in diesem Fall würde der Slave die Übertragung stoppen und der Master würde nach diesem Clock-Zyklus nicht mehr zuhören).

## Firmware von EEPROMs dumpen

Das Dumpen von Firmware kann nützlich sein, um die Firmware zu analysieren und Schwachstellen darin zu finden. Häufig ist die Firmware nicht im Internet verfügbar oder aufgrund von Faktoren wie Modellnummer, Version usw. irrelevant. Daher kann das direkte Extrahieren der Firmware vom physischen Gerät hilfreich sein, um bei der Suche nach Bedrohungen spezifisch vorzugehen.

Eine serielle Konsole zu erhalten, kann hilfreich sein, aber häufig sind die Dateien schreibgeschützt. Dies schränkt die Analyse aus verschiedenen Gründen ein. Beispielsweise wären die Tools, die zum Senden und Empfangen von Paketen erforderlich sind, in der Firmware nicht vorhanden. Daher ist das Extrahieren der Binaries für das Reverse Engineering nicht praktikabel. Die vollständige Firmware auf dem System zu dumpen und die Binaries für die Analyse zu extrahieren, kann daher sehr hilfreich sein.

Außerdem kann das Dumpen der Firmware während Red Teaming und beim Erlangen physischen Zugriffs auf Geräte dabei helfen, die Dateien zu modifizieren oder schädliche Dateien einzuschleusen und sie anschließend erneut in den Speicher zu flashen. Dies könnte hilfreich sein, um eine Backdoor in das Gerät einzuschleusen. Daher können durch das Dumpen von Firmware zahlreiche Möglichkeiten eröffnet werden.

### CH341A EEPROM Programmer und Reader

Dieses Gerät ist ein kostengünstiges Tool zum Dumpen von Firmware aus EEPROMs und zum erneuten Flashen mit Firmware-Dateien. Es ist eine beliebte Wahl für die Arbeit mit Computer-BIOS-Chips (bei denen es sich lediglich um EEPROMs handelt). Das Gerät wird über USB angeschlossen und benötigt nur minimale Tools, um loszulegen. Außerdem erledigt es die Aufgabe in der Regel schnell, sodass es auch beim physischen Zugriff auf Geräte hilfreich sein kann.

![drawing](../../images/board_image_ch341a.jpg)

Verbinde den EEPROM-Speicher mit dem CH341A Programmer und schließe das Gerät an den Computer an. Falls das Gerät nicht erkannt wird, versuche, Treiber auf dem Computer zu installieren. Stelle außerdem sicher, dass der EEPROM richtig ausgerichtet angeschlossen ist (normalerweise wird der VCC-Pin entgegengesetzt zum USB-Anschluss platziert), da die Software den Chip andernfalls nicht erkennen kann. Siehe bei Bedarf das Diagramm:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Verwende schließlich Software wie flashrom, G-Flash (GUI) usw. zum Dumpen der Firmware. G-Flash ist ein minimalistisches GUI-Tool, das schnell ist und den EEPROM automatisch erkennt. Dies kann hilfreich sein, wenn die Firmware schnell und ohne umfangreiche Auseinandersetzung mit der Dokumentation extrahiert werden muss.

![drawing](../../images/connected_status_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse an den Binärdateien durchgeführt werden. Tools wie strings, hexdump, xxd, binwalk usw. können verwendet werden, um viele Informationen über die Firmware sowie das gesamte Dateisystem zu extrahieren.

Um die Inhalte aus der Firmware zu extrahieren, kann binwalk verwendet werden. Binwalk analysiert Hex-Signaturen, identifiziert die Dateien in der Binärdatei und kann sie extrahieren.
```
binwalk -e <filename>
```
The kann je nach verwendeten Tools und Konfigurationen `.bin` oder `.rom` sein.

> [!CAUTION]
> Beachte, dass die Firmware-Extraktion ein heikler Prozess ist und viel Geduld erfordert. Jede unsachgemäße Handhabung kann die Firmware möglicherweise beschädigen oder sie sogar vollständig löschen und das Gerät unbrauchbar machen. Es wird empfohlen, das spezifische Gerät zu untersuchen, bevor versucht wird, die Firmware zu extrahieren.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Beachte, dass das PINOUT des Bus Pirate zwar Pins für **MOSI** und **MISO** zum Anschluss an SPI angibt, einige SPIs die Pins jedoch als DI und DO bezeichnen können. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Beachte, dass das PINOUT des Bus Pirate zwar Pins für MOSI und MISO zum Anschluss an SPI angibt, einige SPIs die Pins jedoch als DI und DO bezeichnen können...](<../../images/image (360).png>)

Unter Windows oder Linux kannst du das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers zu dumpen, indem du etwa Folgendes ausführst:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
