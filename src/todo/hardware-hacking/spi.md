# SPI

{{#include ../../banners/hacktricks-training.md}}

## Grundinformationen

SPI (Serial Peripheral Interface) ist ein synchrones serielles Kommunikationsprotokoll, das in eingebetteten Systemen für die Kurzstreckenkommunikation zwischen ICs (Integrierte Schaltungen) verwendet wird. Das SPI-Kommunikationsprotokoll nutzt die Master-Slave-Architektur, die durch das Takt- und Chip-Auswahl-Signal orchestriert wird. Eine Master-Slave-Architektur besteht aus einem Master (in der Regel ein Mikroprozessor), der externe Peripheriegeräte wie EEPROM, Sensoren, Steuergeräte usw. verwaltet, die als Slaves betrachtet werden.

Mehrere Slaves können mit einem Master verbunden werden, aber Slaves können nicht miteinander kommunizieren. Slaves werden durch zwei Pins, Takt und Chip-Auswahl, verwaltet. Da SPI ein synchrones Kommunikationsprotokoll ist, folgen die Eingangs- und Ausgangspins den Taktsignalen. Die Chip-Auswahl wird vom Master verwendet, um einen Slave auszuwählen und mit ihm zu interagieren. Wenn die Chip-Auswahl hoch ist, ist das Slave-Gerät nicht ausgewählt, während es bei niedrigem Pegel ausgewählt ist und der Master mit dem Slave interagiert.

Die MOSI (Master Out, Slave In) und MISO (Master In, Slave Out) sind verantwortlich für das Senden und Empfangen von Daten. Daten werden über den MOSI-Pin an das Slave-Gerät gesendet, während die Chip-Auswahl niedrig gehalten wird. Die Eingabedaten enthalten Anweisungen, Speicheradressen oder Daten gemäß dem Datenblatt des Slave-Geräteanbieters. Bei einer gültigen Eingabe ist der MISO-Pin verantwortlich für die Übertragung von Daten an den Master. Die Ausgabedaten werden genau im nächsten Taktzyklus gesendet, nachdem die Eingabe endet. Der MISO-Pin überträgt Daten, bis die Daten vollständig übertragen sind oder der Master den Chip-Auswahl-Pin hochsetzt (in diesem Fall würde der Slave die Übertragung stoppen und der Master würde nach diesem Taktzyklus nicht mehr hören).

## Firmware von EEPROMs dumpen

Das Dumpen von Firmware kann nützlich sein, um die Firmware zu analysieren und Schwachstellen darin zu finden. Oftmals ist die Firmware nicht im Internet verfügbar oder irrelevant aufgrund von Variationen wie Modellnummer, Version usw. Daher kann es hilfreich sein, die Firmware direkt vom physischen Gerät zu extrahieren, um spezifisch nach Bedrohungen zu suchen.

Der Zugriff auf die serielle Konsole kann hilfreich sein, aber oft ist es so, dass die Dateien schreibgeschützt sind. Dies schränkt die Analyse aus verschiedenen Gründen ein. Zum Beispiel könnten Werkzeuge, die erforderlich sind, um Pakete zu senden und zu empfangen, nicht in der Firmware vorhanden sein. Daher ist es nicht machbar, die Binärdateien zu extrahieren, um sie zurückzuentwickeln. Daher kann es sehr hilfreich sein, die gesamte Firmware auf dem System zu dumpen und die Binärdateien zur Analyse zu extrahieren.

Außerdem kann das Dumpen der Firmware während des Red Teamings und beim physischen Zugriff auf Geräte helfen, die Dateien zu modifizieren oder bösartige Dateien einzuschleusen und sie dann in den Speicher zurückzuschreiben, was hilfreich sein könnte, um ein Hintertür in das Gerät einzupflanzen. Daher gibt es zahlreiche Möglichkeiten, die durch das Dumpen von Firmware freigeschaltet werden können.

### CH341A EEPROM-Programmierer und -Leser

Dieses Gerät ist ein kostengünstiges Werkzeug zum Dumpen von Firmwares von EEPROMs und auch zum erneuten Flashen mit Firmware-Dateien. Dies war eine beliebte Wahl für die Arbeit mit Computer-BIOS-Chips (die nur EEPROMs sind). Dieses Gerät wird über USB angeschlossen und benötigt minimale Werkzeuge, um zu starten. Außerdem erledigt es die Aufgabe in der Regel schnell, sodass es auch beim physischen Zugriff auf Geräte hilfreich sein kann.

![drawing](../../images/board_image_ch341a.jpg)

Schließen Sie den EEPROM-Speicher an den CH341a-Programmierer an und stecken Sie das Gerät in den Computer. Falls das Gerät nicht erkannt wird, versuchen Sie, Treiber auf dem Computer zu installieren. Stellen Sie außerdem sicher, dass der EEPROM in der richtigen Ausrichtung angeschlossen ist (in der Regel den VCC-Pin in umgekehrter Ausrichtung zum USB-Anschluss platzieren), da die Software sonst den Chip nicht erkennen kann. Verweisen Sie bei Bedarf auf das Diagramm:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Verwenden Sie schließlich Software wie flashrom, G-Flash (GUI) usw. zum Dumpen der Firmware. G-Flash ist ein minimales GUI-Tool, das schnell ist und den EEPROM automatisch erkennt. Dies kann hilfreich sein, wenn die Firmware schnell extrahiert werden muss, ohne viel mit der Dokumentation herumzuprobieren.

![drawing](../../images/connected_status_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse der Binärdateien durchgeführt werden. Werkzeuge wie strings, hexdump, xxd, binwalk usw. können verwendet werden, um viele Informationen über die Firmware sowie das gesamte Dateisystem zu extrahieren.

Um die Inhalte aus der Firmware zu extrahieren, kann binwalk verwendet werden. Binwalk analysiert nach Hex-Signaturen und identifiziert die Dateien in der Binärdatei und ist in der Lage, sie zu extrahieren.
```
binwalk -e <filename>
```
Die Dateien können .bin oder .rom sein, je nach den verwendeten Tools und Konfigurationen.

> [!CAUTION]
> Beachten Sie, dass die Extraktion von Firmware ein heikler Prozess ist und viel Geduld erfordert. Jede unsachgemäße Handhabung kann die Firmware potenziell beschädigen oder sogar vollständig löschen und das Gerät unbrauchbar machen. Es wird empfohlen, das spezifische Gerät zu studieren, bevor Sie versuchen, die Firmware zu extrahieren.

### Bus Pirate + flashrom

![](<../../images/image (910).png>)

Beachten Sie, dass selbst wenn das PINOUT des Pirate Bus Pins für **MOSI** und **MISO** angibt, um sich mit SPI zu verbinden, einige SPIs Pins als DI und DO angeben können. **MOSI -> DI, MISO -> DO**

![](<../../images/image (360).png>)

In Windows oder Linux können Sie das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flashspeichers mit einem Befehl wie diesem zu dumpen:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
