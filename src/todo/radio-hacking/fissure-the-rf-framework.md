# FISSURE - Das RF-Framework

**Frequenzunabhängige SDR-basierte Signalverständnis und Reverse Engineering**

FISSURE ist ein Open-Source-RF- und Reverse-Engineering-Framework, das für alle Fähigkeitsstufen entwickelt wurde und Schnittstellen für Signalentdeckung und -klassifizierung, Protokollentdeckung, Angriffsausführung, IQ-Manipulation, Schwachstellenanalyse, Automatisierung und KI/ML bietet. Das Framework wurde entwickelt, um die schnelle Integration von Softwaremodulen, Radios, Protokollen, Signal Daten, Skripten, Flussdiagrammen, Referenzmaterial und Drittanbieter-Tools zu fördern. FISSURE ist ein Workflow-Ermöglicher, der Software an einem Ort hält und es Teams ermöglicht, mühelos auf den gleichen bewährten Basiskonfigurationsstandard für spezifische Linux-Distributionen zuzugreifen.

Das Framework und die mit FISSURE enthaltenen Tools sind darauf ausgelegt, die Präsenz von RF-Energie zu erkennen, die Eigenschaften eines Signals zu verstehen, Proben zu sammeln und zu analysieren, Übertragungs- und/oder Injektionstechniken zu entwickeln und benutzerdefinierte Payloads oder Nachrichten zu erstellen. FISSURE enthält eine wachsende Bibliothek von Protokoll- und Signalinformationen, um bei der Identifizierung, Paketgestaltung und Fuzzing zu helfen. Online-Archivfunktionen existieren, um Signaldateien herunterzuladen und Playlists zu erstellen, um den Verkehr zu simulieren und Systeme zu testen.

Die benutzerfreundliche Python-Codebasis und Benutzeroberfläche ermöglicht es Anfängern, schnell über beliebte Tools und Techniken im Zusammenhang mit RF und Reverse Engineering zu lernen. Pädagogen in der Cybersicherheit und Ingenieurwissenschaften können das integrierte Material nutzen oder das Framework verwenden, um ihre eigenen realen Anwendungen zu demonstrieren. Entwickler und Forscher können FISSURE für ihre täglichen Aufgaben oder zur Präsentation ihrer innovativen Lösungen einem breiteren Publikum nutzen. Mit dem wachsenden Bewusstsein und der Nutzung von FISSURE in der Community werden auch die Möglichkeiten und der Umfang der Technologie, die es umfasst, zunehmen.

**Zusätzliche Informationen**

* [AIS-Seite](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22-Folien](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22-Papier](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22-Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat-Transkript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Erste Schritte

**Unterstützt**

Es gibt drei Zweige innerhalb von FISSURE, um die Dateinavigation zu erleichtern und den Code-Redundanz zu reduzieren. Der Branch Python2\_maint-3.7 enthält eine Codebasis, die auf Python2, PyQt4 und GNU Radio 3.7 basiert; der Branch Python3\_maint-3.8 basiert auf Python3, PyQt5 und GNU Radio 3.8; und der Branch Python3\_maint-3.10 basiert auf Python3, PyQt5 und GNU Radio 3.10.

|   Betriebssystem   |   FISSURE-Zweig   |
| :-----------------: | :---------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In Arbeit (Beta)**

Diese Betriebssysteme befinden sich noch im Beta-Status. Sie sind in der Entwicklung und mehrere Funktionen sind bekanntlich nicht verfügbar. Elemente im Installer könnten mit vorhandenen Programmen in Konflikt stehen oder die Installation könnte fehlschlagen, bis der Status entfernt wird.

|     Betriebssystem     |    FISSURE-Zweig   |
| :---------------------: | :----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Hinweis: Bestimmte Software-Tools funktionieren nicht für jedes Betriebssystem. Siehe [Software und Konflikte](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dies installiert die erforderlichen PyQt-Softwareabhängigkeiten, die benötigt werden, um die Installations-GUIs zu starten, falls sie nicht gefunden werden.

Wählen Sie als Nächstes die Option aus, die am besten zu Ihrem Betriebssystem passt (sollte automatisch erkannt werden, wenn Ihr OS mit einer Option übereinstimmt).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Es wird empfohlen, FISSURE auf einem sauberen Betriebssystem zu installieren, um bestehende Konflikte zu vermeiden. Wählen Sie alle empfohlenen Kontrollkästchen (Standardtaste) aus, um Fehler beim Betrieb der verschiedenen Tools innerhalb von FISSURE zu vermeiden. Es wird während der Installation mehrere Aufforderungen geben, die hauptsächlich nach erhöhten Berechtigungen und Benutzernamen fragen. Wenn ein Element am Ende einen Abschnitt "Überprüfen" enthält, führt der Installer den folgenden Befehl aus und hebt das Kontrollkästchen grün oder rot hervor, je nachdem, ob durch den Befehl Fehler erzeugt werden. Überprüfte Elemente ohne einen Abschnitt "Überprüfen" bleiben nach der Installation schwarz.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Verwendung**

Öffnen Sie ein Terminal und geben Sie ein:
```
fissure
```
Beziehen Sie sich auf das FISSURE-Hilfemenü für weitere Details zur Verwendung.

## Details

**Komponenten**

* Dashboard
* Central Hub (HIPRFISR)
* Zielsignalidentifikation (TSI)
* Protokollentdeckung (PD)
* Flussdiagramm & Skriptausführer (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Fähigkeiten**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Die folgende Liste umfasst "unterstützte" Hardware mit unterschiedlichen Integrationsgraden:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapter
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lektionen

FISSURE enthält mehrere hilfreiche Anleitungen, um sich mit verschiedenen Technologien und Techniken vertraut zu machen. Viele beinhalten Schritte zur Verwendung verschiedener Werkzeuge, die in FISSURE integriert sind.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Fügen Sie weitere Hardwaretypen, RF-Protokolle, Signalparameter, Analysetools hinzu
* [ ] Unterstützen Sie weitere Betriebssysteme
* [ ] Entwickeln Sie Unterrichtsmaterial zu FISSURE (RF-Angriffe, Wi-Fi, GNU Radio, PyQt usw.)
* [ ] Erstellen Sie einen Signalaufbereiter, Merkmalsextraktor und Signalklassifizierer mit wählbaren AI/ML-Techniken
* [ ] Implementieren Sie rekursive Demodulationsmechanismen zur Erzeugung eines Bitstroms aus unbekannten Signalen
* [ ] Überführen Sie die Hauptkomponenten von FISSURE in ein generisches Sensor-Knoten-Bereitstellungsschema

## Mitwirken

Vorschläge zur Verbesserung von FISSURE sind ausdrücklich erwünscht. Hinterlassen Sie einen Kommentar auf der [Discussions](https://github.com/ainfosec/FISSURE/discussions)-Seite oder im Discord-Server, wenn Sie Gedanken zu Folgendem haben:

* Vorschläge für neue Funktionen und Designänderungen
* Softwaretools mit Installationsschritten
* Neue Lektionen oder zusätzliches Material für bestehende Lektionen
* Interessante RF-Protokolle
* Weitere Hardware- und SDR-Typen zur Integration
* IQ-Analyse-Skripte in Python
* Installationskorrekturen und -verbesserungen

Beiträge zur Verbesserung von FISSURE sind entscheidend, um die Entwicklung zu beschleunigen. Alle Beiträge, die Sie leisten, werden sehr geschätzt. Wenn Sie durch die Entwicklung von Code beitragen möchten, forken Sie das Repository und erstellen Sie eine Pull-Anfrage:

1. Forken Sie das Projekt
2. Erstellen Sie Ihren Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Committen Sie Ihre Änderungen (`git commit -m 'Add some AmazingFeature'`)
4. Pushen Sie zum Branch (`git push origin feature/AmazingFeature`)
5. Öffnen Sie eine Pull-Anfrage

Das Erstellen von [Issues](https://github.com/ainfosec/FISSURE/issues), um auf Fehler aufmerksam zu machen, ist ebenfalls willkommen.

## Zusammenarbeit

Kontaktieren Sie Assured Information Security, Inc. (AIS) Business Development, um Vorschläge und formelle Möglichkeiten zur Zusammenarbeit mit FISSURE zu unterbreiten – sei es durch die Zuweisung von Zeit zur Integration Ihrer Software, durch die talentierten Mitarbeiter von AIS, die Lösungen für Ihre technischen Herausforderungen entwickeln, oder durch die Integration von FISSURE in andere Plattformen/Anwendungen.

## Lizenz

GPL-3.0

Für Lizenzdetails siehe die LICENSE-Datei.

## Kontakt

Treten Sie dem Discord-Server bei: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Folgen Sie uns auf Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Wir danken diesen Entwicklern:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Danksagungen

Besonderer Dank geht an Dr. Samuel Mantravadi und Joseph Reith für ihre Beiträge zu diesem Projekt.
