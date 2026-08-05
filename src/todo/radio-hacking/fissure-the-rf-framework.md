# FISSURE - Das RF-Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE ist ein Open-Source-RF- und Reverse-Engineering-Framework, das für alle Erfahrungsstufen entwickelt wurde und Schnittstellen für Signalerkennung und -klassifizierung, Protokollerkennung, Angriffsausführung, IQ-Manipulation, Schwachstellenanalyse, Automatisierung und AI/ML bietet. Das Framework wurde entwickelt, um die schnelle Integration von Softwaremodulen, Funkgeräten, Protokollen, Signaldaten, Skripten, Flowgraphs, Referenzmaterial und Tools von Drittanbietern zu fördern. FISSURE ermöglicht Workflows, indem es Software an einem Ort bündelt und Teams erlaubt, sich mühelos einzuarbeiten und dieselbe bewährte Basiskonfiguration für bestimmte Linux-Distributionen gemeinsam zu nutzen.<sup>[[1]](#references)[[2]](#references)</sup>

Das Framework und die in FISSURE enthaltenen Tools sind darauf ausgelegt, das Vorhandensein von RF-Energie zu erkennen, die Eigenschaften eines Signals zu verstehen, Samples zu sammeln und zu analysieren, Übertragungs- und/oder Injection-Techniken zu entwickeln sowie benutzerdefinierte Payloads oder Nachrichten zu erstellen. FISSURE enthält eine wachsende Bibliothek mit Informationen zu Protokollen und Signalen, die bei der Identifizierung, dem Packet Crafting und dem Fuzzing unterstützt. Online-Archivfunktionen ermöglichen das Herunterladen von Signalfiles und das Erstellen von Playlists, um Datenverkehr zu simulieren und Systeme zu testen.

Die benutzerfreundliche Python-Codebasis und die Benutzeroberfläche ermöglichen Anfängern, sich schnell mit beliebten Tools und Techniken aus den Bereichen RF und Reverse Engineering vertraut zu machen. Lehrkräfte in den Bereichen Cybersecurity und Engineering können das integrierte Material nutzen oder das Framework einsetzen, um eigene Anwendungen aus der Praxis zu demonstrieren. Entwickler und Forscher können FISSURE für ihre täglichen Aufgaben verwenden oder ihre fortschrittlichen Lösungen einem größeren Publikum zugänglich machen. Mit zunehmender Bekanntheit und Nutzung von FISSURE in der Community werden auch der Funktionsumfang und die Bandbreite der abgedeckten Technologien wachsen.

**Zusätzliche Informationen**

* [AIS-Seite](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22-Folien](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22-Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22-Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkript des Hack Chats](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Erste Schritte

**Unterstützt**

FISSURE verfügt über drei Branches, um die Dateinavigation zu erleichtern und Code-Redundanz zu reduzieren. Der Branch Python2\_maint-3.7 enthält eine auf Python2, PyQt4 und GNU Radio 3.7 basierende Codebasis; der Branch Python3\_maint-3.8 basiert auf Python3, PyQt5 und GNU Radio 3.8; und der Branch Python3\_maint-3.10 basiert auf Python3, PyQt5 und GNU Radio 3.10.

|   Betriebssystem   |   FISSURE-Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In Entwicklung (Beta)**

Diese Betriebssysteme befinden sich noch im Beta-Status. Sie werden derzeit entwickelt, und mehrere Funktionen fehlen bekanntermaßen. Elemente im Installer können mit vorhandenen Programmen in Konflikt geraten oder nicht installiert werden, solange dieser Status besteht.

|     Betriebssystem     |    FISSURE-Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Hinweis: Bestimmte Softwaretools funktionieren nicht unter jedem Betriebssystem. Siehe [Software und Konflikte](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dies installiert die für den Start der Installations-GUIs erforderlichen PyQt-Softwareabhängigkeiten, sofern diese nicht gefunden werden.

Wählen Sie anschließend die Option aus, die am besten zu Ihrem Betriebssystem passt (sollte automatisch erkannt werden, wenn Ihr Betriebssystem einer Option entspricht).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Es wird empfohlen, FISSURE auf einem sauberen Betriebssystem zu installieren, um bestehende Konflikte zu vermeiden. Wählen Sie alle empfohlenen Kontrollkästchen aus (Schaltfläche „Default“), um Fehler bei der Verwendung der verschiedenen Tools innerhalb von FISSURE zu vermeiden. Während der Installation werden mehrere Eingabeaufforderungen angezeigt, die meist nach erhöhten Berechtigungen und Benutzernamen fragen. Wenn ein Element am Ende einen Abschnitt „Verify“ enthält, führt der Installer den darauf folgenden Befehl aus und markiert das Kontrollkästchen je nach Auftreten von Fehlern durch den Befehl grün oder rot. Aktivierte Elemente ohne Abschnitt „Verify“ bleiben nach der Installation schwarz.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Verwendung**

Öffnen Sie ein Terminal und geben Sie Folgendes ein:
```
fissure
```
Weitere Details zur Nutzung finden Sie im FISSURE-Hilfemenü.

## Details

**Komponenten**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Funktionen**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Die folgende Liste enthält „unterstützte“ Hardware mit unterschiedlichem Integrationsgrad:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11-Adapter
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lektionen

FISSURE enthält mehrere hilfreiche Anleitungen, um mit verschiedenen Technologien und Techniken vertraut zu werden. Viele davon enthalten Schritte zur Verwendung verschiedener in FISSURE integrierter Tools.

* [Lektion 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lektion 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lektion 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lektion 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lektion 5: Radiosonden-Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lektion 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lektion 7: Datentypen](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lektion 8: Benutzerdefinierte GNU-Radio-Blöcke](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lektion 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lektion 10: Amateurfunkprüfungen](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lektion 11: Wi-Fi-Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Weitere Hardwaretypen, RF-Protokolle, Signalparameter und Analysetools hinzufügen
* [ ] Weitere Betriebssysteme unterstützen
* [ ] Unterrichtsmaterial zu FISSURE entwickeln (RF Attacks, Wi-Fi, GNU Radio, PyQt usw.)
* [ ] Einen Signal-Conditioner, Feature-Extractor und Signal-Classifier mit auswählbaren AI/ML-Techniken erstellen
* [ ] Rekursive Demodulationsmechanismen zur Erzeugung eines Bitstreams aus unbekannten Signalen implementieren
* [ ] Die zentralen FISSURE-Komponenten auf ein generisches Bereitstellungsschema für Sensorknoten umstellen

## Mitwirken

Vorschläge zur Verbesserung von FISSURE sind ausdrücklich willkommen. Hinterlassen Sie einen Kommentar auf der Seite [Discussions](https://github.com/ainfosec/FISSURE/discussions) oder im Discord Server, wenn Sie Gedanken zu folgenden Themen haben:

* Vorschläge für neue Funktionen und Designänderungen
* Softwaretools mit Installationsschritten
* Neue Lektionen oder zusätzliches Material für bestehende Lektionen
* Interessante RF-Protokolle
* Weitere Hardware- und SDR-Typen zur Integration
* IQ-Analyseskripte in Python
* Korrekturen und Verbesserungen der Installation

Beiträge zur Verbesserung von FISSURE sind entscheidend, um die Entwicklung zu beschleunigen. Jede Ihrer Beiträge wird sehr geschätzt. Wenn Sie durch Codeentwicklung beitragen möchten, forken Sie das Repo und erstellen Sie einen Pull Request:

1. Das Projekt forken
2. Ihren Feature-Branch erstellen (`git checkout -b feature/AmazingFeature`)
3. Ihre Änderungen committen (`git commit -m 'Add some AmazingFeature'`)
4. In den Branch pushen (`git push origin feature/AmazingFeature`)
5. Einen Pull Request öffnen

Das Erstellen von [Issues](https://github.com/ainfosec/FISSURE/issues), um auf Bugs aufmerksam zu machen, ist ebenfalls willkommen.

## Zusammenarbeit

Kontaktieren Sie die Business Development-Abteilung von Assured Information Security, Inc. (AIS), um Möglichkeiten zur Zusammenarbeit an FISSURE vorzuschlagen und zu formalisieren – sei es durch die Bereitstellung von Zeit für die Integration Ihrer Software, durch die Entwicklung von Lösungen durch die talentierten Mitarbeiter von AIS für Ihre technischen Herausforderungen oder durch die Integration von FISSURE in andere Plattformen/Anwendungen.

## Lizenz

GPL-3.0

Details zur Lizenz finden Sie in der Datei LICENSE.

## Kontakt

Treten Sie dem Discord Server bei: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Folgen Sie uns auf Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Wir würdigen diese Entwickler und sind ihnen dankbar:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Danksagungen

Besonderer Dank gilt Dr. Samuel Mantravadi und Joseph Reith für ihre Beiträge zu diesem Projekt.

## Referenzen

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
