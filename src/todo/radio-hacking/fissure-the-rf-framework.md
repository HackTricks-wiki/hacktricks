# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE ist ein Open-Source-RF- und Reverse-Engineering-Framework für alle Kenntnisstufen mit Hooks für Signalerkennung und -klassifizierung, Protokollerkennung, Angriffsausführung, IQ-Manipulation, Schwachstellenanalyse, Automatisierung und AI/ML. Das Framework wurde entwickelt, um die schnelle Integration von Softwaremodulen, Radios, Protokollen, Signaldaten, Scripts, Flow Graphs, Referenzmaterial und Tools von Drittanbietern zu fördern. FISSURE ermöglicht Workflows, indem es Software an einem Ort zentralisiert und Teams eine mühelose Einarbeitung ermöglicht, während sie dieselbe bewährte Basiskonfiguration für bestimmte Linux-Distributionen verwenden.<sup>[[1]](#references)[[2]](#references)</sup>

Das Framework und die in FISSURE enthaltenen Tools dienen dazu, RF-Energie zu erkennen, Signale zu charakterisieren, Samples zu sammeln und zu analysieren, Übertragungs- oder Injection-Techniken zu entwickeln und benutzerdefinierte Payloads oder Nachrichten zu erstellen. FISSURE stellt außerdem Protokoll- und Signalinformationen zur Identifizierung, zum Packet Crafting und Fuzzing sowie Archive und Playlists für die Verkehrssimulation und das Testing bereit.<sup>[[1]](#references)[[2]](#references)</sup>

Die Python-Codebasis und die grafische Benutzeroberfläche helfen Anfängern beim Erlernen von RF- und Reverse-Engineering-Tools. Lehrkräfte können die integrierten Lektionen verwenden, während Entwickler und Forscher ihre eigenen Module und Workflows integrieren können. Aktuelle Releases unterstützen außerdem verteilte Sensorknoten, TAK-Integration, Geolocation-Workflows und rollenbasierte Apptainer-Deployments.<sup>[[1]](#references)[[3]](#references)</sup>

**Zusätzliche Informationen**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Erste Schritte

**Unterstützt**

Die aktuelle FISSURE-Version verwendet für die aktive Entwicklung den **`Python3`**-Branch mit PyQt5 und GNU Radio 3.8 oder 3.10. Der veraltete **`Python2_maint-3.7`**-Branch bleibt für ältere Betriebssysteme und Tools von Drittanbietern verfügbar, die GNU Radio 3.7 benötigen. Die früheren Branch-Namen `Python3_maint-3.8` und `Python3_maint-3.10` sind historisch; die Auswahl der GNU-Radio-Wartungsversion wird nun im `Python3`-Branch vorgenommen.<sup>[[1]](#references)[[3]](#references)</sup>

| Betriebssystem | FISSURE-Branch | Standard-GNU-Radio-Branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | eine unterstützte Linux-Version verwenden | die passende Version verwenden |

**In Bearbeitung (Beta)**

Diese Betriebssysteme befinden sich noch im Beta-Status. Sie werden entwickelt, und mehrere Funktionen fehlen derzeit noch. Elemente im Installer können mit vorhandenen Programmen in Konflikt geraten oder sich möglicherweise nicht installieren lassen, bis dieser Status aufgehoben wird.

| Betriebssystem | FISSURE-Branch | Standard-GNU-Radio-Branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Bestimmte Tools von Drittanbietern funktionieren nicht auf jedem Betriebssystem. Prüfe vor der Installation die aktuelle Dokumentation zu [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Der Submodul-Schritt lädt die von FISSURE verwendeten GNU-Radio-Out-of-Tree-Module herunter und ist bei der Installation dieser Module erforderlich. Das Installationsprogramm installiert außerdem fehlende PyQt-Abhängigkeiten, die zum Starten der Installations-GUIs benötigt werden.<sup>[[3]](#references)</sup>

Wählen Sie anschließend die Option aus, die am besten zu Ihrem Betriebssystem passt (sie sollte automatisch erkannt werden, wenn Ihr Betriebssystem einer Option entspricht).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Es wird empfohlen, FISSURE auf einem sauberen Betriebssystem zu installieren, um bestehende Konflikte zu vermeiden. Wählen Sie alle empfohlenen Kontrollkästchen aus (Schaltfläche „Default“), um Fehler beim Betrieb der verschiedenen Tools innerhalb von FISSURE zu vermeiden. Während der Installation werden mehrere Eingabeaufforderungen angezeigt, die meistens nach erhöhten Berechtigungen und Benutzernamen fragen. Wenn ein Element am Ende einen Abschnitt „Verify“ enthält, führt das Installationsprogramm den darauf folgenden Befehl aus und hebt das Kontrollkästchen je nach Auftreten von Fehlern durch den Befehl grün oder rot hervor. Aktivierte Elemente ohne einen Abschnitt „Verify“ bleiben nach der Installation schwarz.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Verwendung**

Öffnen Sie ein Terminal und geben Sie Folgendes ein:
```
fissure
```
Weitere Details zur Nutzung finden Sie im FISSURE Help-Menü.

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

Die folgende Hardware ist in unterschiedlichem Umfang in FISSURE integriert:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11-Adapter
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lessons

FISSURE enthält mehrere hilfreiche Anleitungen, um sich mit verschiedenen Technologien und Techniken vertraut zu machen. Viele davon enthalten Schritte zur Verwendung verschiedener Tools, die in FISSURE integriert sind.

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
* [Lesson12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lesson13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lesson14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] Weitere Hardwaretypen, RF-Protokolle, Signalparameter und Analyse-Tools hinzufügen
* [ ] Weitere Betriebssysteme unterstützen
* [ ] Unterrichtsmaterial zu FISSURE entwickeln (RF Attacks, Wi-Fi, GNU Radio, PyQt usw.)
* [ ] Einen Signal Conditioner, Feature Extractor und Signal Classifier mit auswählbaren AI/ML-Techniken erstellen
* [ ] Rekursive Demodulation-Mechanismen zur Erzeugung eines Bitstreams aus unbekannten Signalen implementieren
* [ ] Die zentralen FISSURE-Komponenten auf ein generisches Sensor-Node-Deployment-Schema umstellen

## Contributing

Vorschläge zur Verbesserung von FISSURE sind ausdrücklich erwünscht. Hinterlassen Sie einen Kommentar auf der [Discussions](https://github.com/ainfosec/FISSURE/discussions)-Seite oder im Discord Server, wenn Sie Gedanken zu folgenden Themen haben:

* Vorschläge für neue Funktionen und Designänderungen
* Software-Tools mit Installationsschritten
* Neue Lessons oder zusätzliches Material für bestehende Lessons
* Interessante RF-Protokolle
* Weitere Hardware- und SDR-Typen zur Integration
* IQ-Analyse-Skripte in Python
* Korrekturen und Verbesserungen der Installation

Beiträge zur Verbesserung von FISSURE sind entscheidend, um dessen Entwicklung zu beschleunigen. Jede Ihrer contributions wird sehr geschätzt. Wenn Sie durch Codeentwicklung beitragen möchten, forken Sie bitte das Repo und erstellen Sie einen Pull Request:

1. Das Projekt forken
2. Ihren Feature-Branch erstellen (`git checkout -b feature/AmazingFeature`)
3. Ihre Änderungen committen (`git commit -m 'Add some AmazingFeature'`)
4. In den Branch pushen (`git push origin feature/AmazingFeature`)
5. Einen Pull Request öffnen

Das Erstellen von [Issues](https://github.com/ainfosec/FISSURE/issues), um auf Bugs aufmerksam zu machen, ist ebenfalls willkommen.

## Collaborating

Wenden Sie sich an die Business Development-Abteilung von Assured Information Security, Inc. (AIS), um Möglichkeiten zur Zusammenarbeit an FISSURE vorzuschlagen und zu formalisieren – unabhängig davon, ob es um die Bereitstellung von Zeit für die Integration Ihrer Software, die Entwicklung von Lösungen durch die talentierten Mitarbeiter von AIS für Ihre technischen Herausforderungen oder die Integration von FISSURE in andere Plattformen/Anwendungen geht.

## License

GPL-3.0

Details zur Lizenz finden Sie in der LICENSE-Datei.

## Contact

Dem Discord Server beitreten: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Auf Twitter folgen: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Wir erkennen die Beiträge der folgenden Entwickler an und sind ihnen dankbar:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

Besonderer Dank gilt Dr. Samuel Mantravadi und Joseph Reith für ihre Beiträge zu diesem Projekt.

## References

- [1] [FISSURE - Das RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE-Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE-Dokumentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
