# Speicherabbildanalyse

{{#include ../../../banners/hacktricks-training.md}}

## Start

Beginnen Sie mit der **Suche** nach **Malware** im pcap. Verwenden Sie die in [**Malware-Analyse**](../malware-analysis.md) genannten **Werkzeuge**.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility ist das Haupt-Open-Source-Framework für die Analyse von Speicherabbildern**. Dieses Python-Tool analysiert Dumps von externen Quellen oder VMware-VMs und identifiziert Daten wie Prozesse und Passwörter basierend auf dem OS-Profil des Dumps. Es ist mit Plugins erweiterbar, was es äußerst vielseitig für forensische Untersuchungen macht.

**[Hier finden Sie ein Cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Mini-Dump-Absturzbericht

Wenn der Dump klein ist (nur einige KB, vielleicht ein paar MB), dann handelt es sich wahrscheinlich um einen Mini-Dump-Absturzbericht und nicht um ein Speicherabbild.

![](<../../../images/image (216).png>)

Wenn Sie Visual Studio installiert haben, können Sie diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Ausnahmeinformationen und ausgeführte Module binden:

![](<../../../images/image (217).png>)

Sie können auch die Ausnahme laden und die dekompilierten Anweisungen ansehen

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

Wie auch immer, Visual Studio ist nicht das beste Werkzeug, um eine Analyse der Tiefe des Dumps durchzuführen.

Sie sollten es **öffnen**, um es mit **IDA** oder **Radare** **gründlich** zu inspizieren.

​

{{#include ../../../banners/hacktricks-training.md}}
