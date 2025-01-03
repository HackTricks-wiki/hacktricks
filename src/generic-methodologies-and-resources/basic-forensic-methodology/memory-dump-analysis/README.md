# Speicherabbildanalyse

{{#include ../../../banners/hacktricks-training.md}}

## Start

Beginnen Sie mit der **Suche** nach **Malware** im pcap. Verwenden Sie die **Werkzeuge**, die in [**Malware-Analyse**](../malware-analysis.md) erwähnt werden.

## [Volatility](volatility-cheatsheet.md)

**Volatility ist das Haupt-Open-Source-Framework für die Analyse von Speicherabbildern**. Dieses Python-Tool analysiert Dumps von externen Quellen oder VMware-VMs und identifiziert Daten wie Prozesse und Passwörter basierend auf dem OS-Profil des Dumps. Es ist mit Plugins erweiterbar, was es sehr vielseitig für forensische Untersuchungen macht.

[**Hier finden Sie ein Cheatsheet**](volatility-cheatsheet.md)

## Mini-Dump-Absturzbericht

Wenn der Dump klein ist (nur einige KB, vielleicht ein paar MB), dann handelt es sich wahrscheinlich um einen Mini-Dump-Absturzbericht und nicht um ein Speicherabbild.

![](<../../../images/image (532).png>)

Wenn Sie Visual Studio installiert haben, können Sie diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Ausnahmeinformationen und ausgeführte Module binden:

![](<../../../images/image (263).png>)

Sie können auch die Ausnahme laden und die dekompilierten Anweisungen ansehen

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

Jedenfalls ist Visual Studio nicht das beste Werkzeug, um eine tiefgehende Analyse des Dumps durchzuführen.

Sie sollten es **öffnen** und mit **IDA** oder **Radare** **gründlich** untersuchen.

​

{{#include ../../../banners/hacktricks-training.md}}
