# Analyse von Memory Dumps

{{#include ../../../banners/hacktricks-training.md}}

## Start

Beginne damit, im **pcap** nach **Malware** zu **suchen**. Verwende die in [**Malware Analysis**](../malware-analysis.md) erwähnten **Tools**.

## [Volatility](volatility-cheatsheet.md)

**Volatility ist das wichtigste Open-Source-Framework zur Analyse von Memory Dumps**. Dieses Python-Tool analysiert Dumps aus externen Quellen oder VMware-VMs und identifiziert anhand des OS-Profils des Dumps Daten wie Prozesse und Passwörter. Es ist durch Plugins erweiterbar und dadurch äußerst vielseitig für forensische Untersuchungen.

[**Hier findest du einen Cheatsheet**](volatility-cheatsheet.md)

## Mini-Dump-Absturzbericht

Wenn der Dump klein ist (nur einige KB, vielleicht einige MB), handelt es sich wahrscheinlich um einen Mini-Dump-Absturzbericht und nicht um einen Memory Dump.

![Volatility - Mini-Dump-Absturzbericht: Wenn der Dump klein ist (nur einige KB, vielleicht einige MB), handelt es sich wahrscheinlich um einen Mini-Dump-Absturzbericht und nicht um einen Memory Dump](<../../../images/image (532).png>)

Wenn Visual Studio installiert ist, kannst du diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Exception-Informationen und ausgeführte Module anzeigen:

![Volatility - Mini-Dump-Absturzbericht: Wenn Visual Studio installiert ist, kannst du diese Datei öffnen und grundlegende Informationen wie Prozessname, Architektur, Exception-Informationen und ... anzeigen](<../../../images/image (263).png>)

Du kannst außerdem die Exception laden und die dekompilierten Instructions anzeigen.

![Volatility - Mini-Dump-Absturzbericht: Du kannst außerdem die Exception laden und die dekompilierten Instructions anzeigen](<../../../images/image (142).png>)

![Volatility - Mini-Dump-Absturzbericht: Du kannst außerdem die Exception laden und die dekompilierten Instructions anzeigen](<../../../images/image (610).png>)

Visual Studio ist jedoch nicht das beste Tool für eine tiefgehende Analyse des Dumps.

Du solltest ihn mit **IDA** oder **Radare** öffnen, um ihn **eingehend** zu untersuchen.

{{#include ../../../banners/hacktricks-training.md}}
