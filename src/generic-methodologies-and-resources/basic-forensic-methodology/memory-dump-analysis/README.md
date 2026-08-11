# Analyse von Memory Dumps

{{#include ../../../banners/hacktricks-training.md}}

## Start

Beginne damit, im pcap nach **Malware** zu **suchen**. Verwende die in [**Malware Analysis**](../malware-analysis.md) genannten **Tools**.

## [Volatility](volatility-cheatsheet.md)

**Volatility ist ein Open-Source-Framework zur Analyse von Memory Dumps**. Dieses Python-Tool analysiert Dumps aus externen Quellen oder VMware-VMs und identifiziert anhand des Betriebssystemprofils des Dumps Daten wie Prozesse und Passwörter. Es ist durch Plugins erweiterbar und dadurch äußerst vielseitig für forensische Untersuchungen.<sup>[[1]](#references)[[2]](#references)</sup>

[**Hier findest du einen Cheatsheet**](volatility-cheatsheet.md)

## Mini-Dump-Absturzbericht

Wenn der Dump klein ist (nur einige KB, vielleicht wenige MB), handelt es sich möglicherweise um einen Mini-Dump-Absturzbericht und nicht um einen vollständigen Memory Dump.<sup>[[3]](#references)</sup>

![Volatility - Mini-Dump-Absturzbericht: Eine kleine Dump-Datei, die als Mini-DuMP-Absturzbericht identifiziert wurde](<../../../images/image (532).png>)

Wenn Visual Studio installiert ist, kannst du diese Datei öffnen, um grundlegende Informationen wie den Prozessnamen, die Architektur, Ausnahmeinformationen und geladene Module anzuzeigen:<sup>[[4]](#references)</sup>

![Volatility - Mini-Dump-Absturzbericht: Wenn Visual Studio installiert ist, kannst du diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Ausnahmeinformationen und ... abrufen](<../../../images/image (263).png>)

Du kannst auch die Ausnahme untersuchen und die Disassembly des Moduls anzeigen.<sup>[[4]](#references)</sup>

![Visual-Studio-Aktionsbereich für Minidumps mit Optionen zum nativen Debuggen und Festlegen von Symbolpfaden](<../../../images/image (142).png>)

![Visual-Studio-Disassembly von Anweisungen aus der Minidump-Ausnahme](<../../../images/image (610).png>)

Visual Studio ist jedoch nicht das beste Tool für eine gründliche Analyse des Dumps.

Du solltest ihn mit **IDA** oder **Radare** öffnen, um ihn **eingehend** zu untersuchen.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump-Dateien](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Dump-Dateien im Visual-Studio-Debugger verwenden](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
