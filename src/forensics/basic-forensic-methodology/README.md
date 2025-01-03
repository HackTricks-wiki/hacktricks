# Grundlegende forensische Methodik

{{#include ../../banners/hacktricks-training.md}}

## Erstellen und Einbinden eines Images

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **ist nicht unbedingt der erste Schritt, den Sie ausführen sollten, sobald Sie das Image haben**. Aber Sie können diese Malware-Analyse-Techniken unabhängig verwenden, wenn Sie eine Datei, ein Dateisystem-Image, ein Speicher-Image, pcap... haben, also ist es gut, **diese Aktionen im Hinterkopf zu behalten**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Überprüfung eines Images

Wenn Ihnen ein **forensisches Image** eines Geräts gegeben wird, können Sie beginnen, **die Partitionen, das verwendete Dateisystem** zu **analysieren** und potenziell **interessante Dateien** (sogar gelöschte) **wiederherzustellen**. Erfahren Sie, wie in:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Je nach den verwendeten Betriebssystemen und sogar Plattformen sollten verschiedene interessante Artefakte gesucht werden:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Tiefeninspektion spezifischer Dateitypen und Software

Wenn Sie eine sehr **verdächtige** **Datei** haben, dann können **je nach Dateityp und Software**, die sie erstellt hat, mehrere **Tricks** nützlich sein.\
Lesen Sie die folgende Seite, um einige interessante Tricks zu lernen:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ich möchte die Seite besonders erwähnen:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Speicher-Dump-Inspektion

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-Inspektion

{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensische Techniken**

Behalten Sie die mögliche Verwendung von anti-forensischen Techniken im Hinterkopf:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Bedrohungsjagd

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
