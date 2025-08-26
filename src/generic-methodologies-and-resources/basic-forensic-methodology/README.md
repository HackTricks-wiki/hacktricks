# Grundlegende Forensik-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Erstellen und Einbinden eines Images


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **muss nicht unbedingt der erste Schritt sein, nachdem du das Image erhalten hast**. Aber du kannst diese Malware-Analyse-Techniken unabhängig verwenden, wenn du eine Datei, ein Dateisystem-Image, Memory-Image, pcap ... hast, daher ist es gut, diese Aktionen **im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchung eines Images

Wenn dir ein **forensisches Image** eines Geräts gegeben wird, kannst du mit dem **Analysieren der Partitionen und des Dateisystems** beginnen und potenziell **interessante Dateien** (auch gelöschte) **wiederherstellen**. Erfahre wie in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Grundlegende Forensik-Methodik



## Erstellen und Einbinden eines Images


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **muss nicht unbedingt der erste Schritt sein, nachdem du das Image erhalten hast**. Aber du kannst diese Malware-Analyse-Techniken unabhängig verwenden, wenn du eine Datei, ein Dateisystem-Image, Memory-Image, pcap ... hast, daher ist es gut, diese Aktionen **im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchung eines Images

Wenn dir ein **forensisches Image** eines Geräts gegeben wird, kannst du mit dem **Analysieren der Partitionen und des Dateisystems** beginnen und potenziell **interessante Dateien** (auch gelöschte) **wiederherstellen**. Erfahre wie in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Je nach verwendetem Betriebssystem und sogar Plattform sollten unterschiedliche interessante Artefakte gesucht werden:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## Tiefergehende Untersuchung bestimmter Dateitypen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können je nach **Dateityp und der Software**, die sie erstellt hat, verschiedene **Tricks** nützlich sein.\
Lies die folgende Seite, um einige interessante Tricks zu lernen:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ich möchte die folgende Seite besonders hervorheben:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory-Dump-Analyse


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-Analyse


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-forensische Techniken**

Beachte die mögliche Verwendung von anti-forensischen Techniken:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}




## Tiefergehende Untersuchung bestimmter Dateitypen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können je nach **Dateityp und der Software**, die sie erstellt hat, verschiedene **Tricks** nützlich sein.\
Lies die folgende Seite, um einige interessante Tricks zu lernen:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ich möchte die folgende Seite besonders hervorheben:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory-Dump-Analyse


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-Analyse


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-forensische Techniken**

Beachte die mögliche Verwendung von anti-forensischen Techniken:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
