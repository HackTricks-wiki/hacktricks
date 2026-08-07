# Grundlegende forensische Methodik

{{#include ../../banners/hacktricks-training.md}}

## Erstellen und Mounten eines Images


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **ist nicht unbedingt der erste Schritt, der nach dem Erhalt des Images durchgeführt werden muss**. Diese Malware-Analyse-Techniken können jedoch unabhängig davon verwendet werden, ob eine Datei, ein Datei-System-Image, ein Speicherabbild, ein pcap ... vorliegt. Daher ist es sinnvoll, **diese Maßnahmen im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchung eines Images

Wenn dir ein **forensisches Image** eines Geräts vorliegt, kannst du mit der **Analyse der Partitionen und des verwendeten Datei-Systems** sowie der **Wiederherstellung** potenziell **interessanter Dateien** beginnen, einschließlich gelöschter Dateien. Erfahre hier, wie:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Abhängig von den verwendeten Betriebssystemen und sogar der Plattform sollte nach unterschiedlichen interessanten Artefakten gesucht werden:


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

## Tiefgehende Untersuchung spezifischer Datei-Typen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können abhängig vom **Datei-Typ und der Software**, mit der sie erstellt wurde, verschiedene **Tricks** nützlich sein.\
Lies die folgende Seite, um einige interessante Tricks kennenzulernen:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ich möchte besonders auf folgende Seite hinweisen:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Untersuchung von Speicherabbildern


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Untersuchung von Pcaps


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic-Techniken**

Behalte den möglichen Einsatz von Anti-Forensic-Techniken im Hinterkopf:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
