# Grundlegende forensische Methodik

## Erstellen und Mounten eines Images


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **ist nicht unbedingt der erste Schritt, den man nach dem Erhalt des Images durchführen muss**. Diese Malware-Analyse-Techniken können jedoch unabhängig davon eingesetzt werden, wenn eine Datei, ein Dateisystem-Image, ein Speicherabbild, ein pcap usw. vorliegt. Daher ist es sinnvoll, **diese Maßnahmen im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchung eines Images

Wenn dir ein **forensisches Image** eines Geräts vorliegt, kannst du mit der **Analyse der Partitionen und des verwendeten Dateisystems** sowie der **Wiederherstellung** potenziell **interessanter Dateien** beginnen, einschließlich gelöschter Dateien. Erfahre hier, wie:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Abhängig von den verwendeten Betriebssystemen und sogar der Plattform sollten nach unterschiedlichen interessanten Artefakten gesucht werden:


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

## Tiefgehende Untersuchung spezifischer Dateitypen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können je nach **Dateityp und der Software**, mit der sie erstellt wurde, verschiedene **Tricks** hilfreich sein.\
Lies die folgende Seite, um einige interessante Tricks kennenzulernen:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Besonders erwähnen möchte ich die folgende Seite:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Untersuchung von Speicherabbildern


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-Untersuchung


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensik-Techniken**

Behalte die mögliche Verwendung von Anti-Forensik-Techniken im Hinterkopf:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
