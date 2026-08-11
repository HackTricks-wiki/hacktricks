# Grundlegende forensische Methodik

{{#include ../../banners/hacktricks-training.md}}

## Erstellen und Einbinden eines Abbilds


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies **ist nicht unbedingt der erste Schritt, den man nach Erhalt des Abbilds durchführen muss**. Du kannst diese Malware-Analysetechniken jedoch unabhängig davon einsetzen, ob du eine Datei, ein Dateisystem-Abbild, ein Speicherabbild, einen pcap usw. hast. Daher ist es sinnvoll, **diese Maßnahmen im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchen eines Abbilds

Wenn du ein **forensisches Abbild** eines Geräts erhältst, kannst du damit beginnen, die verwendeten **Partitionen und das Dateisystem zu analysieren** und potenziell **interessante Dateien wiederherzustellen** (auch gelöschte). Wie das funktioniert, erfährst du hier:


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

## Tiefgehende Untersuchung bestimmter Dateitypen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können je nach **Dateityp und der Software**, die sie erstellt hat, verschiedene **Tricks** nützlich sein.\
Lies die folgende Seite, um einige interessante Tricks kennenzulernen:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ich möchte besonders auf folgende Seite hinweisen:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Untersuchung eines Speicherabbilds


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Untersuchung eines Pcaps


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensik-Techniken**

Behalte den möglichen Einsatz von Anti-Forensik-Techniken im Hinterkopf:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
