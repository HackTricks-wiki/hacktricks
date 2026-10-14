# Grundlegende Forensik-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Erstellen und Einbinden eines Images


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-Analyse

Dies ist **nicht unbedingt der erste Schritt, den du durchführen musst, sobald du das Image hast**. Du kannst diese Malware-Analysetechniken aber unabhängig davon anwenden, ob du eine Datei, ein Dateisystem-Image, ein Speicher-Image, einen pcap usw. hast. Es ist daher gut, **diese Maßnahmen im Hinterkopf zu behalten**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Untersuchen eines Images

Wenn du ein **forensisches Image** eines Geräts erhältst, kannst du mit der **Analyse der Partitionen und des verwendeten Dateisystems** sowie der **Wiederherstellung** potenziell **interessanter Dateien** beginnen (auch gelöschter Dateien). Hier erfährst du, wie:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Je nach verwendetem Betriebssystem und sogar Plattform sollten nach unterschiedlichen interessanten Artefakten gesucht werden:


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

Informationen zu einem gesperrten Android-Gerät, Möglichkeiten zur Datenerfassung und zur Speicherabbildung findest du unter [Android forensics](android-forensics.md).

## Eingehende Untersuchung bestimmter Dateitypen und Software

Wenn du eine sehr **verdächtige** **Datei** hast, können je nach **Dateityp und der Software**, mit der sie erstellt wurde, verschiedene **Tricks** nützlich sein.\
Auf der folgenden Seite findest du einige interessante Tricks:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Besonders hervorheben möchte ich die folgende Seite:


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
