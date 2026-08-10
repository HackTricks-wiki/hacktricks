# Podstawowa metodologia analizy kryminalistycznej

## Tworzenie i montowanie obrazu


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza Malware

Nie jest to **koniecznie pierwszy krok do wykonania po uzyskaniu obrazu**. Możesz jednak używać tych technik analizy malware niezależnie od tego, czy masz plik, obraz systemu plików, obraz pamięci, pcap... dlatego warto **mieć te działania na uwadze**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekcja obrazu

Jeśli otrzymasz **forensic image** urządzenia, możesz rozpocząć **analizowanie partycji i systemu plików** oraz **odzyskiwanie** potencjalnie **interesujących plików** (w tym usuniętych). Dowiedz się, jak to zrobić:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

W zależności od użytych systemów operacyjnych, a nawet platform, należy szukać różnych interesujących artefaktów:


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

## Szczegółowa inspekcja określonych typów plików i Software

Jeśli masz bardzo **podejrzany** **plik**, to **w zależności od typu pliku i software'u**, który go utworzył, przydatnych może być kilka **tricków**.\
Przeczytaj poniższą stronę, aby poznać kilka interesujących tricków:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Chcę szczególnie wspomnieć o stronie:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspekcja zrzutu pamięci


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspekcja Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniki Anti-Forensic**

Należy pamiętać o możliwości użycia technik anti-forensic:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
