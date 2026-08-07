# Podstawowa metodologia analizy kryminalistycznej

{{#include ../../banners/hacktricks-training.md}}

## Tworzenie i montowanie obrazu


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza malware

To **niekoniecznie pierwszy krok, który należy wykonać po uzyskaniu obrazu**. Możesz jednak korzystać z tych technik analizy malware niezależnie, jeśli masz plik, obraz systemu plików, obraz pamięci, pcap... dlatego warto **mieć te działania na uwadze**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekcja obrazu

Jeśli otrzymasz **obraz kryminalistyczny** urządzenia, możesz rozpocząć **analizowanie partycji i używanego systemu plików** oraz **odzyskiwanie** potencjalnie **interesujących plików** (nawet usuniętych). Dowiedz się, jak to zrobić:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

W zależności od używanych systemów operacyjnych, a nawet platform, należy szukać różnych interesujących artefaktów:


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

## Szczegółowa inspekcja określonych typów plików i oprogramowania

Jeśli masz bardzo **podejrzany** **plik**, to **w zależności od typu pliku i oprogramowania**, które go utworzyło, przydatnych może być kilka **tricków**.\
Przeczytaj poniższą stronę, aby poznać kilka interesujących tricków:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Warto również wspomnieć o stronie:


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

## **Techniki antyforensyczne**

Należy pamiętać o możliwości zastosowania technik antyforensycznych:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
