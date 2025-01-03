# Podstawowa Metodologia Kryminalistyczna

{{#include ../../banners/hacktricks-training.md}}

## Tworzenie i Montowanie Obrazu

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza Złośliwego Oprogramowania

To **nie jest koniecznie pierwszy krok do wykonania po uzyskaniu obrazu**. Ale możesz używać tych technik analizy złośliwego oprogramowania niezależnie, jeśli masz plik, obraz systemu plików, obraz pamięci, pcap... więc warto **mieć te działania na uwadze**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekcja Obrazu

Jeśli otrzymasz **obraz kryminalistyczny** urządzenia, możesz zacząć **analizować partycje, system plików** używany i **odzyskiwać** potencjalnie **interesujące pliki** (nawet usunięte). Dowiedz się jak w:

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

## Głęboka inspekcja specyficznych typów plików i oprogramowania

Jeśli masz bardzo **podejrzany** **plik**, to **w zależności od typu pliku i oprogramowania**, które go stworzyło, kilka **sztuczek** może być przydatnych.\
Przeczytaj następującą stronę, aby poznać kilka interesujących sztuczek:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Chcę szczególnie wspomnieć o stronie:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspekcja Zrzutu Pamięci

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspekcja Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniki Antykryminalistyczne**

Pamiętaj o możliwym użyciu technik antykryminalistycznych:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Polowanie na Zagrożenia

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
