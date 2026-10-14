# Podstawowa metodyka informatyki śledczej

{{#include ../../banners/hacktricks-training.md}}

## Tworzenie i montowanie obrazu


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza malware

**Nie musi to być pierwszy krok po uzyskaniu obrazu**. Możesz jednak stosować te techniki analizy malware niezależnie, jeśli masz plik, obraz systemu plików, obraz pamięci, pcap... Warto więc **mieć te działania na uwadze**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Analiza obrazu

Jeśli otrzymasz **obraz kryminalistyczny** urządzenia, możesz zacząć **analizować partycje i użyty system plików**, a także **odzyskiwać** potencjalnie **interesujące pliki** (również usunięte). Dowiedz się, jak to zrobić:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

W zależności od używanego systemu operacyjnego, a nawet platformy, warto szukać różnych interesujących artefaktów:


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

Informacje o zablokowanym urządzeniu Android, metodach pozyskiwania danych i tworzeniu obrazu pamięci znajdziesz w sekcji [Android forensics](android-forensics.md).

## Szczegółowa analiza określonych typów plików i oprogramowania

Jeśli masz **podejrzany plik**, w zależności od **jego typu i oprogramowania**, które go utworzyło, przydatnych może być kilka **sztuczek**.\
Na poniższej stronie znajdziesz kilka ciekawych sztuczek:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Chcę szczególnie zwrócić uwagę na stronę:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Analiza zrzutu pamięci


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Analiza pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniki antyforensyczne**

Pamiętaj o możliwości zastosowania technik antyforensycznych:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Hunting zagrożeń


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
