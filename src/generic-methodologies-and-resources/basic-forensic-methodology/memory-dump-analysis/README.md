# Analiza zrzutów pamięci

{{#include ../../../banners/hacktricks-training.md}}

## Początek

Rozpocznij **wyszukiwanie** **złośliwego oprogramowania** w pcap. Użyj **narzędzi** wymienionych w [**Analiza złośliwego oprogramowania**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility to główna otwartoźródłowa platforma do analizy zrzutów pamięci**. To narzędzie w Pythonie analizuje zrzuty z zewnętrznych źródeł lub maszyn wirtualnych VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego zrzutu. Jest rozszerzalne za pomocą wtyczek, co czyni je bardzo wszechstronnym w dochodzeniach kryminalistycznych.

[**Znajdź tutaj arkusz skrótów**](volatility-cheatsheet.md)

## Raport o awarii mini zrzutu

Gdy zrzut jest mały (zaledwie kilka KB, może kilka MB), to prawdopodobnie jest to raport o awarii mini zrzutu, a nie zrzut pamięci.

![](<../../../images/image (532).png>)

Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i powiązać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątkach i moduły, które są wykonywane:

![](<../../../images/image (263).png>)

Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

W każdym razie, Visual Studio nie jest najlepszym narzędziem do przeprowadzenia analizy głębokości zrzutu.

Powinieneś **otworzyć** go za pomocą **IDA** lub **Radare**, aby przeprowadzić inspekcję w **głębi**.

​

{{#include ../../../banners/hacktricks-training.md}}
