# Analiza zrzutu pamięci

{{#include ../../../banners/hacktricks-training.md}}

## Początek

Rozpocznij **wyszukiwanie** **malware** wewnątrz pcap. Użyj **narzędzi** wymienionych w [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility to główny framework open-source do analizy zrzutów pamięci**. To narzędzie napisane w Pythonie analizuje zrzuty z zewnętrznych źródeł lub maszyn wirtualnych VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego zrzutu. Można je rozszerzać za pomocą pluginów, dzięki czemu jest bardzo wszechstronne w badaniach forensic.

[**Znajdziesz tutaj ściągawkę**](volatility-cheatsheet.md)

## Raport awarii mini dump

Gdy zrzut jest mały (ma zaledwie kilka KB, a czasem kilka MB), prawdopodobnie jest to raport awarii mini dump, a nie zrzut pamięci.

![Volatility - Raport awarii mini dump: Gdy zrzut jest mały (ma zaledwie kilka KB, a czasem kilka MB), prawdopodobnie jest to raport awarii mini dump, a nie zrzut pamięci](<../../../images/image (532).png>)

Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i uzyskać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątku oraz wykonywane moduły:

![Volatility - Raport awarii mini dump: Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i uzyskać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątku oraz...](<../../../images/image (263).png>)

Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje

![Volatility - Raport awarii mini dump: Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje](<../../../images/image (142).png>)

![Volatility - Raport awarii mini dump: Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje](<../../../images/image (610).png>)

W każdym razie Visual Studio nie jest najlepszym narzędziem do przeprowadzenia dogłębnej analizy zrzutu.

Powinieneś **otworzyć** go za pomocą **IDA** lub **Radare**, aby przeprowadzić jego **dogłębną inspekcję**.

{{#include ../../../banners/hacktricks-training.md}}
