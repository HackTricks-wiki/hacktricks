# Analiza zrzutu pamięci

## Rozpoczęcie

Rozpocznij **wyszukiwanie** **malware** w pliku pcap. Użyj **narzędzi** wymienionych w [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility to framework open-source do analizy zrzutów pamięci**. To narzędzie Python analizuje zrzuty z zewnętrznych źródeł lub maszyn VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego zrzutu. Można je rozszerzać za pomocą pluginów, dzięki czemu jest bardzo wszechstronne w badaniach forensic.<sup>[[1]](#references)[[2]](#references)</sup>

[**Znajdź tutaj ściągawkę**](volatility-cheatsheet.md)

## Raport awarii zrzutu mini

Gdy zrzut jest mały (ma zaledwie kilka KB, ewentualnie kilka MB), może być raportem awarii zrzutu mini, a nie pełnym zrzutem pamięci.<sup>[[3]](#references)</sup>

![Volatility - Raport awarii zrzutu mini: Mały plik zrzutu zidentyfikowany jako raport awarii Mini DuMP](<../../../images/image (532).png>)

Jeśli masz zainstalowane Visual Studio, możesz otworzyć ten plik, aby wyświetlić podstawowe informacje, takie jak nazwa procesu, architektura, szczegóły wyjątku i załadowane moduły:<sup>[[4]](#references)</sup>

![Volatility - Raport awarii zrzutu mini: Jeśli masz zainstalowane Visual Studio, możesz otworzyć ten plik i wyświetlić podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątku i...](<../../../images/image (263).png>)

Możesz również przeanalizować wyjątek i wyświetlić disassembly modułu.<sup>[[4]](#references)</sup>

![Panel Actions programu Visual Studio dla minidump z opcjami natywnego debugowania i ustawiania ścieżek symboli](<../../../images/image (142).png>)

![Disassembly instrukcji z wyjątku minidump w Visual Studio](<../../../images/image (610).png>)

W każdym razie Visual Studio nie jest najlepszym narzędziem do przeprowadzania dogłębnej analizy zrzutu.

Powinieneś **otworzyć** go za pomocą **IDA** lub **Radare**, aby przeanalizować go **dogłębnie**.

## References

- [1] [Framework Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Korzystanie z Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Pliki Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Korzystanie z plików zrzutu w debuggerze Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
