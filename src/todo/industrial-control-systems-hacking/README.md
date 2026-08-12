# Hacking przemysłowych systemów sterowania

{{#include ../../banners/hacktricks-training.md}}

## O tej sekcji

Ta sekcja przedstawia komponenty, architektury, protokoły i metody oceny bezpieczeństwa przemysłowych systemów sterowania (ICS). ICS jest częścią szerszej domeny technologii operacyjnej (OT): programowalnych systemów i urządzeń, które monitorują procesy fizyczne lub powodują w nich zmiany. Typowe przykłady obejmują systemy nadzoru i zbierania danych (SCADA), rozproszone systemy sterowania (DCS) oraz programowalne sterowniki logiczne (PLC).<sup>[[1]](#references)</sup>

Prace związane z bezpieczeństwem w tych środowiskach muszą uwzględniać wymagania różniące się od wymagań konwencjonalnego IT, w tym bezpieczeństwo procesów, niezawodność, dostępność, deterministyczne działanie oraz cykle życia urządzeń. Technicznie poprawna kontrola bezpieczeństwa może być nieodpowiednia, jeśli zakłóca proces fizyczny, dlatego testy i działania naprawcze należy koordynować z właścicielem systemu oraz personelem operacyjnym.<sup>[[1]](#references)</sup>

Przejęcie systemu lub przypadkowe zakłócenie jego działania może zatrzymać produkcję, uszkodzić urządzenia, doprowadzić do uwolnienia substancji niebezpiecznych, zaszkodzić środowisku albo spowodować obrażenia i śmierć. Ten potencjalny wpływ fizyczny sprawia, że zrozumienie kontrolowanego procesu i jego bezpiecznych limitów operacyjnych musi poprzedzać aktywne testy.<sup>[[1]](#references)</sup>

Wiele wdrożeń OT nadal korzysta ze starszych systemów operacyjnych, aplikacji i protokołów, ponieważ urządzenia mają długi okres eksploatacji, a zmiany wymagają testów operacyjnych i bezpieczeństwa. Niektóre protokoły zaprojektowano bez nowoczesnego uwierzytelniania lub szyfrowania, a patching może być ograniczony przez wsparcie dostawcy albo okna konserwacyjne; tam, gdzie bezpośrednie aktualizacje nie są możliwe, należy zastosować segmentację, kontrolę dostępu i monitoring.<sup>[[1]](#references)</sup>

## Priorytety oceny

Zacznij od zrozumienia kontrolowanego procesu, granic systemu, topologii sieci, zasobów, przepływów danych, relacji zaufania i połączeń zewnętrznych. Podobne typy urządzeń mogą pełnić różne funkcje w różnych lokalizacjach, dlatego unikaj zakładania, że architektura lub model wpływu jednego wdrożenia ma zastosowanie do innego.<sup>[[1]](#references)</sup>

W miarę możliwości preferuj pasywne rozpoznanie i istniejącą dokumentację inżynieryjną. Każde aktywne skanowanie lub exploitation powinno być prowadzone zgodnie z zatwierdzonym planem testów, który definiuje ograniczenia bezpieczeństwa, okna konserwacyjne, procedury odtwarzania i warunki przerwania testu. Wyniki należy oceniać zarówno pod kątem wpływu na cyberbezpieczeństwo, jak i potencjalnego wpływu na proces fizyczny.<sup>[[1]](#references)</sup>

Ta sama wiedza o architekturze wspiera działania obronne, takie jak inwentaryzacja zasobów, segmentacja sieci, monitoring, reagowanie na incydenty oraz zarządzanie podatnościami oparte na ryzyku.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Przewodnik po bezpieczeństwie technologii operacyjnej (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
