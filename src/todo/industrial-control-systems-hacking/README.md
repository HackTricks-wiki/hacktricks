# Hacking przemysłowych systemów sterowania

{{#include ../../banners/hacktricks-training.md}}

## O tej sekcji

Ta sekcja przedstawia komponenty, architektury, protokoły oraz metody oceny bezpieczeństwa przemysłowych systemów sterowania (ICS). ICS jest częścią szerszej dziedziny technologii operacyjnej (OT): programowalnych systemów i urządzeń, które monitorują procesy fizyczne lub powodują w nich zmiany. Typowe przykłady obejmują systemy nadzoru i akwizycji danych (SCADA), rozproszone systemy sterowania (DCS) oraz programowalne sterowniki logiczne (PLC).<sup>[[1]](#references)</sup>

Prace związane z bezpieczeństwem w tych środowiskach muszą uwzględniać wymagania różniące się od wymagań typowych środowisk IT, w tym bezpieczeństwo procesów, niezawodność, dostępność, działanie deterministyczne oraz cykle życia urządzeń. Technicznie poprawny środek bezpieczeństwa może nadal być nieodpowiedni, jeśli zakłóca proces fizyczny, dlatego testowanie i usuwanie problemów powinny być koordynowane z właścicielem systemu oraz personelem operacyjnym.<sup>[[1]](#references)</sup>

## Priorytety oceny

Zacznij od zrozumienia kontrolowanego procesu, granic systemu, topologii sieci, zasobów, przepływów danych, relacji zaufania oraz połączeń zewnętrznych. Podobne typy urządzeń mogą pełnić różne funkcje w różnych lokalizacjach, dlatego unikaj zakładania, że architektura lub model wpływu z jednego wdrożenia mają zastosowanie do innego.<sup>[[1]](#references)</sup>

W miarę możliwości preferuj pasywne rozpoznanie oraz istniejącą dokumentację inżynieryjną. Każde aktywne skanowanie lub exploitation powinno odbywać się zgodnie z zatwierdzonym planem testów, który definiuje ograniczenia bezpieczeństwa, okna serwisowe, procedury odzyskiwania oraz warunki przerwania. Wyniki powinny być oceniane zarówno pod kątem wpływu na cyberbezpieczeństwo, jak i potencjalnych skutków dla procesu fizycznego.<sup>[[1]](#references)</sup>

Ta sama wiedza architektoniczna wspiera działania defensywne, takie jak inwentaryzacja zasobów, segmentacja sieci, monitorowanie, reagowanie na incydenty oraz zarządzanie podatnościami oparte na ryzyku.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Przewodnik po bezpieczeństwie technologii operacyjnej (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
