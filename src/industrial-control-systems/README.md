# Hacking systemów sterowania przemysłowego

{{#include ../banners/hacktricks-training.md}}

## O tej sekcji

Ta sekcja przedstawia komponenty, architektury i protokoły przemysłowych systemów sterowania (ICS), a także metody oceny ich bezpieczeństwa. ICS należą do szerszej dziedziny technologii operacyjnej (OT): programowalnych systemów i urządzeń, które monitorują procesy fizyczne lub powodują w nich zmiany. Typowe przykłady obejmują systemy nadzoru i akwizycji danych (SCADA), rozproszone systemy sterowania (DCS) oraz programowalne sterowniki logiczne (PLC).<sup>[[1]](#references)</sup>

Prace związane z bezpieczeństwem w tych środowiskach muszą uwzględniać wymagania różniące się od typowych wymagań IT, w tym bezpieczeństwo procesów, niezawodność, dostępność, deterministyczne działanie i cykl życia urządzeń. Technicznie poprawne zabezpieczenie może być nieodpowiednie, jeśli zakłóca proces fizyczny, dlatego testy i działania naprawcze należy koordynować z właścicielem systemu i personelem operacyjnym.<sup>[[1]](#references)</sup>

Kompromitacja lub przypadkowe zakłócenie działania mogą zatrzymać produkcję, uszkodzić urządzenia, doprowadzić do uwolnienia niebezpiecznych substancji, zaszkodzić środowisku albo spowodować obrażenia czy śmierć. Potencjalny wpływ na świat fizyczny sprawia, że przed rozpoczęciem aktywnych testów należy zrozumieć kontrolowany proces i jego bezpieczne limity operacyjne.<sup>[[1]](#references)</sup>

Wiele wdrożeń OT nadal korzysta ze starszych systemów operacyjnych, aplikacji i protokołów, ponieważ urządzenia mają długi okres eksploatacji, a wprowadzanie zmian wymaga testów operacyjnych i bezpieczeństwa. Niektóre protokoły zaprojektowano bez nowoczesnych mechanizmów uwierzytelniania i szyfrowania, a możliwość instalowania poprawek może być ograniczona przez wsparcie dostawcy lub okna serwisowe; tam, gdzie bezpośrednie aktualizacje nie są możliwe, należy zastosować segmentację, kontrolę dostępu i monitorowanie.<sup>[[1]](#references)</sup>

## Priorytety oceny

Zacznij od poznania kontrolowanego procesu, granic systemu, topologii sieci, zasobów, przepływów danych, relacji zaufania i połączeń zewnętrznych. Podobne typy urządzeń mogą pełnić różne funkcje w różnych zakładach, dlatego nie zakładaj, że architektura lub model wpływu z jednego wdrożenia będą pasować do innego.<sup>[[1]](#references)</sup>

W miarę możliwości preferuj pasywne wykrywanie i istniejącą dokumentację inżynieryjną. Wszelkie aktywne skanowanie lub exploitacja powinny być prowadzone zgodnie z zatwierdzonym planem testów, który określa ograniczenia bezpieczeństwa, okna serwisowe, procedury odzyskiwania i warunki przerwania testów. Ustalenia należy oceniać zarówno pod kątem wpływu na cyberbezpieczeństwo, jak i potencjalnych skutków dla procesu fizycznego.<sup>[[1]](#references)</sup>

Ta sama wiedza o architekturze wspiera działania obronne, takie jak inwentaryzacja zasobów, segmentacja sieci, monitorowanie, reagowanie na incydenty i zarządzanie podatnościami oparte na ryzyku.<sup>[[1]](#references)</sup>

## Punkty wejścia protokołów

- [Testowanie Modbus](../network-services-pentesting/pentesting-modbus.md) obejmuje Modbus TCP, warianty szeregowe, kody funkcji i dostęp do rejestrów.
- [Testowanie OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) obejmuje usługę wymiany danych przemysłowych.
- [Testowanie BACnet](../network-services-pentesting/47808-udp-bacnet.md) obejmuje sieci sterowania automatyką budynkową.

## References

- [1] [NIST SP 800-82 Rev. 3 - Przewodnik po bezpieczeństwie technologii operacyjnej (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
