# Hacking systemów sterowania przemysłowego

{{#include ../banners/hacktricks-training.md}}

## O tej sekcji

Ta sekcja przedstawia komponenty, architektury i protokoły przemysłowych systemów sterowania (ICS), a także metody oceny ich bezpieczeństwa. ICS należą do szerszej dziedziny technologii operacyjnych (OT): programowalnych systemów i urządzeń, które monitorują procesy fizyczne lub powodują w nich zmiany. Typowe przykłady to systemy nadzoru, sterowania i akwizycji danych (SCADA), rozproszone systemy sterowania (DCS) oraz programowalne sterowniki logiczne (PLC).<sup>[[1]](#references)</sup>

Prace związane z bezpieczeństwem w tych środowiskach muszą uwzględniać wymagania inne niż w tradycyjnym IT, w tym bezpieczeństwo procesów, niezawodność, dostępność, deterministyczne działanie i cykle życia urządzeń. Technicznie poprawne zabezpieczenie może być nieodpowiednie, jeśli zakłóca proces fizyczny, dlatego testy i działania naprawcze należy uzgadniać z właścicielem systemu i personelem operacyjnym.<sup>[[1]](#references)</sup>

Kompromitacja lub przypadkowe zakłócenie działania może zatrzymać produkcję, uszkodzić urządzenia, doprowadzić do uwolnienia niebezpiecznych substancji, zaszkodzić środowisku albo spowodować obrażenia lub śmierć. Potencjalny wpływ na świat fizyczny sprawia, że przed rozpoczęciem aktywnych testów należy zrozumieć kontrolowany proces i jego bezpieczne granice działania.<sup>[[1]](#references)</sup>

Wiele wdrożeń OT nadal korzysta ze starszych systemów operacyjnych, aplikacji i protokołów, ponieważ urządzenia mają długi okres eksploatacji, a zmiany wymagają testów operacyjnych i bezpieczeństwa. Niektóre protokoły zaprojektowano bez nowoczesnych mechanizmów uwierzytelniania lub szyfrowania, a instalowanie poprawek może być ograniczone przez wsparcie producenta lub okna serwisowe; tam, gdzie bezpośrednia aktualizacja nie jest możliwa, należy zastosować segmentację, kontrolę dostępu i monitorowanie.<sup>[[1]](#references)</sup>

## Priorytety oceny

Zacznij od zrozumienia kontrolowanego procesu, granic systemu, topologii sieci, zasobów, przepływów danych, relacji zaufania i połączeń zewnętrznych. Podobne typy urządzeń mogą pełnić różne funkcje w różnych lokalizacjach, dlatego nie zakładaj, że architektura ani model wpływu jednego wdrożenia mają zastosowanie do innego.<sup>[[1]](#references)</sup>

W miarę możliwości preferuj pasywne rozpoznanie i istniejącą dokumentację inżynieryjną. Wszelkie aktywne skanowanie lub eksploatacja powinny być prowadzone zgodnie z zatwierdzonym planem testów, który określa ograniczenia bezpieczeństwa, okna serwisowe, procedury przywracania działania i warunki przerwania testów. Ustalenia należy oceniać zarówno pod kątem wpływu na cyberbezpieczeństwo, jak i potencjalnego oddziaływania na proces fizyczny.<sup>[[1]](#references)</sup>

Ta sama wiedza o architekturze wspiera działania obronne, takie jak inwentaryzacja zasobów, segmentacja sieci, monitorowanie, reagowanie na incydenty i zarządzanie podatnościami oparte na ryzyku.<sup>[[1]](#references)</sup>

## Nadużycie sterownika nadzorującego system chłodniczy

Menedżer systemu chłodniczego koordynuje pracę sprężarek i sterowników komór, ale sam ich nie chłodzi. Dostęp do jego interfejsu zarządzania może więc umożliwić sterowanie wieloma urządzeniami podrzędnymi za pośrednictwem standardowego rozpowszechniania konfiguracji. Różni się to od zmiany ustawień jednego termostatu lub bezpośredniego sterowania sprężarką.<sup>[[3]](#references)[[4]](#references)</sup>

### Logowanie za pomocą kodu serwisowego wyliczanego na podstawie daty

W podatnych menedżerach systemu Danfoss alternatywne logowanie XML akceptuje kod wyliczany na podstawie daty kontrolera zamiast hasła do konta.<sup>[[2]](#references)[[3]](#references)</sup> W modelach SM800 i SC255 Synacktiv prześledził atrybuty `eds_only` i `quantum_only` przez funkcje `xml_load_file` i `check_authorize` aż do `check_code_of_day`. W poradniku pokazano również, że funkcja `read_date_time` w `xml.cgi` ujawnia datę kontrolera bez uwierzytelnienia.<sup>[[2]](#references)</sup> Claroty znalazło odpowiadającą temu ścieżkę `getauth` w modelu AK-SM 800A, ale zredagowało atrybuty ją wyzwalające; nie należy zakładać, że nazwy atrybutów ze starszych modeli zadziałają na tej platformie.<sup>[[3]](#references)</sup>

Synacktiv opisuje następujące zapytanie o datę, które nie wymaga uwierzytelnienia:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Kod nie zawiera sekretu specyficznego dla urządzenia: odzyskanie algorytmu z [oprogramowania układowego](../hardware-physical-access/firmware-analysis/) może pozwolić uzyskać poświadczenie ważne w danym dniu dla urządzeń z tą samą podatną implementacją.<sup>[[2]](#references)[[3]](#references)</sup> Najpierw potwierdź model i wersję oprogramowania układowego. Sama odpowiedź zależna od daty nie dowodzi, że alternatywna metoda logowania jest dostępna ani że uzyskano sesję.

### Masowa zmiana konfiguracji i nadużycie grzałki odszraniania

Po uzyskaniu dostępu administracyjnego ustal, które sterowniki lad chłodniczych są przypisane do menedżera systemu oraz czy funkcja dystrybucji konfiguracji pozwala aktualizować je jednocześnie. Zmiana wartości zadanej lady zwykle ogrzewa ją tylko do temperatury otoczenia. Aby ogrzać ją powyżej tej temperatury, należy użyć elektrycznej grzałki odszraniania parownika w sterowniku lady: odszranianie zatrzymuje chłodzenie i uruchamia grzałkę aż do zakończenia cyklu przez czujnik lub timer. Zmiana metody odszraniania, harmonogramu, temperatury zakończenia i limitu czasu może sprawić, że grzałka pozostanie włączona. Menedżer może rozesłać te zmiany do wielu lad i wyciszyć powiązane alarmy, zamieniając pojedyncze przejęcie systemu nadzorczego w zmianę procesu obejmującą cały sklep.<sup>[[4]](#references)</sup>

Stwarza to zagrożenie dla procesu fizycznego; nie jest to bezpieczny sposób demonstrowania działania na systemie produkcyjnym. Jeśli występują, ograniczniki termiczne mogą ograniczać pracę grzałki, ale ciągłe działanie nadal może doprowadzić do przegrzania już osłabionego połączenia elektrycznego. Konfigurację i wpływ zmian weryfikuj wyłącznie w zatwierdzonym laboratorium lub zgodnie z planem bezpieczeństwa procesowego operatora.<sup>[[4]](#references)</sup>

## Punkty wejścia protokołów

- [Testowanie Modbus](../network-services-pentesting/pentesting-modbus.md) obejmuje Modbus TCP, warianty szeregowe, kody funkcji i dostęp do rejestrów.
- [Testowanie OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) dotyczy przemysłowej usługi wymiany danych.
- [Testowanie BACnet](../network-services-pentesting/47808-udp-bacnet.md) obejmuje sieci sterowania automatyką budynkową.

## References

- [1] [NIST SP 800-82 Rev. 3 - Przewodnik po bezpieczeństwie Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Obejście uwierzytelniania w Danfoss System-Managers SM800 i SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Zamroź sterownik, rozmroź żywność](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Aby ogrzać lodówkę, nie potrzeba państwa narodowego](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
