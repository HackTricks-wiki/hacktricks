# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Typy payloadów Intruder

Burp Intruder zawiera następujące wbudowane generatory payloadów i transformacje:<sup>[[1]](#references)</sup>

- **Simple list:** Używa skonfigurowanej listy ciągów znaków jako payloadów.
- **Runtime file:** Odczytuje po jednym payloadzie z każdej linii w czasie działania. Jest to przydatne w przypadku dużych list, ponieważ Burp nie wczytuje całego pliku do pamięci.
- **Case modification:** Generuje niezmienioną wartość, wersję z małymi lub wielkimi literami, `Propername` (pierwsza litera wielka, pozostałe małe) lub `ProperName` (pierwsza litera wielka, pozostałe znaki bez zmian). Burp usuwa zduplikowane wyniki.
- **Numbers:** Generuje kolejne lub losowe liczby z określonego zakresu.
- **Brute forcer:** Generuje wszystkie permutacje z wybranego zestawu znaków dla minimalnej i maksymalnej długości.

## Rozszerzenia i narzędzia uzupełniające

- **Collabfiltrator** generuje payloady, które wykonują polecenia i eksfiltrują ich wyniki przez zapytania DNS do Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** eksportuje wyniki Burp do wykorzystania w innych procesach raportowania.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** konwertuje żądania HTTP na skrypty w kilku językach.<sup>[[4]](#references)</sup>

## Testowanie autoryzacji w wielu sesjach za pomocą Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) to rozszerzenie Java dla Burp Suite `2025.5+`, które przechowuje pliki cookie i nietypowe nagłówki w nazwanych profilach poświadczeń. Wybranie profilu w edytorze żądań umożliwiającym edycję, takim jak Repeater lub przechwycone żądanie Proxy, zastępuje dane uwierzytelniające w żądaniu. To narzędzie ułatwiające ponowne wysyłanie żądań, **a nie obejście autoryzacji**: używaj go do wysyłania tego samego żądania z różnych kont podczas sprawdzania dostępu poziomego, granic uprawnień ról, izolacji tenantów oraz [IDOR/BOLA](../pentesting-web/idor.md) w ramach [metodyki testowania aplikacji webowych](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Powtarzalny proces testowania różnic między tożsamościami

Poniższy proces pozwala traktować zasób/akcję i tożsamość wykonującą żądanie jako oddzielne zmienne testowe, ograniczając fałszywe wyniki spowodowane nieaktualnymi tokenami lub użyciem niewłaściwej sesji przeglądarki.<sup>[[5]](#references)[[8]](#references)</sup>

1. Uwierzytelnij konta testowe reprezentujące każdego odpowiedniego użytkownika, rolę i tenanta w oddzielnych profilach przeglądarki lub kontenerach.
2. Otwórz żądanie zawierające pliki cookie i nagłówki jednej tożsamości, wybierz **Sessions > New** i nadaj profilowi jednoznaczną nazwę, np. `tenant-a-user` lub `tenant-b-admin`. Powtórz te czynności dla każdej tożsamości testowej.
3. Wyślij potencjalnie podatne żądanie do Repeater i ponownie je wyślij bez zmiany metody, endpointu, parametrów ani identyfikatora obiektu, zmieniając wyłącznie wybraną sesję. Porównuj dane w odpowiedziach i obserwowalne zmiany stanu, a nie tylko kody statusu.
4. W przypadku kontroli na poziomie obiektu ponownie wyślij żądanie dotyczące obiektu, o którym wiadomo, że należy do konta A, wybierając profil konta B. W przypadku kontroli na poziomie funkcji ponownie wyślij tę samą uprzywilejowaną akcję z profilami o niższych uprawnieniach.
5. Po ponownym uwierzytelnieniu lub rotacji tokenu użyj **Update** na bieżącym żądaniu przeglądarki albo skonfiguruj regułę Auto Update przed ponownym wykonaniem porównania.

### Semantyka przechwytywania i wstrzykiwania

Przed testowaniem sprawdź tryby aktualizacji/wstrzykiwania, ponieważ żądanie hybrydowe zawierające dane uwierzytelniające dwóch tożsamości może unieważnić porównanie. Bieżące ustawienia domyślne odzwierciedlają wszystkie pliki cookie żądania w profilu, aktualizują tylko już zapisane nietypowe nagłówki, odzwierciedlają pliki cookie wybranego profilu w żądaniu docelowym (usuwając z niego istniejące pliki cookie) i dodają nagłówki profilu. Wybór profilu można ograniczyć do dokładnej subdomeny, domeny aplikacji najwyższego poziomu (ustawienie domyślne) lub wszystkich zapisanych profili.<sup>[[7]](#references)</sup>

- **Mirror** przydaje się, gdy pełny zestaw plików cookie określa tożsamość, a nieaktualne pliki cookie żądania docelowego muszą zostać usunięte.
- **Update existing** pozwala śledzić rotujące wartości bez pobierania z ruchu przeglądarki niezwiązanych plików cookie ani nagłówków.
- **Add all** zachowuje dodatkowe wartości już zapisane w profilu lub żądaniu; sprawdź, czy nie pozostawia danych uwierzytelniających poprzedniej sesji.
- **Do nothing** wyklucza pliki cookie lub nagłówki z aktualizacji profilu, gdy dana klasa poświadczeń nie ma znaczenia.

### Synchronizacja sesji za pomocą Proxy

Reguły Auto Update przypisują ruch Proxy do zapisanego profilu i odświeżają jego pliki cookie/nagłówki. Preferuj stabilny wyróżnik, taki jak dedykowany nagłówek żądania, znacznik `User-Agent` specyficzny dla profilu, identyfikujący plik cookie, `X-PwnFox-Color` lub deklaracja JWT; połącz go z warunkami zakresu/domeny/ścieżki, aby inne aplikacje nie mogły aktualizować profilu. Wszystkie warunki w jednej regule są kolejno oceniane jako logiczne `AND`, dlatego najpierw umieszczaj te najbardziej ograniczające; logikę `OR` uzyskasz, tworząc kilka reguł przypisanych do tego samego profilu. Obsługiwane jest również dopasowanie negatywne.<sup>[[6]](#references)</sup>

Dla każdej pasującej reguły niezależnie wybierz **Mirror request**, **Add all**, **Update existing** lub **Do nothing** dla plików cookie i nagłówków. Reguły dotyczące tylko żądań są uruchamiane, gdy Proxy otrzymuje żądanie; dodanie warunku dotyczącego statusu odpowiedzi, nagłówka odpowiedzi lub treści odpowiedzi opóźnia ocenę do chwili otrzymania odpowiedzi. Kolor wyróżnienia może oznaczać pasujący ruch, co ułatwia sprawdzenie, czy każda tożsamość przeglądarki aktualizuje tylko przypisany jej profil.<sup>[[6]](#references)</sup>

Zapisane profile są przechowywane w projekcie Burp, a eksporty danych projektu w formacie JSON zawierają sesje, a zatem także ich pliki cookie i nagłówki. Traktuj oba pliki jako aktywne dane uwierzytelniające, ogranicz do nich dostęp i po zakończeniu testów usuń zapisane dane rozszerzenia.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentacja PortSwigger - typy payloadów Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - dokumentacja źródłowa i użytkowania Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - reguły Auto Update w Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - ustawienia Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: uproszczenie testowania autoryzacji w wielu sesjach w Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
