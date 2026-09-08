# Playbooki prywatności operacyjnej

{{#include ../banners/hacktricks-training.md}}

Te playbooki łączą mechanizmy kontroli z pozostałej części tej sekcji. Są punktami wyjścia, a nie gwarancjami: aktualizuj model zagrożeń za każdym razem, gdy do workflow dołącza nowy obserwator, konto, urządzenie, lokalizacja, płatność, plik lub kontrahent.

## Uniwersalna kontrola wstępna

1. Zapisz uzasadniony cel oraz to, co musi pozostać prywatne **przed kim**.
2. Zapisz tożsamości, urządzenia, sieci, konta, kanały płatności, kontrahentów, lokalizacje fizyczne i dane, których dotknie działanie.
3. Zidentyfikuj najsilniejszego prawdopodobnego obserwatora oraz konsekwencje niepowodzenia.
4. Potwierdź upoważnienie, obowiązujące prawo, warunki dostawcy i politykę organizacji.
5. Zdecyduj, co musi pozostać możliwe do przypisania wewnętrznie ze względów bezpieczeństwa, reagowania na incydenty, księgowości i audytu.
6. Wybierz najmniejszy działający compartment; przed użyciem przygotuj ścieżki jego odzyskiwania i wyłączenia.
7. Przetestuj compartment względem kontrolowanej usługi, w tym IP/DNS/IPv6, tożsamość przeglądarki, metadane dokumentów, wyciąg płatniczy i wycieki powiadomień.

Skorzystaj ze szczegółowego modelu w [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Podstawy prywatności na co dzień

Cel: ograniczyć komercyjne śledzenie, przejęcie kont i niepotrzebną ekspozycję bez prób osiągnięcia anonimowości.

- Używaj utrzymywanego systemu operacyjnego z pełnym szyfrowaniem dysku, automatycznymi aktualizacjami, blokadą ekranu i bezpiecznym rozruchem, jeśli są dostępne.
- W pierwszej kolejności uporządkuj password manager, zapasowy adres e-mail oraz odporne na phishing MFA/klucze bezpieczeństwa.
- Przejrzyj uprawnienia aplikacji, historię lokalizacji, identyfikatory reklamowe, synchronizację z chmurą i połączenia z kontami stron trzecich.
- Używaj mainstreamowej przeglądarki z niewielką liczbą rozszerzeń, ochroną przed śledzeniem i HTTPS, a także oddzielnych profili do przeglądania treści służbowych, prywatnych i wysokiego ryzyka.
- Używaj aliasów private relay lub oddzielnych adresów e-mail zależnie od relacji; nie używaj prywatnego numeru telefonu, gdy jest on jedynie opcjonalny.
- Preferuj komunikatory z szyfrowaniem end-to-end dla treści, pamiętając, że uczestnicy, czas, grupy i endpointy pozostają metadanymi.
- Celowo usuwaj metadane z plików i przed publikacją sprawdzaj wyeksportowaną kopię — nie oryginał.
- Używaj kart wirtualnych lub tokenów portfela do compartmentalization danych uwierzytelniających płatności; nie nazywaj ich anonimowymi.
- Twórz kopie zapasowe zaszyfrowanych materiałów odzyskiwania i testuj ich przywracanie.

## Publikacja pseudonimowa

Cel: uniemożliwić przypadkowym czytelnikom i platformom łatwe powiązanie publikacji z tożsamością cywilną. Nie pokonuje to kompetentnego, ukierunkowanego śledztwa.

1. Określ, czy platforma, dostawca hostingu, czytelnicy, kontakty, sieć lokalna, dostawca płatności lub postępowanie prawne należą do modelu zagrożeń.
2. Utwórz dedykowany kontekst endpointu/konta na czystej bazie. Wyłącz osobistą synchronizację przeglądarki, dokumenty w chmurze, przesyłanie kontaktów i podglądy powiadomień.
3. Utwórz konto pseudonimowe przez wybrany network compartment. Nie używaj ponownie nazw użytkownika, awatarów, kanałów odzyskiwania, szablonów tekstu ani logowania przez osobistego identity providera.
4. Używaj Tor Browser, gdy ważniejsza jest unlinkability miejsca docelowego niż szybkość; nie dodawaj rozszerzeń, nie zmieniaj nadmiernie rozmiaru ani ustawień i nie otwieraj pobranych dokumentów online w zwykłej sesji desktopowej.
5. Przygotowuj tekst w procesie, który nie osadza osobistych nazw szablonów, autorów zmian, ścieżek drukarek, GPS/EXIF, miniaturek ani ukrytych warstw. Eksportuj kopię i sprawdzaj ją za pomocą odpowiednich narzędzi do metadanych.
6. Sprawdzaj treść pod kątem faktów identyfikujących autora: unikalnych dat, szczegółów dotyczących miejsca pracy, lokalnej pogody/strefy czasowej, odbić, dźwięku tła, nawyków językowych i ponownego użycia tekstu z wcześniejszych publikacji.
7. Używaj oddzielnego kanału odpowiedzi. Traktuj każdy bezpośredni kontakt, załącznik i link jako potencjalną próbę korelacji lub phishingu.
8. Jeśli w grę wchodzą pieniądze, użyj zgodnej z prawem metody, która ujawnia tylko niezbędne dane. Załóż, że platforma i regulowany pośrednik mogą znać odbiorcę płatności, nawet jeśli nie znają go czytelnicy.
9. Opublikuj materiał, a następnie sprawdź publiczny rezultat z innego, czystego kontekstu. Zapisz, co platforma dodała lub przekształciła.
10. Utrzymuj zaplanowaną częstotliwość tylko wtedy, gdy nie tworzy ona stabilnego fingerprintu behawioralnego; wycofaj compartment zamiast po cichu używać go ponownie do innych celów.

W przypadku poważnego dziennikarstwa, aktywizmu, przemocy domowej lub ryzyka na poziomie państwowym uzyskaj spersonalizowaną pomoc od doświadczonej organizacji zajmującej się bezpieczeństwem cyfrowym; statyczna checklista nie jest w stanie modelować lokalnego prawa ani aktywnego przeciwnika.

## Autoryzowane działania red-team

Cel: utrzymać prywatne tożsamości operatorów i ich sieci domowe poza telemetryką celu, zachowując jednocześnie autoryzację, kontrolę i reagowanie na incydenty.

### Przed rozpoczęciem

- Sfinalizuj aneks infrastrukturalny ROE, cele/wykluczenia, zakresy źródłowe, daty, awaryjne zatrzymanie oraz uprawnienia stron trzecich/dostawców.
- Przydziel dedykowany profil operatora lub VM, sekrety engagementu, magazyn dowodów, projekt cloud, domeny i budżet.
- Preferuj egress dostarczony przez klienta lub stały bastion kontrolowany przez organizację. Przetestuj działanie full-tunnel IPv4/IPv6/DNS oraz politykę fail-closed.
- Przechowuj mapowanie operatora na publiczną infrastrukturę u kontrolera ćwiczenia lub uzgodnionego kontaktu escrow.
- Ustal limity szybkości, allowlisty miejsc docelowych oraz oddzielne zatwierdzenia dla działań destrukcyjnych, bezprzewodowych, fizycznych, phishingowych lub polegających na zbieraniu danych uwierzytelniających.
- Używaj kanału płatności kontrolowanego przez organizację i zapisuj wewnętrznie zatwierdzenia.

### Podczas engagementu

- Rozpoczynaj z zatwierdzonego endpointu i tunelu; przed ruchem testowym weryfikuj obserwowany egress.
- Nie umieszczaj w compartment osobistych kont, urządzeń, numerów telefonów, repozytoriów, kluczy SSH/GPG ani synchronizacji z chmurą.
- Rejestruj operatora/zadanie, rozpoczęcie/zakończenie, źródło, miejsce docelowe w zakresie i zmianę konfiguracji bez zbierania niepotrzebnych treści klienta.
- Zatrzymaj działania w przypadku niejasności zakresu, nieoczekiwanych systemów stron trzecich, powiadomienia dostawcy o abuse, wpływu na bezpieczeństwo, utraty sprzętu lub utraty kontaktu z kontrolerem.
- Nigdy nie improwizuj, korzystając z Wi-Fi sąsiada, skradzionych danych uwierzytelniających, niezatwierdzonej karty SIM/konta ani sprzętu ukrytego w obiekcie.

### Po zakończeniu engagementu

- Zatrzymaj zadania i C2; odzyskaj zatwierdzone urządzenia drop; unieważnij tokeny, dane uwierzytelniające i certyfikaty.
- Uzgodnij infrastrukturę, domeny, adresy źródłowe, wydatki, dane i sprawy u dostawców z inwentarzem.
- Zwróć/usuń/zachowaj dane klienta zgodnie z umową, zachowaj minimalny wymagany materiał audytowy i zleć drugiemu operatorowi weryfikację wyłączenia.

Zobacz [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md), aby zapoznać się z pełnym przewodnikiem budowy i teardownu.

## Zgodny z prawem prywatny zakup lub darowizna

Cel: zminimalizować ujawnienie danych sprzedawcy lub opinii publicznej, jednocześnie spełniając obowiązki wobec wydawcy instrumentu, księgowe, podatkowe i dotyczące sankcji.

1. Wymień, kto nie może dowiedzieć się czego: opinia publiczna, sprzedawca, pośrednik płatniczy, pracodawca/pełnomocnik konta rodzinnego, usługa dostawy lub obserwator blockchaina.
2. Sprawdź lokalne przepisy, odbiorcę/kontrahenta, warunki dostawcy, limity gotówkowe i wymagania dotyczące dokumentacji.
3. Wybierz kanał:
- gotówka dla akceptowanych, zgodnych z prawem lokalnych płatności bez zapisu w sieci płatniczej;
- regulowana karta wirtualna lub karta przeznaczona dla konkretnego sprzedawcy do separacji danych uwierzytelniających online;
- kryptowaluta dopiero po przeanalizowaniu pozyskania, ledger, backendu portfela, sieci, kontrahenta i późniejszych powiązań z wydatkami.
4. Podawaj wymagane prawdziwe dane i pomijaj wyłącznie opcjonalne informacje lojalnościowe/marketingowe. Nie używaj tożsamości ani adresu innej osoby i nie dziel transakcji w celu obejścia progu.
5. Oddziel kontekst przeglądarki/konta sprzedawcy i unikaj niezwiązanych logowań społecznościowych, programów lojalnościowych lub osobistych kanałów odzyskiwania.
6. Potwierdź, co pojawia się na wyciągach, paragonach, powiadomieniach, przesyłkach i publicznych listach darczyńców.
7. Przechowuj wymagane dowody zakupu/podatkowe/autoryzacji w formie zaszyfrowanej; po upływie okresu zwrotu unieważnij jednorazowe dane uwierzytelniające płatności.

Zobacz [Private Digital Payments](private-digital-payments.md) i [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Podróże i niezaufane sieci

Cel: chronić dane i konta w sieciach, którymi użytkownik nie administruje — nie ukrywać nieautoryzowanych działań.

- Zaktualizuj urządzenia i pobierz potrzebne dane uwierzytelniające/mapy przed podróżą.
- Ogranicz przechowywane dane; używaj pełnego szyfrowania dysku, silnego odblokowania, planowania zdalnego odzyskiwania oraz procedur wyłączenia urządzenia podczas kontroli granicznej/ryzyka fizycznego, odpowiednich do porady prawnej.
- Zweryfikuj SSID obiektu/captive portal. W razie potrzeby preferuj osobisty hotspot, pamiętając jednak o rejestrach abonenta sieci komórkowej i lokalizacji.
- Używaj pełnego/wymuszonego zatwierdzonego VPN dla danych organizacji; sprawdź, czy urządzenia korzystające z tetheringu również go używają, oraz przetestuj działanie IPv6/DNS.
- Używaj travel routera do izolacji klientów i powtarzalnej polityki, a nie jako gwarancji anonimowości.
- Traktuj publiczne ładowarki USB, pożyczone komputery, publiczne drukarki i współdzielone systemy w salach konferencyjnych jako oddzielne zagrożenia.
- Załóż, że obecność fizyczna, identyfikatory radiowe, logowanie do portalu, kamery oraz rejestry płatności/lokalizacji mogą skorelować wizytę.

Szczegóły porównania i konfiguracji znajdują się w [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Reagowanie na awarie i ekspozycję

Gdy compartment wycieknie lub może zostać powiązany:

1. Zatrzymaj działanie, jeśli jego kontynuowanie zwiększa szkody; w stosownych przypadkach użyj awaryjnego zatrzymania engagementu.
2. Zachowaj niezbędne dowody bez rozpowszechniania wrażliwych danych. Zapisz dokładny czas, zaobserwowany wskaźnik i zasoby, których dotyczy problem.
3. Powiadom odpowiedniego właściciela/kontrolera/kontakt ds. bezpieczeństwa. Nie ukrywaj incydentu, aby zachować narrację o prywatności.
4. Unieważnij sesje, tokeny, dane uwierzytelniające płatności i dostęp do infrastruktury; zmień sekrety z użyciem znanego jako czysty endpoint.
5. Ustal, które krawędzie utworzyły powiązanie: endpoint, konto odzyskiwania, sieć, płatność, metadane, treść, zachowanie, kontrahent lub obecność fizyczna.
6. Traktuj cały dotknięty compartment jako spalony. Nie zmieniaj jedynie jego nazwy użytkownika lub adresu wyjściowego IP.
7. Wypełnij obowiązki dotyczące powiadomień o wycieku, dostawcy, klienta, finansów i prawa.
8. Odbuduj system dopiero po zmianie procesu, który spowodował powiązanie; udokumentuj mechanizm kontroli i przetestuj go.

## Okresowy audyt

- [ ] Model zagrożeń oraz założenia prawne/dostawcy zostały sprawdzone zgodnie z określonym harmonogramem.
- [ ] Urządzenia, konta, aliasy, domeny, ścieżki sieciowe i dane uwierzytelniające płatności są zinwentaryzowane.
- [ ] Ścieżki odzyskiwania nie przekraczają nieoczekiwanie granic compartment.
- [ ] Działanie full-tunnel, DNS, IPv6 i fail-closed zostało przetestowane.
- [ ] Publiczne pliki i profile zostały sprawdzone pod kątem metadanych/ponownego użycia treści.
- [ ] Założenia dotyczące node'ów/backendów portfeli i protokołów crypto pozostają aktualne.
- [ ] Logi i paragony są minimalne, zaszyfrowane, objęte kontrolą dostępu i przechowywane w ramach okresu retencji.
- [ ] Stare compartmenty i infrastruktura engagementu zostały w pełni wycofane.
{{#include ../banners/hacktricks-training.md}}
