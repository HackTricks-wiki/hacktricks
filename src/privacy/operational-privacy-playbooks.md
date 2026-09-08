# Playbooki prywatności operacyjnej

Te playbooki łączą mechanizmy kontroli opisane w pozostałej części tej sekcji. Są punktami wyjścia, a nie gwarancjami: aktualizuj model zagrożeń za każdym razem, gdy w workflow pojawi się nowy obserwator, konto, urządzenie, lokalizacja, płatność, plik lub kontrahent.

## Uniwersalna kontrola wstępna

1. Zapisz uzasadniony cel oraz to, co musi pozostać prywatne **przed kim**.
2. Zarejestruj tożsamości, urządzenia, sieci, konta, kanały płatności, kontrahentów, lokalizacje fizyczne i dane, których dotknie działanie.
3. Zidentyfikuj najsilniejszego prawdopodobnego obserwatora oraz konsekwencje niepowodzenia.
4. Potwierdź uprawnienia, obowiązujące prawo, warunki dostawcy i politykę organizacji.
5. Zdecyduj, co musi pozostać wewnętrznie przypisywalne na potrzeby bezpieczeństwa, reagowania na incydenty, księgowości i audytu.
6. Wybierz najmniejszy użyteczny segment; przed użyciem przygotuj jego ścieżki odzyskiwania i wyłączenia.
7. Przetestuj segment względem kontrolowanej usługi, w tym wycieki IP/DNS/IPv6, tożsamość przeglądarki, metadane dokumentów, wyciąg płatniczy i powiadomienia.

Skorzystaj ze szczegółowego modelu w [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Codzienna podstawa prywatności

Cel: ograniczyć tracking komercyjny, przejęcie kont i niepotrzebne ujawnianie danych bez prób osiągnięcia anonimowości.

- Używaj utrzymywanego systemu operacyjnego z szyfrowaniem całego dysku, automatycznymi aktualizacjami, blokadą ekranu i bezpiecznym rozruchem, jeśli są dostępne.
- W pierwszej kolejności skonfiguruj password manager, email odzyskiwania oraz odporne na phishing MFA/klucze bezpieczeństwa.
- Przeglądaj uprawnienia aplikacji, historię lokalizacji, identyfikatory reklamowe, synchronizację z chmurą i połączenia z kontami zewnętrznych usług.
- Używaj popularnej przeglądarki z niewielką liczbą rozszerzeń, ochroną przed trackingiem, HTTPS oraz oddzielnymi profilami do przeglądania treści służbowych, prywatnych i wysokiego ryzyka.
- Używaj aliasów private relay lub odrębnych adresów email zależnie od relacji; nie używaj prywatnego numeru telefonu, gdy jest on jedynie opcjonalny.
- Preferuj komunikatory z szyfrowaniem end-to-end dla treści, pamiętając, że uczestnicy, czas, grupy i endpointy pozostają metadanymi.
- Celowo usuwaj metadane z plików i przed publikacją sprawdzaj wyeksportowaną kopię — nie oryginał.
- Używaj tokenów wirtualnych kart lub walletów do segmentacji danych uwierzytelniających płatności; nie nazywaj ich anonimowymi.
- Twórz kopie zapasowe zaszyfrowanych materiałów odzyskiwania i testuj ich przywracanie.

## Publikacja pseudonimowa

Cel: uniemożliwić przypadkowym czytelnikom i platformom proste powiązanie publikacji z tożsamością cywilną. Nie zapewnia to ochrony przed kompetentnym, ukierunkowanym dochodzeniem.

1. Określ, czy platforma, dostawca hostingu, czytelnicy, kontakty, sieć lokalna, dostawca płatności lub postępowanie prawne należą do modelu zagrożeń.
2. Utwórz dedykowany kontekst endpointu/konta na czystej bazie. Wyłącz osobistą synchronizację przeglądarki, dokumenty w chmurze, przesyłanie kontaktów i podglądy powiadomień.
3. Utwórz konto pseudonimowe przez wybrany segment sieci. Nie używaj ponownie nazw użytkownika, awatarów, kanałów odzyskiwania, szablonów tekstu, loginu osobistego identity providera.
4. Używaj Tor Browser, gdy unlinkability względem celu jest ważniejsza od szybkości; nie dodawaj rozszerzeń, nie zmieniaj nadmiernie rozmiaru ani ustawień i nie otwieraj pobranych dokumentów online w zwykłej sesji desktopowej.
5. Twórz treści w procesie, który nie osadza osobistych nazw szablonów, autorów rewizji, ścieżek drukarek, GPS/EXIF, miniatur ani ukrytych warstw. Wyeksportuj kopię i sprawdź ją odpowiednimi narzędziami do metadanych.
6. Sprawdź treść pod kątem faktów umożliwiających identyfikację: unikalnych dat, szczegółów dotyczących miejsca pracy, lokalnej pogody/strefy czasowej, odbić, dźwięku tła, nawyków językowych i ponownego użycia tekstu z wcześniejszych publikacji.
7. Używaj oddzielnego kanału odpowiedzi. Każdy bezpośredni kontakt, załącznik i link traktuj jako potencjalną próbę korelacji lub phishingu.
8. Jeśli w grę wchodzą pieniądze, użyj zgodnej z prawem metody, która ujawnia wyłącznie niezbędne dane. Zakładaj, że platforma i regulowany pośrednik mogą znać odbiorcę płatności, nawet jeśli czytelnicy go nie znają.
9. Opublikuj materiał, a następnie sprawdź publiczny rezultat z innego, czystego kontekstu. Zapisz, co platforma dodała lub przekształciła.
10. Utrzymuj zaplanowaną częstotliwość tylko wtedy, gdy nie tworzy ona stabilnego fingerprintu zachowania; wycofaj segment zamiast po cichu wykorzystywać go ponownie.

W przypadku poważnego dziennikarstwa, aktywizmu, przemocy domowej lub ryzyka na poziomie państwowym uzyskaj indywidualną pomoc od doświadczonej organizacji zajmującej się bezpieczeństwem cyfrowym; statyczna checklista nie jest w stanie modelować lokalnego prawa ani aktywnego przeciwnika.

## Autoryzowane działania red team

Cel: utrzymać osobiste tożsamości operatorów i ich sieci domowe poza telemetrią celu, zachowując jednocześnie autoryzację, kontrolę i reagowanie na incydenty.

### Przed oknem startowym

- Sfinalizuj aneks infrastrukturalny ROE, cele/wykluczenia, zakresy źródłowe, daty, awaryjne zatrzymanie oraz uprawnienia stron trzecich/dostawców.
- Przydziel dedykowany profil operatora lub VM, sekrety zaangażowania, magazyn dowodów, projekt w chmurze, domeny i budżet.
- Preferuj egress dostarczony przez klienta lub stały bastion kontrolowany przez organizację. Przetestuj zachowanie full-tunnel IPv4/IPv6/DNS oraz politykę fail-closed.
- Przechowuj mapowanie operatora na publiczną infrastrukturę u kontrolera ćwiczenia lub uzgodnionego kontaktu escrow.
- Ustal limity szybkości, allowlisty celów oraz oddzielne zatwierdzanie działań destrukcyjnych, bezprzewodowych, fizycznych, phishingowych lub obejmujących zbieranie poświadczeń.
- Używaj kanału płatności kontrolowanego przez organizację i wewnętrznie rejestruj zatwierdzenia.

### W trakcie zaangażowania

- Rozpoczynaj z zatwierdzonego endpointu i tunelu; przed ruchem assessment sprawdź obserwowany egress.
- Nie umieszczaj w segmencie osobistych kont, urządzeń, numerów telefonów, repozytoriów, kluczy SSH/GPG ani synchronizacji z chmurą.
- Rejestruj operatora/zadanie, rozpoczęcie/zakończenie, źródło, cel w zakresie i zmianę konfiguracji bez zbierania niepotrzebnych treści klienta.
- Zatrzymaj się w przypadku niejasności zakresu, nieoczekiwanych systemów stron trzecich, powiadomienia dostawcy o nadużyciu, wpływu na bezpieczeństwo, utraty sprzętu lub utraty kontaktu z kontrolerem.
- Nigdy nie improwizuj, używając Wi-Fi sąsiada, skradzionych poświadczeń, niezatwierdzonej karty SIM/konta ani sprzętu ukrytego w lokalu.

### Po zakończeniu zaangażowania

- Zatrzymaj zadania i C2; odzyskaj zatwierdzone urządzenia drop; unieważnij tokeny, poświadczenia i certyfikaty.
- Uzgodnij infrastrukturę, domeny, adresy źródłowe, wydatki, dane i sprawy u dostawców z inwentarzem.
- Zwróć/usuń/zachowaj dane klienta zgodnie z umową, zachowaj minimalny wymagany materiał audytowy i zleć drugiemu operatorowi weryfikację wyłączenia.

Zobacz [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md), aby zapoznać się z pełnym przewodnikiem tworzenia i usuwania infrastruktury.

## Zgodny z prawem prywatny zakup lub darowizna

Cel: zminimalizować ujawnianie danych sprzedawcy lub opinii publicznej, jednocześnie wypełniając obowiązki wobec wystawcy, księgowe, podatkowe i związane z sankcjami.

1. Wymień, kto nie może dowiedzieć się czego: odbiorcy publiczni, sprzedawca, pośrednik płatniczy, pracodawca/delegat konta rodzinnego, usługa dostawy lub obserwator blockchaina.
2. Sprawdź lokalne przepisy, odbiorcę/kontrahenta, warunki dostawcy, limity gotówkowe i potrzeby związane z prowadzeniem dokumentacji.
3. Wybierz kanał:
- gotówkę w przypadku akceptowanych, zgodnych z prawem płatności lokalnych bez zapisu w sieci płatniczej;
- regulowaną kartę wirtualną lub kartę przeznaczoną dla konkretnego sprzedawcy w celu separacji danych uwierzytelniających online;
- cryptocurrency dopiero po przeanalizowaniu nabycia, ledgeru, backendu walleta, sieci, kontrahenta i powiązań z późniejszym wydawaniem.
4. Podawaj prawdziwe wymagane dane i pomijaj wyłącznie opcjonalne informacje lojalnościowe/marketingowe. Nie używaj tożsamości ani adresu innej osoby i nie dziel transakcji w celu obejścia progu.
5. Oddziel kontekst przeglądarki/konta sprzedawcy i unikaj niezwiązanych loginów społecznościowych, programów lojalnościowych oraz osobistych kanałów odzyskiwania.
6. Sprawdź, co pojawia się na wyciągach, rachunkach, powiadomieniach, przesyłkach i publicznych listach darczyńców.
7. Przechowuj wymagane dowody zakupu/podatkowe/autoryzacyjne w formie zaszyfrowanej; unieważnij jednorazowe dane płatnicze po upływie okresu zwrotu.

Zobacz [Private Digital Payments](private-digital-payments.md) i [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Podróże i niezaufane sieci

Cel: chronić dane i konta w sieciach nieadministrowanych przez użytkownika — nie ukrywać nieautoryzowanej aktywności.

- Zaktualizuj urządzenia i pobierz potrzebne poświadczenia/mapy przed podróżą.
- Ogranicz ilość przechowywanych danych; używaj szyfrowania całego dysku, silnego odblokowania, planowania zdalnego odzyskiwania oraz procedur wyłączania urządzeń przed przekroczeniem granicy/w razie ryzyka fizycznego, odpowiednich do porady prawnej.
- Zweryfikuj SSID lokalu/portal captive. Jeśli to właściwe, preferuj osobisty hotspot, pamiętając jednak o rejestrach abonenta sieci komórkowej i lokalizacji.
- Używaj pełnego/wymuszonego zatwierdzonego VPN dla danych organizacji; sprawdź, czy urządzenia połączone przez tethering również z niego korzystają, i przetestuj zachowanie IPv6/DNS.
- Używaj travel routera do izolacji klientów i powtarzalnej polityki, a nie jako gwarancji anonimowości.
- Traktuj publiczne ładowarki USB, pożyczone komputery, publiczne drukarki i współdzielone systemy w salach konferencyjnych jako odrębne zagrożenia.
- Zakładaj, że obecność fizyczna, identyfikatory radiowe, logowanie do portalu, kamery oraz rejestry płatności/lokalizacji mogą skorelować wizytę.

Szczegóły porównania i konfiguracji znajdują się w [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Reagowanie na awarie i ujawnienie danych

Gdy dojdzie do wycieku z segmentu lub może on zostać powiązany:

1. Zatrzymaj aktywność, jeśli jej kontynuowanie zwiększa ryzyko; w stosownych przypadkach użyj awaryjnego zatrzymania zaangażowania.
2. Zachowaj niezbędne dowody bez rozpowszechniania wrażliwych danych. Zapisz dokładny czas, zaobserwowany wskaźnik i dotknięte zasoby.
3. Powiadom odpowiedniego właściciela/kontrolera/kontakt ds. bezpieczeństwa. Nie ukrywaj incydentu w celu zachowania narracji o prywatności.
4. Unieważnij sesje, tokeny, dane uwierzytelniające płatności i dostęp do infrastruktury; zmień sekrety z użyciem znanego jako czysty endpointu.
5. Ustal, które krawędzie utworzyły powiązanie: endpoint, konto odzyskiwania, sieć, płatność, metadane, treść, zachowanie, kontrahent lub obecność fizyczna.
6. Uznaj cały dotknięty segment za spalony. Nie zmieniaj jedynie jego nazwy użytkownika ani wyjściowego IP.
7. Wypełnij obowiązki dotyczące powiadomień o wycieku, dostawcy, klienta, finansowe i prawne.
8. Odbuduj segment dopiero po zmianie procesu, który spowodował powiązanie; udokumentuj mechanizm kontroli i przetestuj go.

## Okresowy audyt

- [ ] Model zagrożeń oraz założenia prawne/dostawców są przeglądane zgodnie z harmonogramem i z odnotowaną datą.
- [ ] Urządzenia, konta, aliasy, domeny, ścieżki sieciowe i dane uwierzytelniające płatności są ujęte w inwentarzu.
- [ ] Ścieżki odzyskiwania nie przecinają nieoczekiwanie segmentów.
- [ ] Przetestowano zachowanie full-tunnel, DNS, IPv6 i fail-closed.
- [ ] Publiczne pliki i profile sprawdzono pod kątem metadanych/powtórnego użycia treści.
- [ ] Założenia dotyczące node'ów/backendów walletów i protokołów crypto pozostają aktualne.
- [ ] Logi i rachunki są minimalne, zaszyfrowane, objęte kontrolą dostępu i przechowywane w ramach okresu retencji.
- [ ] Stare segmenty i infrastruktura zaangażowania zostały w pełni wycofane.
