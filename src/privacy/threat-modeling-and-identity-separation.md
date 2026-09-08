# Modelowanie zagrożeń i separacja tożsamości

{{#include ../banners/hacktricks-training.md}}

Najczęstszą przyczyną niepowodzenia anonimowości nie jest złamana kryptografia. Jest nią **linkage**: jeden identyfikator, wzorzec czasowy, urządzenie, konto, płatność, plik lub ludzki nawyk łączy dwa konteksty, które miały pozostać rozdzielone.

## Utwórz model zagrożeń prywatności

Sześciopytaniowy plan bezpieczeństwa EFF to solidna podstawa: co należy chronić, przed kim, jaki jest wpływ i prawdopodobieństwo awarii, jakie zasoby są dostępne oraz jacy sojusznicy mogą pomóc.<sup>[[1]](#references)</sup> Nadaj mu praktyczną formę za pomocą niewielkiej tabeli:

| Zasób/działanie | Obserwator | Obserwowalne dane | Ścieżka korelacji | Kontrola | Ryzyko resztkowe |
|---|---|---|---|---|---|
| Badanie klienta | ISP | Metadane miejsca docelowego/czasu | Rekord abonenta domowego | Tor Browser | Widoczne użycie Tor; korelacja end-to-end |
| Konto pseudonimowe | Platforma | IP, browser, dane odzyskiwania | Ponownie użyty telefon/email/zdjęcie | Dedykowany kontekst i alias | Korelacja stylu pisania/grafu społecznościowego |
| Zakup online | Sprzedawca | Konto, dostawa, tokenizowana karta | Adres i historia konta | Zakup gościnny, minimalna liczba pól, karta wirtualna | Wystawca i operator zachowują rekordy |
| Ruch Red-team | Cel/klient | Źródłowy adres IP i zachowanie | Rekordy dostawcy/zlecenia | Dedykowany autoryzowany egress | Celowo przypisywalne podczas eskalacji |

Przeglądaj tabelę za każdym razem, gdy zmieniają się lokalizacja, dostawca, urządzenie, druga strona lub konsekwencje.

## Narysuj graf linkowalności

Traktuj każdą tożsamość jako osobny węzeł. Dodaj krawędź dla każdego współdzielonego atrybutu:

- email lub adres odzyskiwania;
- numer telefonu lub przesłanie książki kontaktów;
- username, avatar, zdjęcie, bio lub styl pisania/kodu;
- hasło, konto synchronizacji passkey lub pytanie odzyskiwania;
- urządzenie, advertising ID, profil browsera, cookies, fonty lub extensions;
- adres IP, strefa czasowa, język, harmonogram lub jednoczesny status online;
- karta bankowa, konto exchange, klaster wallet, adres wysyłkowy lub program lojalnościowy;
- pola autora dokumentu, lokalizacja EXIF, oznaczenia drukarki lub właściciel udostępnienia w cloud;
- współpracownik, członkostwo w grupie i graf społecznościowy.

Krawędź nie jest automatycznie krytyczna, ale wskazuje, który obserwator może dokonać połączenia. EFF wyraźnie ostrzega, że numery telefonów, adresy email i ponownie użyte fotografie mogą łączyć profile.<sup>[[2]](#references)</sup>

## Utwórz compartment krok po kroku

1. **Nazwij kontekst i zabronione połączenia.** Przykład: `client-red-2026`, bez połączenia z osobistym emailem, domowymi profilami browsera, osobistymi metodami płatności i niezwiązanymi klientami.
2. **Wybierz granicę izolacji.** Rosnąca siła: osobny profil browsera → osobne konto OS → osobna VM/qube → dedykowane urządzenie. Osobna karta lub okno prywatne nie jest granicą bezpieczeństwa.
3. **Utwórz świeże identyfikatory wewnątrz tej granicy.** Użyj emaila/aliasu przypisanego do kontekstu, username, sejfu lub kolekcji w password managerze oraz kluczy uwierzytelniania. Nie dodawaj osobistego kanału odzyskiwania, jeśli unlinkability wobec dostawcy ma znaczenie.
4. **Wybierz jedną politykę sieciową.** Zdecyduj, czy kontekst zawsze używa client VPN, engagement VPS, zaufanego VPN czy Tor. W miarę możliwości wymuś routing fail-closed.
5. **Wybierz politykę płatności.** Metoda płatności musi odpowiadać modelowi obserwatora; karta wirtualna może ukryć PAN przed sprzedawcą, ale nadal identyfikuje klienta przed wystawcą.
6. **Ustal zasady transferu danych.** Preferuj wąsko określone, celowe transfery. Traktuj clipboard, współdzielone foldery, urządzenia USB, cloud sync, drukarki i screenshots jako możliwe mosty.
7. **Zapisz daty utworzenia i likwidacji.** Określ, jakie dowody muszą być zachowane na potrzeby umów/podatków/compliance, a jakie dane tymczasowe powinny wygasnąć.
8. **Przetestuj połączenia przed użyciem.** Sprawdź ustawienia konta, pola odzyskiwania, publiczny profil, IP/DNS, stan browsera, metadane plików i dashboardy dostawców.

{% hint style="warning" %}
Nie wymyślaj informacji o tożsamości tam, gdzie usługa lub prawo wymaga dokładnej identyfikacji. Privacy compartment dotyczy minimalizacji i separacji danych, a nie oszustwa tożsamościowego ani omijania customer due diligence.
{% endhint %}

## Podstawy endpointów i kont

- Używaj wspieranego sprzętu i niezwłocznie instaluj aktualizacje OS, browsera, walletów i firmware.
- Włącz szyfrowanie urządzenia i używaj silnego kodu urządzenia. Szyfrowanie danych w spoczynku pomaga, gdy wyłączone urządzenie zostanie zgubione lub zajęte, ale nie wtedy, gdy malware lub odblokowana sesja może odczytywać dane.<sup>[[3]](#references)</sup>
- Używaj unikalnych, losowo generowanych haseł w password managerze.
- Jeśli model zagrożeń pozwala na użycie ich modelu odzyskiwania/synchronizacji, preferuj odporne na phishing uwierzytelnianie, takie jak WebAuthn/passkeys lub sprzętowe security keys. NIST wskazuje, że ręcznie wprowadzane OTP nie są odporne na phishing, ponieważ impostor może je przekazać dalej.<sup>[[4]](#references)</sup>
- Przechowuj kody odzyskiwania offline i oddzielnie od endpointu. Sprawdź, czy zsynchronizowane konto passkey nie łączy tożsamości, które powinny pozostać rozdzielone.
- Wyłącz zbędne uprawnienia lokalizacji, kontaktów, mikrofonu, kamery, Bluetooth, advertising ID i działania w tle.
- Nie łącz osobistej synchronizacji cloud, synchronizacji browsera, kont password managera ani app stores z kontekstem wymagającym wysokiej separacji.

## Prywatność browsera

Fingerprinting browsera wykorzystuje obserwowalną konfigurację, urządzenie, środowisko i zachowanie do identyfikowania lub korelowania użytkownika. Czyszczenie cookies lub zmiana adresów IP nie eliminuje go niezawodnie, a W3C uznaje całkowite techniczne wyeliminowanie tego zjawiska za pomocą szeroko wdrożonych metod za mało prawdopodobne.<sup>[[5]](#references)</sup>

W przypadku zwykłej prywatności:

1. Używaj utrzymywanego browsera z trybem HTTPS-only i silną ochroną przed trackingiem.
2. Blokuj tracking stron trzecich i włączaj partycjonowanie stanu, jeśli jest obsługiwane.
3. Używaj osobnych profili browsera dla rzeczywiście oddzielnych kontekstów.
4. Wyłącz zbędne uprawnienia i czyść dane witryn zgodnie z ustalonym harmonogramem.
5. Unikaj logowania do kont zawierających dużo informacji o tożsamości podczas niezwiązanych z nimi wrażliwych badań.

W przypadku anonimowości web używaj **Tor Browser w standardowej konfiguracji**. Nie kieruj zwykłego browsera przez Tor: Tor Project ostrzega, że zwykłe browsery mogą ujawniać dane przez DNS/WebRTC, trwały stan, fonty, plugins i różnice fingerprintu.<sup>[[6]](#references)</sup> Unikaj dodatkowych extensions, nietypowych rozmiarów okna, własnych fontów i preferencji, które wyróżniają browser.<sup>[[7]](#references)</sup>

## Komunikacja i metadane

Metadane obejmują nadawcę, odbiorcę, czas, lokalizację i inny kontekst, nawet gdy treść wiadomości jest zaszyfrowana.<sup>[[8]](#references)</sup>

- W miarę możliwości preferuj narzędzia z szyfrowaniem end-to-end, ograniczonymi metadanymi po stronie serwera oraz otwartymi protokołami/klientami.
- Weryfikuj wrażliwe kontakty niezależnym kanałem lub osobiście. Signal safety numbers służą właśnie do takiej weryfikacji.<sup>[[9]](#references)</sup>
- Signal usernames mogą inicjować kontakt bez ujawniania numeru telefonu, ale numer telefonu nadal jest wymagany do rejestracji; świadomie skonfiguruj widoczność/wykrywalność numeru telefonu.<sup>[[9]](#references)</sup>
- Znikające wiadomości ograniczają liczbę zachowanych kopii; odbiorcy nadal mogą sfotografować, skopiować, przekazać dalej lub zarchiwizować treść.
- Email zwykle ujawnia metadane routingu. Nawet dostawcy skupieni na prywatności nie mogą zapewnić szyfrowania end-to-end, gdy druga strona używa zwykłego emaila, chyba że obie strony korzystają ze zgodnej metody E2EE. Proton na przykład dokumentuje, że zwykła poczta do innych dostawców korzysta z TLS i pozostaje czytelna dla dostawcy odbierającego.<sup>[[10]](#references)</sup>
- Używaj oddzielnych książek adresowych i nie przesyłaj osobistych kontaktów do konta pseudonimowego.

## Pliki, zdjęcia i autorstwo

Tails ostrzega, że fotografie mogą zawierać dane aparatu i lokalizacji, a dokumenty biurowe mogą zawierać pola autora i czasu utworzenia.<sup>[[11]](#references)</sup>

Przed udostępnieniem:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Następnie ponownie otwórz oczyszczoną kopię w izolowanej przeglądarce i sprawdź:

- właściwości dokumentu, komentarze, śledzone zmiany, ukryte arkusze/slajdy, miniatury i załączniki;
- EXIF/XMP/IPTC, GPS, znaczniki czasu, nazwy urządzeń/oprogramowania i unikalne identyfikatory;
- widoczne odbicia, charakterystyczne punkty, zawartość ekranów, głosy, twarze i dźwięki tła;
- nazwę pliku, ścieżki w archiwum, właściciela udostępnienia w chmurze, certyfikat podpisu i historię zmian.

Sanityzacja może uszkodzić dowody lub autentyczność. Zachowaj zaszyfrowany oryginał, jeśli znaczenie ma chain of custody lub późniejsza weryfikacja. Stylometria i styl kodowania również mogą powiązać autora z materiałem; usunięcie metadanych nie zmienia ludzkiego stylu.

## Typowe schematy niepowodzeń

- Logowanie się do osobistego konta przez „anonimowe” połączenie.
- Ponowne używanie telefonu odzyskiwania, awatara, nazwy użytkownika, klucza publicznego, portfela lub adresu darowizn.
- Jednoczesne używanie dwóch tożsamości w skorelowanych kontekstach.
- Kopiowanie tekstu/plików przez osobisty schowek w chmurze lub współdzielony folder.
- Instalowanie wyróżniających się rozszerzeń Tor Browser lub zmienianie wielu ustawień domyślnych.
- Ufanie twierdzeniu „brak logów” bez zrozumienia, co jest logowane, jak długo i przez których podwykonawców.
- Zakładanie, że dodatkowy telefon jest anonimowy, gdy podróżuje obok osobistego telefonu. EFF zauważa, że lokalizacja komórkowa i wspólne przemieszczanie się mogą korelować te urządzenia.<sup>[[3]](#references)</sup>
- Traktowanie szyfrowania jak usuwania danych; endpointy i odbiorcy mogą zachować plaintext.

## Lista kontrolna weryfikacji

- [ ] Kontekst nie zawiera osobistego adresu odzyskiwania, numeru telefonu, konta synchronizacji ani ponownie używanych mediów, chyba że zostało to celowo zaakceptowane.
- [ ] Zamierzona ścieżka sieciowa jest aktywna i w razie awarii blokuje połączenie.
- [ ] Strefa czasowa, ustawienia regionalne, rozszerzenia i uprawnienia przeglądarki/urządzenia odpowiadają planowi.
- [ ] W kontenerze nie są otwarte żadne osobiste konta.
- [ ] Pliki zostały sprawdzone i poddane sanityzacji; oryginały są obsługiwane oddzielnie.
- [ ] Kontakty zostały uwierzytelnione przez drugi kanał.
- [ ] Metadane widoczne dla dostawcy i okres retencji są zrozumiałe.
- [ ] Procedury likwidacji środowiska, przechowywania dowodów i odzyskiwania konta są udokumentowane.

## References

- [1] [EFF Surveillance Self-Defense — Twój plan bezpieczeństwa](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Ochrona siebie w sieciach społecznościowych](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Udział w proteście](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Uwierzytelnianie i zarządzanie authenticatorami](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Ograniczanie fingerprintingu przeglądarki w specyfikacjach Web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Używanie Tor z innymi przeglądarkami](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Wtyczki i dodatki w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Dlaczego metadane komunikacji mają znaczenie](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Prywatność numeru telefonu i nazwy użytkowników: szczegółowe omówienie](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Co jest szyfrowane w Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Ostrzeżenia: Tails jest bezpieczny, ale nie jest magiczny](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
