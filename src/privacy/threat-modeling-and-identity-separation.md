# Modelowanie zagrożeń i separacja tożsamości

Najczęstszą przyczyną utraty anonimowości nie jest złamana kryptografia. Jest nią **linkage**: pojedynczy identyfikator, wzorzec czasowy, urządzenie, konto, płatność, plik lub ludzki nawyk łączy dwa konteksty, które miały pozostać rozdzielone.

## Zbuduj model zagrożeń prywatności

Sześciopytaniowy plan bezpieczeństwa EFF stanowi solidną podstawę: co należy chronić, przed kim, jaki jest wpływ i prawdopodobieństwo awarii, jakie zasoby są dostępne oraz jacy sojusznicy mogą pomóc.<sup>[[1]](#references)</sup> Nadaj mu praktyczną formę za pomocą małej tabeli:

| Zasób/działanie | Obserwator | Obserwowalne dane | Droga korelacji | Kontrola | Ryzyko rezydualne |
|---|---|---|---|---|---|
| Badanie klienta | ISP | Metadane celu/czasu | Rejestr abonenta domowego | Tor Browser | Widoczne użycie Tor; korelacja end-to-end |
| Konto pseudonimowe | Platforma | IP, przeglądarka, dane odzyskiwania | Ponownie użyty telefon/e-mail/zdjęcie | Dedykowany kontekst i alias | Korelacja stylu pisania/grafu społecznego |
| Zakup online | Sprzedawca | Konto, dostawa, tokenizowana karta | Adres i historia konta | Guest checkout, minimalna liczba pól, karta wirtualna | Emitent i operator zachowują rejestry |
| Ruch red-team | Cel/klient | Źródłowy adres IP i zachowanie | Rejestry dostawcy/zlecenia | Dedykowany autoryzowany egress | Celowo przypisywalne w przypadku eskalacji |

Przeglądaj tabelę za każdym razem, gdy zmieniają się lokalizacja, dostawca, urządzenie, strona przeciwna lub konsekwencje.

## Narysuj graf linkability

Traktuj każdą tożsamość jako oddzielny węzeł. Dodaj krawędź dla każdego współdzielonego atrybutu:

- e-mail lub adres odzyskiwania;
- numer telefonu lub przesłanie książki kontaktów;
- nazwa użytkownika, avatar, zdjęcie, bio lub styl pisania/kodu;
- hasło, konto synchronizacji passkey lub pytanie odzyskiwania;
- urządzenie, identyfikator reklamowy, profil przeglądarki, cookies, fonty lub rozszerzenia;
- adres IP, strefa czasowa, język, harmonogram lub jednoczesny status online;
- karta bankowa, konto giełdy, klaster portfeli, adres wysyłkowy lub program lojalnościowy;
- pola autora dokumentu, lokalizacja EXIF, oznaczenia drukarki lub właściciel udostępnienia w chmurze;
- współpracownik, członkostwo w grupie i graf społeczny.

Krawędź nie jest automatycznie katastrofalna, ale wskazuje, który obserwator może dokonać połączenia. EFF wyraźnie ostrzega, że numery telefonów, adresy e-mail i ponownie użyte fotografie mogą łączyć profile.<sup>[[2]](#references)</sup>

## Utwórz compartment krok po kroku

1. **Nazwij kontekst i zabronione połączenia.** Przykład: `client-red-2026`, bez połączeń z prywatnym e-mailem, profilami domowej przeglądarki, prywatnymi metodami płatności i niezwiązanymi klientami.
2. **Wybierz granicę izolacji.** Rosnąca siła: oddzielny profil przeglądarki → oddzielne konto OS → oddzielna VM/qube → dedykowane urządzenie. Oddzielna karta lub okno prywatne nie stanowi granicy bezpieczeństwa.
3. **Utwórz świeże identyfikatory wewnątrz tej granicy.** Użyj adresu e-mail/aliasu właściwego dla kontekstu, nazwy użytkownika, sejfu lub kolekcji w password managerze oraz kluczy uwierzytelniania. Nie dodawaj prywatnego kanału odzyskiwania, jeśli niepowiązanie z dostawcą ma znaczenie.
4. **Wybierz jedną politykę sieciową.** Zdecyduj, czy kontekst zawsze korzysta z client VPN, engagement VPS, zaufanego VPN czy Tor. W miarę możliwości wymuś routing fail-closed.
5. **Wybierz politykę płatności.** Metoda płatności musi odpowiadać modelowi obserwatora; karta wirtualna może ukrywać PAN przed sprzedawcą, ale nadal identyfikuje klienta przed emitentem.
6. **Ustal zasady transferu danych.** Preferuj celowe transfery o wąskim zakresie. Traktuj schowek, foldery współdzielone, urządzenia USB, synchronizację z chmurą, drukarki i zrzuty ekranu jako możliwe mosty.
7. **Zapisz daty utworzenia i likwidacji.** Określ, które dowody muszą być przechowywane na potrzeby umów/podatków/compliance, a które dane tymczasowe powinny wygasnąć.
8. **Przetestuj połączenia przed użyciem.** Sprawdź ustawienia konta, pola odzyskiwania, profil publiczny, IP/DNS, stan przeglądarki, metadane plików i dashboardy dostawców.

{% hint style="warning" %}
Nie wymyślaj informacji o tożsamości, jeśli usługa lub prawo wymaga prawidłowej identyfikacji. Privacy compartment służy minimalizacji i separacji danych, a nie oszustwu tożsamości ani omijaniu customer due diligence.
{% endhint %}

## Podstawowa konfiguracja endpointu i konta

- Używaj obsługiwanego sprzętu i niezwłocznie instaluj aktualizacje OS, przeglądarki, walleta i firmware.
- Włącz szyfrowanie urządzenia i używaj silnego kodu urządzenia. Szyfrowanie danych w spoczynku pomaga, gdy wyłączone urządzenie zostanie zgubione lub zajęte, ale nie chroni, gdy malware lub odblokowana sesja mogą odczytywać dane.<sup>[[3]](#references)</sup>
- Używaj unikalnych, losowo generowanych haseł przechowywanych w password managerze.
- Jeśli model zagrożeń pozwala na ich model odzyskiwania/synchronizacji, preferuj uwierzytelnianie odporne na phishing, takie jak WebAuthn/passkeys lub hardware security keys. NIST wskazuje, że ręcznie wpisywane OTP nie są odporne na phishing, ponieważ impostor może je przekazać dalej.<sup>[[4]](#references)</sup>
- Przechowuj kody odzyskiwania offline i oddzielnie od endpointu. Sprawdź, czy zsynchronizowane konto passkey nie łączy tożsamości, które powinny pozostać rozdzielone.
- Wyłącz zbędne uprawnienia lokalizacji, kontaktów, mikrofonu, kamery, Bluetooth, identyfikatora reklamowego i działania w tle.
- Nie mieszaj prywatnej synchronizacji z chmurą, synchronizacji przeglądarki, kont password managera ani sklepów z aplikacjami z kontekstem wymagającym wysokiej separacji.

## Prywatność przeglądarki

Browser fingerprinting wykorzystuje obserwowalną konfigurację, urządzenie, środowisko i zachowanie do identyfikowania lub korelowania użytkownika. Usuwanie cookies lub zmiana adresów IP nie pokonuje go niezawodnie, a W3C uznaje całkowite techniczne wyeliminowanie go za pomocą szeroko wdrożonych metod za mało prawdopodobne.<sup>[[5]](#references)</sup>

W przypadku zwykłej prywatności:

1. Używaj utrzymywanej przeglądarki z trybem HTTPS-only i silną ochroną przed trackingiem.
2. Blokuj tracking stron trzecich i stosuj partycjonowanie stanu, jeśli jest obsługiwane.
3. Używaj oddzielnych profili przeglądarki dla rzeczywiście oddzielnych kontekstów.
4. Wyłącz niepotrzebne uprawnienia i czyść dane witryn według ustalonego harmonogramu.
5. Unikaj logowania do kont zawierających bogate dane o tożsamości podczas prowadzenia niezwiązanych wrażliwych badań.

W przypadku anonimowości w sieci używaj **Tor Browser w standardowej konfiguracji**. Nie przepuszczaj zwykłej przeglądarki przez Tor: Tor Project ostrzega, że zwykłe przeglądarki mogą ujawniać dane przez DNS/WebRTC, trwały stan, fonty, pluginy i różnice fingerprintu.<sup>[[6]](#references)</sup> Unikaj dodatkowych rozszerzeń, nietypowych rozmiarów okna, niestandardowych fontów i preferencji, które wyróżniają przeglądarkę.<sup>[[7]](#references)</sup>

## Komunikacja i metadane

Metadane obejmują nadawcę, odbiorcę, czas, lokalizację i inny kontekst, nawet gdy treść wiadomości jest szyfrowana.<sup>[[8]](#references)</sup>

- W miarę możliwości preferuj narzędzia z szyfrowaniem end-to-end, ograniczonymi metadanymi po stronie serwera oraz otwartymi protokołami/klientami.
- Weryfikuj wrażliwe kontakty za pomocą niezależnego kanału lub osobiście. Numery bezpieczeństwa Signal służą właśnie do takiej weryfikacji.<sup>[[9]](#references)</sup>
- Nazwy użytkownika Signal mogą inicjować kontakt bez ujawniania numeru telefonu, ale numer telefonu nadal jest wymagany do rejestracji; świadomie konfiguruj widoczność/wykrywalność numeru telefonu.<sup>[[9]](#references)</sup>
- Znikające wiadomości ograniczają liczbę przechowywanych kopii; odbiorcy nadal mogą sfotografować, skopiować, przekazać dalej lub zarchiwizować treść.
- E-mail zwykle ujawnia metadane routingu. Nawet dostawcy skupieni na prywatności nie mogą zapewnić szyfrowania end-to-end wiadomości, gdy druga strona korzysta ze zwykłego e-maila, chyba że obie strony używają kompatybilnej metody E2EE. Proton na przykład dokumentuje, że zwykła poczta do innych dostawców korzysta z TLS i pozostaje czytelna dla dostawcy odbierającego.<sup>[[10]](#references)</sup>
- Używaj oddzielnych książek adresowych i nie przesyłaj prywatnych kontaktów do konta pseudonimowego.

## Pliki, zdjęcia i autorstwo

Tails ostrzega, że fotografie mogą zawierać dane aparatu i lokalizacji, a dokumenty biurowe mogą zawierać pola autora i czasu utworzenia.<sup>[[11]](#references)</sup>

Przed udostępnieniem:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Następnie otwórz ponownie oczyszczoną kopię w izolowanej przeglądarce i sprawdź:

- właściwości dokumentu, komentarze, śledzone zmiany, ukryte arkusze/slajdy, miniatury i załączniki;
- EXIF/XMP/IPTC, GPS, znaczniki czasu, nazwy urządzeń/oprogramowania i unikalne identyfikatory;
- widoczne odbicia, charakterystyczne miejsca, zawartość ekranów, głosy, twarze i dźwięki tła;
- nazwę pliku, ścieżki w archiwum, właściciela udostępnienia w chmurze, certyfikat podpisu i historię zmian.

Sanityzacja może uszkodzić dowody lub autentyczność. Zachowaj zaszyfrowany oryginał, gdy istotne jest zachowanie chain of custody lub późniejsza weryfikacja. Stylometria i styl kodowania również mogą wskazywać autorstwo; usunięcie metadanych nie zmienia ludzkiego stylu.

## Typowe schematy niepowodzeń

- Logowanie się do osobistego konta przez połączenie „anonimowe”.
- Ponowne używanie telefonu do odzyskiwania konta, awatara, nazwy użytkownika, klucza publicznego, portfela lub adresu darowizn.
- Jednoczesne korzystanie z dwóch tożsamości w skorelowanych kontekstach.
- Kopiowanie tekstu/plików przez osobisty schowek w chmurze lub współdzielony folder.
- Instalowanie charakterystycznych rozszerzeń Tor Browser lub zmienianie wielu ustawień domyślnych.
- Ufanie twierdzeniu o „braku logów” bez zrozumienia, co jest rejestrowane, jak długo i przez których podwykonawców.
- Zakładanie, że dodatkowy telefon jest anonimowy, podczas gdy podróżuje obok telefonu osobistego. EFF zauważa, że lokalizacja komórkowa i wspólne przemieszczanie się mogą pozwolić na skorelowanie urządzeń.<sup>[[3]](#references)</sup>
- Traktowanie szyfrowania jako usuwania danych; punkty końcowe i odbiorcy mogą zachować tekst jawny.

## Lista kontrolna weryfikacji

- [ ] Kontekst nie zawiera osobistego adresu odzyskiwania, numeru telefonu, konta synchronizacji ani ponownie używanych multimediów, chyba że zostało to celowo zaakceptowane.
- [ ] Zamierzona ścieżka sieciowa jest aktywna i w razie awarii odcina połączenie.
- [ ] Strefa czasowa, ustawienia regionalne, rozszerzenia i uprawnienia przeglądarki/urządzenia są zgodne z planem.
- [ ] W kontekście nie są otwarte żadne osobiste konta.
- [ ] Pliki zostały sprawdzone i poddane sanityzacji; oryginały są obsługiwane oddzielnie.
- [ ] Kontakty zostały uwierzytelnione drugim kanałem.
- [ ] Metadane widoczne dla dostawcy oraz okres przechowywania danych są znane.
- [ ] Procedury likwidacji środowiska, przechowywania dowodów i odzyskiwania kont są udokumentowane.

## References

- [1] [EFF Surveillance Self-Defense — Twój plan bezpieczeństwa](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Ochrona siebie w sieciach społecznościowych](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Udział w proteście](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Uwierzytelnianie i zarządzanie authenticatorami](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Ograniczanie fingerprintingu przeglądarki w specyfikacjach internetowych](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Używanie Tor z innymi przeglądarkami](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Wtyczki i dodatki w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Dlaczego metadane komunikacji mają znaczenie](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Prywatność numeru telefonu i nazwy użytkowników: szczegółowe omówienie](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Co jest szyfrowane w Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Ostrzeżenia: Tails jest bezpieczny, ale nie jest magiczny](https://tails.net/doc/about/warnings/index.en.html)
