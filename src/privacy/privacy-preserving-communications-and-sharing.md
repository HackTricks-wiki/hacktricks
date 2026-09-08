# Komunikacja i udostępnianie z ochroną prywatności

{{#include ../banners/hacktricks-training.md}}

Szyfrowanie end-to-end chroni treść. Nie ukrywa jednak automatycznie konta, numeru telefonu, grafu kontaktów, adresu IP, tokenu push, podglądu powiadomień, czasu, metadanych pliku ani zachowania odbiorcy. Wybierz narzędzie na podstawie metadanych, które usuwa, oraz obserwatorów, których wprowadza.

## Porównanie modeli komunikacji

| Narzędzie/model | Przydatna właściwość | Pozostali obserwatorzy i ograniczenia |
|---|---|---|
| Signal | Dojrzałe E2EE; usernames mogą inicjować kontakt bez udostępniania numeru; sealed sender ogranicza metadane usługi | Numer telefonu jest wymagany do rejestracji; usługa, dostawca push, kontakty i endpoints zachowują część obserwacji |
| SimpleX | Brak globalnego identyfikatora użytkownika; kolejki per-contact; opcjonalny transport Tor | Czas/transport relaya, usługa push, zaproszenia i endpoints; nowszy/mniejszy ekosystem |
| Briar | Bezpośrednia synchronizacja; Tor online; Bluetooth/Wi-Fi offline; brak centralnego magazynu wiadomości | Kontakty i endpoints; lokalni obserwatorzy radia; rozwiązanie skupione na Androidzie; obie strony muszą być dostępne albo należy użyć Mailbox |
| OnionShare | Bezpośrednie udostępnianie plików/odbieranie/czat/strona przez tymczasową usługę onion; brak dostawcy storage | Komputer nadawcy jest usługą; posiadacz linku uzyskuje dostęp; czas i endpoints pozostają widoczne |
| Zaszyfrowany plik `age` | Proste szyfrowanie kluczem odbiorcy niezależne od transportu | Transport widzi nadawcę/odbiorcę/czas/rozmiar; nazwy plików/metadane archiwum i endpoints pozostają widoczne |
| Zwykły email + TLS | Szyfrowanie kanału między serwerami | Obaj dostawcy poczty mogą zazwyczaj odczytać treść i zachowywać metadane routingu/konta |

## Signal: prywatny kontakt bez ujawniania numeru

Signal usernames mogą rozpocząć czat bez ujawniania numeru telefonu użytkownika nowemu kontaktowi, ale numer telefonu nadal jest wymagany do rejestracji.<sup>[[1]](#references)</sup> Sealed sender to przyrostowa ochrona metadanych, a nie odporność na każdą korelację adresu IP/czasu.<sup>[[2]](#references)</sup>

### Procedura

1. Zainstaluj Signal z oficjalnego app store/projektu i najpierw zaktualizuj system operacyjny.
2. Zarejestruj się przy użyciu numeru, do którego masz zgodne z prawem uprawnienie. Nie używaj wynajętych aktywacji SMS, numeru innej osoby ani konta dostawcy uzyskanego przy użyciu fałszywej tożsamości.
3. W **Settings → Privacy → Phone Number** ustaw, kto może widzieć numer i kto może znaleźć konto po numerze, zgodnie z threat model.
4. Utwórz username do wyszukiwania nowych kontaktów. Udostępnij jego dokładny link/QR przez już uwierzytelniony kanał; usernames mogą się zmieniać i nie są nazwą profilu.
5. Wyłącz upload kontaktów/uprawnienia, jeśli wygoda nie jest warta powiązania, i dodawaj kontakty ręcznie tam, gdzie platforma to obsługuje.
6. Otwórz szczegóły kontaktu i porównaj safety number/QR przez drugi kanał lub osobiście przed wysłaniem wrażliwej treści.
7. Sprawdź linked devices, registration lock/PIN, podglądy powiadomień, screen security, call relaying, domyślne ustawienia disappearing messages oraz działanie backupu.
8. Wyślij niewrażliwą wiadomość testową i wykonaj połączenie. Sprawdź ślady na ekranie blokady, komputerze, urządzeniach wearable i w cloud notifications po obu stronach.
9. Traktuj zmieniony safety number lub nieoczekiwane linked device jako zdarzenie wymagające analizy, a nie alert, który należy automatycznie odrzucić.

Nie łącz pseudonimowego zdjęcia profilowego, bio, członkostwa w grupach ani harmonogramu z identyfikującym kontekstem Signal.

## SimpleX: połączenia per-contact bez globalnego identyfikatora

SimpleX przekazuje wiadomości przez jednokierunkowe kolejki i nie przypisuje użytkownikowi identyfikatora obejmującego całą sieć. Własna polityka nadal dokumentuje sesje transportowe, tymczasowe dane serwera, kompromisy związane z push notifications oraz odpowiedzialność endpointów.<sup>[[3]](#references)</sup>

### Procedura

1. Pobierz utrzymywanego klienta z oficjalnego projektu/store i zweryfikuj wydawcę. Użyj dedykowanego profilu OS/aplikacji, gdy tożsamości nie mogą się mieszać.
2. Utwórz **lokalny** profil z nazwą wyświetlaną i obrazem właściwymi dla danego kontekstu. Usunięcie aplikacji bez backupu może spowodować utratę profilu i połączeń.
3. Przy pierwszym uruchomieniu świadomie wybierz tryb powiadomień. Natychmiastowy mobile push może ujawniać dodatkowe metadane infrastrukturze Apple/Google.
4. Utwórz jednorazowy link zaproszenia dla jednego kontaktu. Przekaż go przez uwierzytelniony kanał; każdy, kto uzyska aktywne zaproszenie, może próbować go użyć.
5. Po nawiązaniu połączenia otwórz szczegóły kontaktu i porównaj security code osobiście lub przez niezależny zweryfikowany kanał.<sup>[[4]](#references)</sup>
6. Używaj incognito per-group profile, jeśli jest obsługiwany, zamiast ponownie wykorzystywać ten sam profil w niepowiązanych grupach.
7. Skonfiguruj obsługiwany przez klienta transport Tor, jeśli lokalna sieć/serwer nie powinny widzieć bezpośredniego adresu IP. Po zmianie potwierdź połączenie; nie wymuszaj nieobsługiwanego system proxy.
8. Sprawdź delivery receipts, link previews, połączenia, automatyczne pobieranie oraz eksport/backup bazy danych. Każdy z tych elementów zmienia metadane lub ekspozycję endpointu.
9. Przetestuj odzyskiwanie na zapasowym, odizolowanym urządzeniu bez uruchamiania zduplikowanego aktywnego stanu profilu; projekt ostrzega, że równoczesne kopie mogą zakłócać rozmowy.

Brak globalnego identyfikatora nie uniemożliwia kontaktowi zidentyfikowania użytkownika na podstawie treści, ponownego użycia profilu, dostarczenia zaproszenia, czasu lub grafu społecznego.

## Briar: bezpośrednie wiadomości odporne na zakłócenia

Briar synchronizuje się bezpośrednio między urządzeniami, przez Tor, gdy są online, oraz przez Bluetooth/Wi-Fi podczas lokalnych awarii. Oficjalny threat model zakłada jedynie ograniczone, krótkotrwałe monitorowanie radia bliskiego zasięgu przez przeciwnika, dlatego lokalna sieć bezprzewodowa nie jest niewidoczna.<sup>[[5]](#references)</sup>

### Procedura

1. Zainstaluj Briar z oficjalnej dystrybucji i zweryfikuj źródło pakietu. Użyj obsługiwanego urządzenia Android z aktualnymi security updates.
2. Utwórz lokalne konto z unikalnym pseudonimem kontekstowym i silnym hasłem. Nie ma ścieżki resetowania hasła; sprawdź, czy sekret odblokowania można odzyskać.
3. Jeśli to możliwe, dodawaj kontakty osobiście, skanując wzajemnie kody QR. Uwierzytelnia to kontakt i pozwala uniknąć wysyłania linku przez korelowalny kanał.
4. W ustawieniach łączności włącz tylko wymagane transporty: Tor/Internet, Wi-Fi i/lub Bluetooth. Wyłącz lokalne radia, gdy nie są potrzebne.
5. W przypadku dostarczania asynchronicznego rozważ Briar Mailbox na dedykowanym, zasilanym urządzeniu; zinwentaryzuj je i chroń fizycznie jak serwer wiadomości.
6. Wyślij nieszkodliwą wiadomość testową, gdy Internet jest dostępny, a następnie przetestuj planowaną ścieżkę działania podczas awarii, wyłączając Internet w lokalizacji, do której masz uprawnienia.
7. Sprawdź Android backups, podglądy powiadomień, screenshots i eksportowaną treść. Lokalne szyfrowane storage jest ujawnione po odblokowaniu/przejęciu endpointu.
8. Usuń utracone kontakty/urządzenia i wycofaj cały kontekst, jeśli naruszono fizyczne posiadanie urządzenia lub ujawniono hasło konta.

## OnionShare: bezpośredni transfer tymczasowy

OnionShare uruchamia usługę onion na komputerze nadawcy/odbiorcy; pliki nie są uploadowane do dostawcy storage, a ruch jest szyfrowany end-to-end wewnątrz Tor.<sup>[[6]](#references)</sup> Pełny onion URL jest bearer capability i musi być chroniony.

### Procedura udostępniania plików przez GUI

1. Zainstaluj OnionShare z jego oficjalnej, podpisanej dystrybucji oraz Tor Browser po stronie odbiorcy.
2. Umieść **oczyszczone kopie** plików w dedykowanym katalogu staging. Nie wskazuj OnionShare osobistego katalogu domowego.
3. Otwórz **Share Files**, dodaj wyłącznie pliki ze staging, pozostaw włączone zabezpieczenie private key/access i włącz opcję **Stop sharing after files have been sent** dla jednego odbiorcy.
4. Rozpocznij udostępnianie i wyślij pełny onion URL przez już uwierzytelniony kanał E2EE. Nie wklejaj go do emaila, issue trackerów ani publicznych chatów.
5. Odbiorca otwiera URL w Tor Browser, weryfikuje z nadawcą oczekiwane nazwy/rozmiary plików i pobiera je.
6. Obie strony porównują wcześniej uzgodniony lub dostarczony oddzielnym kanałem digest SHA-256 w celu zapewnienia integralności, gdy sam plik stanowi granicę bezpieczeństwa.
7. Potwierdź, że OnionShare zatrzymał się po pobraniu; w przeciwnym razie zatrzymaj go ręcznie i zamknij aplikację.
8. Usuń kopię ze staging zgodnie z polityką retencji i sprawdź ustawienia historii/logów OnionShare pod kątem niezamierzonego ujawnienia nazwy pliku.

### Procedura CLI

Oficjalny CLI przyjmuje pliki jako argumenty pozycyjne i zatrzymuje się po domyślnym pojedynczym zakończonym udostępnieniu. Na hoście z zainstalowanymi oficjalnymi CLI/Tor:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Bezpiecznie przekaż pełny wynikowy URL. Nie dodawaj `--public`, `--no-autostop-sharing`, szczegółowego logowania nazw plików ani persistence, chyba że model zagrożeń wyraźnie wymaga wynikowego ujawnienia.<sup>[[7]](#references)</sup>

Traktuj otrzymane dokumenty jako wrogie. Otwieraj je w jednorazowej VM lub rendererze w stylu Dangerzone, a nie na hoście zawierającym tożsamość.

## Niezależne szyfrowanie pliku za pomocą `age`

Niezależne od transportu szyfrowanie jest przydatne, gdy storage/email provider może uzyskać dostęp do obiektu. Nie ukrywa ono nadawcy, odbiorcy, rozmiaru, czasu ani nazwy pliku, chyba że te informacje są obsługiwane oddzielnie.

### Konfiguracja odbiorcy
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Uwierzytelnij publiczny ciąg odbiorcy za pośrednictwem drugiego kanału. Następnie nadawca uruchamia:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Odbiorca odszyfrowuje do nowej ścieżki:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Oficjalne CLI ostrzega, że `-o` nadpisuje istniejący output, dlatego użyj nowego katalogu i zweryfikuj skrót/zawartość przed przeniesieniem.<sup>[[8]](#references)</sup> Nigdy nie wysyłaj pliku tożsamości wraz z ciphertextem.

## Powtarzalny potok sanitizacji plików

Usuwanie metadanych zależy od formatu. Zachowaj zaszyfrowany oryginał, gdy autentyczność, analiza forensics lub chain of custody ma znaczenie; pracuj na kopii.

### Przykład JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Zgodnie z bezpieczniejszymi zaleceniami ExifTool dotyczącymi JPEG, bezmyślne usunięcie każdego tagu może również usunąć informacje o kolorach.<sup>[[9]](#references)</sup> Następnie wizualnie sprawdź piksele pod kątem twarzy, odbić, ekranów, charakterystycznych punktów oraz unikalnych wzorców uszkodzeń/szumu.

### Przepływ pracy dla Office/PDF

1. Przechowuj edytowalny oryginał w postaci zaszyfrowanej i poza kontekstem publikacji.
2. Usuń komentarze, śledzone zmiany, ukryte slajdy/arkusze, osadzone pliki, osobiste szablony oraz właściwości dokumentu w aplikacji używanej do tworzenia dokumentu.
3. Wyeksportuj nowy PDF z dedykowanego, czystego profilu; nie „drukuj” do drukarki cloud.
4. Sprawdź plik zarówno za pomocą narzędzi rozpoznających format, jak i jednorazowego renderera wizualnego:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Przeszukaj wyrenderowany wynik pod kątem nazw, ścieżek, adresów e-mail i tekstu rewizji. Rasteryzacja może usunąć aktywne struktury, ale pogarsza dostępność i możliwość wyszukiwania oraz nie usuwa widocznej zawartości ani stylu pisania.
6. Oblicz hash finalnego artefaktu i przekaż **wyłącznie** tę kopię przez compartment publikacyjny.

## Privacy Pass: anonimowa autoryzacja dla projektantów usług

Privacy Pass oddziela **wydawanie** tokenów od ich **wykorzystywania**. Origin może dowiedzieć się, że klient posiada token zatwierdzony przez issuer, bez poznawania konkretnej interakcji klienta podczas wydawania. Ponowne użycie tokena, unikalne metadane, synchronizacja czasowa lub collusion mogą przywrócić możliwość powiązania.<sup>[[10]](#references)</sup>

Bezpieczny wzorzec wdrożenia:

1. Zdefiniuj twierdzenie, które potwierdza token (na przykład uprawnienie do rate-limit), zamiast ukrytej globalnej tożsamości.
2. Korzystaj ze standaryzowanej architektury i protokołów wydawania; nie implementuj kryptografii blind signature od podstaw.
3. Oddziel administrację issuer/attester i origin, jeśli wymaga tego pożądana właściwość.
4. Ogranicz publiczne/prywatne metadane tokenów do minimum i upewnij się, że zbiory anonimowości są wystarczająco duże.
5. Jeśli jest to obsługiwane, wydawaj tokeny w batchach przed użyciem, aby czas wydania nie odpowiadał w sposób trywialny czasowi wykorzystania.
6. Wykorzystuj każdy token tylko raz, weryfikuj challenge powiązany z origin i usuwaj stan wygasłych tokenów.
7. Nie pozwól, aby cookies, logowanie adresów IP i konta aplikacji po cichu niweczyły właściwość prywatności tokenów.
8. Sprawdź, czy logi issuer i origin mogą połączyć kontrolowane zdarzenie wydania i wykorzystania za pomocą synchronizacji czasowej, metadanych lub unikalnych błędów.

Privacy Pass jest funkcją aplikacji, a nie czymś, co użytkownik może dołączyć do dowolnego konta.

## Lista kontrolna weryfikacji komunikacji

- [ ] Kontakt/zaproszenie/klucz został uwierzytelniony niezależnie.
- [ ] Zrozumiano zakres ujawnienia numeru telefonu, nazwy użytkownika, profilu, grupy i przesyłania kontaktów.
- [ ] Wymieniono obserwatorów bezpośredniego adresu IP, relay, Tor, dostawcy push i lokalnego radia.
- [ ] Przetestowano podglądy powiadomień, wearables, połączone komputery oraz backupy.
- [ ] Pliki zostały oczyszczone, zaszyfrowane w razie potrzeby i otwarte w disposable context.
- [ ] Odzyskiwanie działa bez łączenia niezależnych tożsamości.
- [ ] Dla logów, historii i tymczasowych usług udostępniania określono zasadę wyłączania/przechowywania.

## References

- [1] [Signal — Prywatność numeru telefonu i nazwy użytkownika](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Polityka prywatności i warunki korzystania](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Przewodnik po prywatności i bezpieczeństwie](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Jak to działa](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Projekt bezpieczeństwa](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Zaawansowane użycie i CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — oficjalne CLI i użycie](https://github.com/FiloSottile/age)
- [9] [FAQ ExifTool — Bezpieczne usuwanie metadanych](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architektura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
