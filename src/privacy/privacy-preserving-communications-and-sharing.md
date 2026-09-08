# Komunikacja i udostępnianie z ochroną prywatności

Szyfrowanie end-to-end chroni treść. Nie ukrywa jednak automatycznie konta, numeru telefonu, grafu kontaktów, adresu IP, tokenu push, podglądu powiadomień, czasu, metadanych plików ani zachowania odbiorcy. Wybierz narzędzie na podstawie metadanych, które usuwa, oraz obserwatorów, których wprowadza.

## Porównanie modeli komunikacji

| Narzędzie/model | Przydatna właściwość | Pozostali obserwatorzy i ograniczenia |
|---|---|---|
| Signal | Dojrzałe E2EE; usernames mogą inicjować kontakt bez udostępniania numeru; sealed sender ogranicza metadane usługi | Numer telefonu jest wymagany do rejestracji; usługa, dostawca push, kontakty i endpointy zachowują część obserwacji |
| SimpleX | Brak globalnego identyfikatora użytkownika; kolejki per-contact; opcjonalny transport Tor | Czas/transport relay, usługa push, zaproszenia i endpointy; nowszy/mniejszy ekosystem |
| Briar | Bezpośrednia synchronizacja; Tor online; Bluetooth/Wi-Fi offline; brak centralnego przechowywania wiadomości | Kontakty i endpointy; lokalni obserwatorzy radiowi; rozwiązanie skoncentrowane na Androidzie; obie strony muszą być dostępne lub należy użyć Mailbox |
| OnionShare | Bezpośrednie przesyłanie/odbieranie plików, chat i strona przez tymczasową usługę onion; brak dostawcy storage | Komputer nadawcy jest usługą; posiadacz linku poznaje dane dostępowe; czas i endpointy pozostają widoczne |
| Zaszyfrowany plik `age` | Proste szyfrowanie kluczem odbiorcy niezależne od transportu | Transport widzi nadawcę/odbiorcę/czas/rozmiar; nazwy plików/metadane archiwum i endpointy pozostają widoczne |
| Zwykły email + TLS | Szyfrowanie kanału między serwerami | Obaj dostawcy poczty mogą zwykle odczytać treść i zachować metadane routingu/konta |

## Signal: prywatny kontakt bez ujawniania numeru

Signal usernames mogą rozpocząć chat bez ujawniania numeru telefonu użytkownika nowemu kontaktowi, ale numer telefonu nadal jest wymagany do rejestracji.<sup>[[1]](#references)</sup> Sealed sender zapewnia dodatkową ochronę metadanych, ale nie chroni przed każdą korelacją IP/czasu.<sup>[[2]](#references)</sup>

### Workflow

1. Zainstaluj Signal z oficjalnego app store/projektu i najpierw zaktualizuj system operacyjny.
2. Zarejestruj się za pomocą numeru, do którego legalnego używania masz uprawnienia. Nie używaj wynajętych aktywacji SMS, numeru innej osoby ani konta dostawcy uzyskanego z użyciem fałszywej tożsamości.
3. W **Settings → Privacy → Phone Number** ustaw, kto może widzieć numer i kto może znaleźć konto po numerze, zgodnie z threat model.
4. Utwórz username do wyszukiwania nowych kontaktów. Udostępnij jego dokładny link/QR przez już uwierzytelniony kanał; usernames mogą się zmieniać i nie są nazwą profilu.
5. Wyłącz przesyłanie kontaktów/uprawnienia, jeśli wygoda nie jest warta powiązania, i dodawaj kontakty ręcznie tam, gdzie platforma to obsługuje.
6. Otwórz dane kontaktu i porównaj safety number/QR przez drugi kanał lub osobiście przed wysłaniem wrażliwej treści.
7. Sprawdź linked devices, registration lock/PIN, podglądy powiadomień, screen security, call relaying, domyślne ustawienia disappearing messages oraz zachowanie backupów.
8. Wyślij niewrażliwą wiadomość testową i zadzwoń. Po obu stronach sprawdź ślady na ekranie blokady, komputerze, urządzeniach wearable i w cloud notifications.
9. Traktuj zmieniony safety number lub nieoczekiwane linked device jako zdarzenie wymagające analizy, a nie alert, który należy automatycznie zignorować.

Nie łącz pseudonimowego zdjęcia profilowego, bio, członkostwa w grupach ani harmonogramu z identyfikującym kontekstem Signal.

## SimpleX: połączenia per-contact bez globalnego identyfikatora

SimpleX przekazuje wiadomości przez jednokierunkowe kolejki i nie przypisuje użytkownikowi identyfikatora obejmującego całą sieć. Jego własna polityka nadal opisuje sesje transportowe, tymczasowe dane serwera, kompromisy związane z powiadomieniami push oraz odpowiedzialność endpointu.<sup>[[3]](#references)</sup>

### Workflow

1. Pobierz utrzymywanego clienta z oficjalnego projektu/store i zweryfikuj wydawcę. Użyj dedykowanego profilu systemu/aplikacji, gdy tożsamości nie mogą się mieszać.
2. Utwórz **lokalny** profil z nazwą wyświetlaną i obrazem właściwymi dla danego kontekstu. Usunięcie aplikacji bez backupu może spowodować utratę profilu i połączeń.
3. Przy pierwszym uruchomieniu świadomie wybierz tryb powiadomień. Natychmiastowy mobile push może ujawnić dodatkowe metadane infrastrukturze Apple/Google.
4. Utwórz jednorazowy link zaproszenia dla jednego kontaktu. Przekaż go przez uwierzytelniony kanał; każdy, kto uzyska aktywne zaproszenie, może próbować z niego skorzystać.
5. Po połączeniu otwórz dane kontaktu i porównaj security code osobiście lub przez niezależny, zweryfikowany kanał.<sup>[[4]](#references)</sup>
6. Używaj obsługiwanego incognito per-group profile zamiast ponownie wykorzystywać ten sam profil w niezwiązanych grupach.
7. Skonfiguruj obsługiwany przez clienta transport Tor, jeśli lokalna sieć/serwer nie powinny widzieć bezpośredniego IP. Po zmianie potwierdź połączenie; nie wymuszaj nieobsługiwanego proxy systemowego.
8. Sprawdź delivery receipts, link previews, calls, automatyczne pobieranie oraz eksport/backup bazy danych. Każdy z tych elementów zmienia metadane lub ekspozycję endpointu.
9. Przetestuj odzyskiwanie na zapasowym, odizolowanym urządzeniu bez uruchamiania zduplikowanego aktywnego stanu profilu; projekt ostrzega, że równoczesne kopie mogą zakłócać rozmowy.

Brak globalnego identyfikatora nie uniemożliwia kontaktowi zidentyfikowania użytkownika na podstawie treści, ponownego użycia profilu, dostarczenia zaproszenia, czasu lub grafu społecznego.

## Briar: bezpośrednie i odporne na zakłócenia przesyłanie wiadomości

Briar synchronizuje się bezpośrednio między urządzeniami, przez Tor, gdy są online, oraz przez Bluetooth/Wi-Fi podczas lokalnych awarii. Oficjalny threat model zakłada jedynie ograniczone wrogie monitorowanie radia krótkiego zasięgu, więc lokalna komunikacja bezprzewodowa nie jest niewidoczna.<sup>[[5]](#references)</sup>

### Workflow

1. Zainstaluj Briar z oficjalnej dystrybucji i zweryfikuj źródło pakietu. Używaj obsługiwanego urządzenia Android z aktualnymi security updates.
2. Utwórz lokalne konto z unikalnym nickname właściwym dla kontekstu i silnym hasłem. Nie ma ścieżki resetowania hasła; sprawdź, czy secret odblokowujący można odzyskać.
3. Jeśli to możliwe, dodawaj kontakty osobiście, skanując wzajemnie swoje kody QR. Uwierzytelnia to kontakt i pozwala uniknąć wysyłania linku kanałem podatnym na korelację.
4. W ustawieniach connectivity włącz wyłącznie potrzebne transporty: Tor/Internet, Wi-Fi i/lub Bluetooth. Wyłącz lokalne radia, gdy nie są wymagane.
5. W przypadku asynchronicznego dostarczania rozważ Briar Mailbox na dedykowanym, zasilanym urządzeniu; zinwentaryzuj je i chroń fizycznie jak serwer wiadomości.
6. Wyślij nieszkodliwą wiadomość testową, gdy Internet jest dostępny, a następnie przetestuj zaplanowaną ścieżkę działania podczas awarii z wyłączonym Internetem w lokalizacji, do której masz uprawnienia.
7. Sprawdź Android backups, podglądy powiadomień, screenshots i wyeksportowaną treść. Lokalne zaszyfrowane storage jest ujawniane po odblokowaniu/naruszeniu endpointu.
8. Usuń utracone kontakty/urządzenia i wycofaj cały kontekst, jeśli naruszono fizyczne posiadanie urządzenia lub hasło konta.

## OnionShare: bezpośredni transfer tymczasowy

OnionShare uruchamia usługę onion na komputerze nadawcy/odbiorcy; pliki nie są przesyłane do dostawcy storage, a ruch jest szyfrowany end-to-end wewnątrz Tor.<sup>[[6]](#references)</sup> Pełny onion URL jest bearer capability i należy go chronić.

### GUI file-sharing workflow

1. Zainstaluj OnionShare z jego oficjalnej podpisanej dystrybucji oraz Tor Browser po stronie odbiorcy.
2. Umieść **oczyszczone kopie** plików w dedykowanym staging directory. Nie wskazuj OnionShare osobistego katalogu home.
3. Otwórz **Share Files**, dodaj wyłącznie pliki ze staging directory, pozostaw włączoną ochronę kluczem prywatnym/dostępem oraz ustawienie **Stop sharing after files have been sent** dla jednego odbiorcy.
4. Rozpocznij udostępnianie i prześlij pełny onion URL przez już uwierzytelniony kanał E2EE. Nie wklejaj go do emaila, issue trackerów ani publicznych chatów.
5. Odbiorca otwiera URL w Tor Browser, weryfikuje z nadawcą oczekiwane nazwy/rozmiary plików i pobiera je.
6. Obie strony porównują wcześniej uzgodniony lub dostarczony osobnym kanałem digest SHA-256 w celu zapewnienia integralności, gdy sam plik stanowi granicę bezpieczeństwa.
7. Potwierdź, że OnionShare zatrzymał się po pobraniu; w przeciwnym razie zatrzymaj go ręcznie i zamknij aplikację.
8. Usuń staging copy zgodnie z polityką retencji i sprawdź ustawienia historii/logów OnionShare pod kątem niezamierzonego ujawnienia nazw plików.

### CLI workflow

Oficjalny CLI przyjmuje pliki jako argumenty pozycyjne i zatrzymuje się po domyślnym pojedynczym zakończonym udostępnieniu. Na hoście z zainstalowanymi oficjalnymi CLI/Tor:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Bezpiecznie przekaż pełny wynikowy URL. Nie dodawaj `--public`, `--no-autostop-sharing`, szczegółowego logowania nazw plików ani persistence, chyba że model zagrożeń wyraźnie wymaga takiej ekspozycji.<sup>[[7]](#references)</sup>

Traktuj otrzymane dokumenty jako wrogie. Otwieraj je w jednorazowej maszynie wirtualnej lub rendererze w stylu Dangerzone, a nie na hoście zawierającym tożsamość.

## Niezależne szyfrowanie pliku za pomocą `age`

Szyfrowanie niezależne od transportu jest przydatne, gdy dostawca storage/email może uzyskać dostęp do obiektu. Nie ukrywa ono nadawcy, odbiorcy, rozmiaru, czasu ani nazwy pliku, chyba że te elementy zostaną obsłużone osobno.

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
Oficjalne CLI ostrzega, że `-o` nadpisuje istniejący output, dlatego użyj nowego katalogu i zweryfikuj digest/zawartość przed jego przeniesieniem.<sup>[[8]](#references)</sup> Nigdy nie wysyłaj pliku tożsamości razem z szyfrogramem.

## Powtarzalny pipeline oczyszczania plików

Usuwanie metadanych zależy od formatu. Zachowaj zaszyfrowany oryginał, gdy autentyczność, informatyka śledcza lub chain of custody ma znaczenie; pracuj na kopii.

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
Zgodnie z bezpieczniejszymi zaleceniami ExifTool dotyczącymi JPEG, bezmyślne usunięcie wszystkich tagów może również usunąć informacje o kolorach.<sup>[[9]](#references)</sup> Następnie wizualnie sprawdź piksele pod kątem twarzy, odbić, ekranów, charakterystycznych punktów oraz unikalnych wzorców uszkodzeń/szumu.

### Workflow dla Office/PDF

1. Zachowaj edytowalny oryginał w formie zaszyfrowanej i offline, poza kontekstem publikacji.
2. Usuń komentarze, śledzone zmiany, ukryte slajdy/arkusze, osadzone pliki, osobiste szablony oraz właściwości dokumentu w aplikacji użytej do tworzenia dokumentu.
3. Wyeksportuj nowy PDF z przeznaczonego do tego celu czystego profilu; nie „drukuj” do cloud printera.
4. Sprawdź dokument zarówno za pomocą narzędzi rozpoznających format, jak i jednorazowego wizualnego renderera:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Przeszukaj wyrenderowany wynik pod kątem nazw, ścieżek, adresów e-mail i tekstu rewizji. Rasteryzacja może usunąć aktywne struktury, ale pogarsza dostępność i możliwość wyszukiwania oraz nie usuwa widocznej zawartości ani stylu pisania.
6. Oblicz hash finalnego artefaktu i prześlij **wyłącznie** tę kopię przez przedział publikacyjny.

## Privacy Pass: anonimowa autoryzacja dla projektantów usług

Privacy Pass oddziela **wydawanie** tokenów od ich **realizacji**. Origin może dowiedzieć się, że klient posiada token zatwierdzony przez issuer, bez poznania konkretnej interakcji klienta związanej z wydaniem tokenu. Ponowne użycie tokenu, unikalne metadane, czas lub collusion mogą ponownie wprowadzić możliwość powiązania.<sup>[[10]](#references)</sup>

Bezpieczny wzorzec wdrożenia:

1. Zdefiniuj twierdzenie, które potwierdza token (na przykład uprawnienie do rate limitingu), a nie ukrytą globalną tożsamość.
2. Używaj standaryzowanej architektury i protokołów wydawania; nie implementuj kryptografii ślepych podpisów od podstaw.
3. Oddziel administrację issuer/attester i origin, jeśli wymaga tego oczekiwana właściwość.
4. Minimalizuj publiczne/prywatne metadane tokenów i upewnij się, że zbiory anonimowości są wystarczająco duże.
5. Jeśli jest to obsługiwane, wydawaj tokeny w partiach przed użyciem, aby czas wydania nie odpowiadał trywialnie czasowi realizacji.
6. Realizuj każdy token tylko raz, weryfikuj wyzwanie powiązane z origin i usuwaj stan wygasłych tokenów.
7. Nie pozwól, aby cookies, logowanie adresów IP i konta aplikacji po cichu niweczyły właściwość prywatności tokenu.
8. Sprawdź, czy logi issuer i origin mogą połączyć kontrolowane zdarzenie wydania i realizacji za pomocą czasu, metadanych lub unikalnych błędów.

Privacy Pass jest funkcją aplikacji, a nie czymś, co użytkownik może dodać do dowolnego konta.

## Lista kontrolna weryfikacji komunikacji

- [ ] Kontakt/zaproszenie/klucz został niezależnie uwierzytelniony.
- [ ] Zrozumiano ekspozycję numeru telefonu, nazwy użytkownika, profilu, grupy i przesyłania kontaktów.
- [ ] Wymieniono obserwatorów bezpośredniego IP, relay, Tor, dostawcy push i lokalnego radia.
- [ ] Przetestowano podglądy powiadomień, wearables, połączone komputery stacjonarne i backupy.
- [ ] Pliki zostały oczyszczone, w razie potrzeby zaszyfrowane i otwarte w kontekście jednorazowym.
- [ ] Odzyskiwanie działa bez łączenia niezwiązanych tożsamości.
- [ ] Dla logów, historii i tymczasowych usług udostępniania ustalono regułę wyłączania/przechowywania.

## References

- [1] [Signal — Prywatność numeru telefonu i nazwy użytkownika](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Polityka prywatności i warunki użytkowania](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Przewodnik po prywatności i bezpieczeństwie](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Jak to działa](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Projekt bezpieczeństwa](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Zaawansowane użycie i CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — Oficjalne CLI i użycie](https://github.com/FiloSottile/age)
- [9] [FAQ ExifTool — Bezpieczne usuwanie metadanych](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architektura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
