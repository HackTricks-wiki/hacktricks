# Integralność firmware'u

{{#include ../../banners/hacktricks-training.md}}

Gdy podczas autoryzowanego testu wykryta zostanie słaba lub brakująca weryfikacja podpisu firmware'u, zmodyfikowany obraz firmware'u może posłużyć do zademonstrowania wpływu na integralność. Poniższy workflow laboratoryjny dodaje bind shell, zachowując oryginalne kroki ekstrakcji, emulacji i ponownego pakowania.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware można wyodrębnić za pomocą firmware-mod-kit (FMK).
2. Należy określić architekturę i endianowość docelowego firmware'u.
3. Można zbudować cross compiler za pomocą Buildroot lub innej odpowiedniej metody dla danego środowiska.
4. Backdoor można zbudować za pomocą cross compilera.
5. Backdoor można skopiować do katalogu /usr/bin wyodrębnionego firmware'u.
6. Odpowiedni plik binarny QEMU można skopiować do katalogu głównego rootfs wyodrębnionego firmware'u.
7. Backdoor można emulować za pomocą chroot i QEMU.
8. Można połączyć się z backdoorem za pomocą netcat.
9. Należy usunąć plik binarny QEMU z katalogu głównego rootfs wyodrębnionego firmware'u.
10. Zmodyfikowany firmware można ponownie spakować za pomocą FMK.
11. Backdoored firmware można przetestować, emulując go za pomocą firmware analysis toolkit (FAT) i łącząc się z adresem IP oraz portem docelowego backdoora za pomocą netcat.

Jeśli uzyskano już root shell za pomocą analizy dynamicznej, manipulacji bootloaderem lub testów bezpieczeństwa sprzętu, można uruchomić wstępnie skompilowane binaria testowe, takie jak implanty lub reverse shelle. `msfvenom` z Metasploit może wygenerować payload dostosowany do architektury na potrzeby tego workflow walidacyjnego:<sup>[[4]](#references)</sup>

1. Należy określić architekturę i endianowość docelowego firmware'u.
2. Msfvenom można użyć do określenia docelowego payloadu, adresu IP hosta atakującego, numeru portu nasłuchującego, typu pliku, architektury, platformy i pliku wyjściowego.
3. Payload można przesłać na skompromitowane urządzenie i upewnić się, że ma uprawnienia do wykonywania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payloadem.
5. Na skompromitowanym urządzeniu można uruchomić reverse shell meterpreter.

## Nieuwierzytelnione mosty transportowe do uprzywilejowanych protokołów aktualizacji

Częstym błędem projektowym w urządzeniach wbudowanych jest udostępnianie **tego samego wewnętrznego protokołu poleceń przez kilka transportów**, przy jednoczesnym egzekwowaniu uwierzytelniania tylko w jednym z nich. Na przykład USB może wymagać uwierzytelniania typu challenge-response, podczas gdy BLE po prostu przekazuje nieuwierzytelnione **zapisy GATT** do tego samego uprzywilejowanego handlera aktualizacji firmware'u.<sup>[[1]](#references)</sup>

Typowy workflow ofensywny:

1. Wylicz bazę danych BLE GATT i zidentyfikuj zapisywalne charakterystyki używane przez oficjalną aplikację mobilną.
2. Przechwyć ruch aplikacji i poszukaj **magic bytes / opcode'ów** pasujących do protokołu przewodowego.
3. Odtwórz uprzywilejowane polecenia przez BLE **bez parowania** i sprawdź, czy wrażliwe operacje nadal działają.
4. Jeśli dostępne są opcode'y aktualizacji firmware'u, zapisu konfiguracji, debugowania lub testów fabrycznych, potraktuj BLE jako **osiągalny radiowo port administratora**.

Szybkie kontrole:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Rzeczy do zweryfikowania podczas reverse engineeringu:

- Czy BLE wymaga **pairing/bonding**, czy wystarczy zwykłe połączenie?
- Czy wszystkie transporty są kierowane do tej samej wewnętrznej tablicy dispatcherów?
- Czy uprzywilejowane opcode’y są filtrowane w różny sposób przez USB / BLE / UART / Wi-Fi?
- Czy aplikacja mobilna może zdalnie uruchomić aktualizację firmware, tryb recovery lub handlery diagnostyczne?

## Kontenery firmware chronione wyłącznie sumą kontrolną nadal zawierają firmware kontrolowany przez atakującego

Kontener firmware chroniony wyłącznie **niekluczowaną sumą kontrolną** (CRC32, SHA-256, MD5 itd.) wykrywa uszkodzenia, ale **nie potwierdza autentyczności**. Jeśli atakujący może uzyskać dostęp do procedury aktualizacji, może zmodyfikować obraz, ponownie obliczyć sumę kontrolną i wgrać dowolny kod.<sup>[[1]](#references)</sup>

Sygnały ostrzegawcze podczas RE:

- Kod aktualizacji weryfikuje wyłącznie końcowy blok sumy kontrolnej, taki jak `CHK2`, `CRC` lub `SHA256`.
- Brak weryfikacji podpisu lub root of trust bezpiecznego rozruchu.
- Nie jest używany MAC / HMAC powiązany z urządzeniem ani szyfrowanie uwierzytelnione.
- Tryb recovery akceptuje ten sam nieuwierzytelniony format obrazu.

Praktyczny proces walidacji:

1. Wyodrębnij kontener firmware i zidentyfikuj bootloader, główne firmware oraz metadane integralności.
2. Zmodyfikuj nieszkodliwy ciąg znaków lub baner w obrazie.
3. Ponownie oblicz sumę kontrolną dokładnie tak, jak oczekuje tego updater.
4. Wgraj obraz ponownie zwykłą ścieżką aktualizacji.
5. Potwierdź zmianę po uruchomieniu, aby wykazać możliwość zastąpienia firmware dowolnym obrazem.

Jeśli działa to przez zdalnie dostępny transport, taki jak BLE/Wi-Fi, błąd w praktyce umożliwia **nieuwierzytelnioną wymianę firmware OTA**.

## Fragmentowany stan aktualizacji i zapisywalne metadane integralności

Updater może weryfikować podpisany nagłówek firmware podczas instalacji, ale mimo to uruchamiać obrazy, sprawdzając jedynie zapisaną sumę kontrolną. W urządzeniu Cypherock X1 Bootloader wywoływał oddzielne zadania Firewall, które weryfikowały nagłówek i umieszczały wersję/rozmiar w RAM, zapisywały podpis firmware w RAM, weryfikowały zapisany obraz, a na końcu obliczały hash obrazu i zapisywały go w trwałych danych Primary Bootloader Data. Sam podpis nie był zapisywany na stałe. Zadania te można było wywoływać niezależnie, zamiast wymuszać jedną uwierzytelnioną transakcję aktualizacji.<sup>[[5]](#references)</sup>

Mając możliwość wykonywania kodu MCU i zapisu do Flash, atakujący zmodyfikował obraz aplikacji, zmienił wartości wersji/rozmiaru w RAM Bootloadera współdzielonym z Firewall, a następnie wywołał końcowe zadanie metadanych, aby zapisać hash złośliwego obrazu i przywrócić zwykły stan rozruchu. Standardowa kontrola integralności przy uruchamianiu zaakceptowała ten hash bez ponownej weryfikacji podpisu. Analizując podobny updater, sprawdź, **który komponent może wywołać każde zadanie**, gdzie przechowywane są zweryfikowane wartości oraz czy decyzja podejmowana podczas rozruchu uwierzytelnia *ten sam obraz*, którego hash jest zapisany. To węższy problem niż format obrazu chroniony wyłącznie sumą kontrolną: weryfikacja podpisu istniała, ale nie była powiązana ze zmianą stanu.<sup>[[5]](#references)</sup>

## Podpisy secure element dla niezaufanych pomiarów firmware

Secure element nie poświadcza uruchomionego kodu tylko dlatego, że podpisuje hash dostarczony przez ten kod. W tym samym portfelu secure element podpisywał numer seryjny urządzenia, a następnie wynik XOR nonce z chmury i hasha firmware przekazanego przez MCU. Naruszone firmware mogło przedstawić do podpisania oczekiwany hash, jednocześnie wykonując inny kod. Aplikacja kliencka przesyłała też wersję firmware do chmury, więc porównanie z oczekiwanym hashem przez weryfikator nadal opierało się na pomiarze pochodzącym z MCU, a nie na niezależnym odczycie Flash.<sup>[[5]](#references)</sup>

Wynik po stronie urządzenia tworzył odrębną granicę zaufania: chmura sprawdzała urządzenie, ale urządzenie nie uwierzytelniało werdyktu chmury. Zmodyfikowany klient mógł zgłosić lokalny sukces na zmodyfikowanym urządzeniu. Sprawdź osobno pochodzenie pomiaru i uwierzytelnianie odpowiedzi; prawidłowy podpis secure element i ekran z informacją o sukcesie same w sobie nie dowodzą, że zainstalowana aplikacja jest autentyczna.<sup>[[5]](#references)</sup>

Informacje o ujawnieniu chronionego kodu, które umożliwiło analizę tego updatera, znajdziesz w sekcji [Pozyskiwanie firmware przez zadanie kopiujące Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Zmiana zaufanego urządzenia peryferyjnego USB w BadUSB przez ponowne wgranie firmware

Jeśli urządzenie docelowe jest już zaufane przez hosta przez USB, złośliwe firmware może nie wymagać implementacji całego nowego stosu USB. Znacznie prostszym rozwiązaniem jest często **ponowne wykorzystanie istniejącej obsługi HID**.<sup>[[1]](#references)</sup>

Przydatny schemat działania:

1. Sprawdź, czy urządzenie jest już wykrywane jako interfejs **HID Consumer Control** / media / vendor HID.
2. Znajdź istniejący **deskryptor raportu HID** w firmware.
3. Dodaj lub zastąp wpisy deskryptora, aby urządzenie zgłaszało również obsługę **klawiatury**.
4. Wykorzystaj istniejące procedury firmware, które już wysyłają raporty HID, zamiast pisać nową implementację transportu.
5. Wysyłaj raporty wciśnięcia i zwolnienia klawiszy, aby wpisywać polecenia na hoście.

W ten sposób przejęcie firmware prowadzi do **przejęcia hosta**, ponieważ komputer ufa przeprogramowanemu urządzeniu peryferyjnemu jako prawidłowej klawiaturze.

### Minimalna lista kontrolna oceny

- Czy `dmesg`, Device Manager lub deskryptory USB pokazują istniejący interfejs HID?
- Czy w pobliżu deskryptora raportu jest wolne miejsce albo czy tabela deskryptorów może być przeniesiona?
- Czy istniejące procedury wysyłania zdarzeń sterujących multimediami można wykorzystać do raportów klawiatury?
- Czy host automatycznie zaakceptuje nowy interfejs klawiatury po ponownym wgraniu firmware?

## Niezawodne wykonywanie payloadu w firmware RTOS

Zamiast wstawiać kruche trampoliny w losowe ścieżki kodu, poszukaj **istniejących zadań RTOS**, które w normalnym działaniu są nieużywane lub mają niewielki wpływ.<sup>[[1]](#references)</sup>

Dlaczego to przydatne:

- Scheduler naturalnie uruchamia payload podczas rozruchu.
- Unikasz uszkodzenia krytycznego przepływu sterowania.
- Opóźnione payloady rzadziej powodują reset watchdog niż payloady uruchamiane we wrażliwym czasowo handlerze USB/sieciowym.

Dobrymi celami są zadania diagnostyczne, testów fabrycznych, telemetryczne lub obsługujące koprocesor, które w normalnym użyciu wydają się nieaktywne.

## Szybkie iterowanie exploitów: ponowne wykorzystanie nieszkodliwych handlerów protokołu

Gdy modyfikowanie firmware jest już możliwe, zwięzłym sposobem na przyspieszenie RE jest zastąpienie nieszkodliwego handlera poleceń (na przykład **opcode’u echo/debug**) własnymi prymitywami **odczytu / zapisu / wykonywania pamięci**. Pozwala to uniknąć ponownego wgrywania firmware przy każdym eksperymencie i jest szczególnie przydatne, gdy urządzenie obsługuje zmodyfikowany handler przez szybki transport przewodowy.<sup>[[1]](#references)</sup>

Wykorzystaj to do:

- Weryfikowania map pamięci ładowanych rozproszonymi obszarami
- Sprawdzania na żywo stanu sterty i zadań
- Testowania małych payloadów przed zapisaniem ich w flash
- Bezpiecznego odzyskiwania wskaźników do funkcji, ciągów znaków i tabel deskryptorów

## References

- [1] [Pwnd Blaster: Hakowanie komputera za pomocą głośnika, bez dotykania go](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [zestaw narzędzi firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Zestaw narzędzi do analizy firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit — jak używać `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Jak i dlaczego zhakowaliśmy portfel sprzętowy Cypherock: pełna historia](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
