# Integralność firmware

{{#include ../../banners/hacktricks-training.md}}

Gdy autoryzowana ocena wykryje słabą lub brakującą weryfikację podpisu firmware, zmodyfikowany obraz firmware może wykazać wpływ na integralność. Poniższy workflow laboratoryjny dodaje bind shell, zachowując oryginalne kroki ekstrakcji, emulacji i przepakowywania.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware można wyodrębnić za pomocą firmware-mod-kit (FMK).
2. Należy zidentyfikować architekturę i endianowość docelowego firmware.
3. Cross compiler można zbudować za pomocą Buildroot lub innych odpowiednich metod dla danego środowiska.
4. Backdoor można zbudować za pomocą cross compilera.
5. Backdoor można skopiować do katalogu /usr/bin wyodrębnionego firmware.
6. Odpowiedni plik binarny QEMU można skopiować do głównego systemu plików wyodrębnionego firmware.
7. Backdoor można emulować za pomocą chroot i QEMU.
8. Z backdoorem można połączyć się za pomocą netcat.
9. Plik binarny QEMU należy usunąć z głównego systemu plików wyodrębnionego firmware.
10. Zmodyfikowany firmware można przepakować za pomocą FMK.
11. Backdoored firmware można przetestować, emulując go za pomocą firmware analysis toolkit (FAT) i łącząc się z docelowym adresem IP oraz portem backdoora za pomocą netcat.

Jeśli root shell został już uzyskany za pomocą analizy dynamicznej, manipulacji bootloaderem lub testów bezpieczeństwa sprzętu, można uruchomić wstępnie skompilowane binaria testowe, takie jak implanty lub reverse shells. `msfvenom` z Metasploit może wygenerować payload specyficzny dla danej architektury na potrzeby tego workflow walidacyjnego:<sup>[[4]](#references)</sup>

1. Należy zidentyfikować architekturę i endianowość docelowego firmware.
2. Msfvenom może zostać użyty do określenia docelowego payloadu, adresu IP hosta atakującego, numeru portu nasłuchującego, typu pliku, architektury, platformy i pliku wyjściowego.
3. Payload można przesłać na zaatakowane urządzenie i upewnić się, że ma uprawnienia do wykonywania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payloadem.
5. Reverse shell meterpretera można uruchomić na zaatakowanym urządzeniu.

## Nieuwierzytelnione mosty transportowe do uprzywilejowanych protokołów aktualizacji

Częstym błędem w projektowaniu systemów embedded jest udostępnianie **tego samego wewnętrznego protokołu poleceń przez kilka transportów**, przy egzekwowaniu uwierzytelniania tylko w jednym z nich. Na przykład USB może wymagać challenge-response, podczas gdy BLE po prostu przekazuje nieuwierzytelnione **zapisy GATT** do tego samego uprzywilejowanego handlera aktualizacji firmware.<sup>[[1]](#references)</sup>

Typowy workflow ofensywny:

1. Wylicz bazę danych BLE GATT i zidentyfikuj zapisywalne charakterystyki używane przez oficjalną aplikację mobilną.
2. Przechwyć ruch aplikacji i poszukaj **magic bytes / opcode'ów**, które pasują do protokołu przewodowego.
3. Odtwórz uprzywilejowane polecenia przez BLE **bez parowania** i sprawdź, czy wrażliwe operacje nadal działają.
4. Jeśli dostępne są opcode'y aktualizacji firmware, zapisu konfiguracji, debugowania lub testów fabrycznych, potraktuj BLE jako **osiągalny radiowo port administracyjny**.

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

- Czy BLE wymaga **pairing/bonding**, czy tylko zwykłego połączenia?
- Czy wszystkie transporty są kierowane do tej samej wewnętrznej tabeli dispatcherów?
- Czy uprzywilejowane opcodes są filtrowane w różny sposób przez USB / BLE / UART / Wi-Fi?
- Czy aplikacja mobilna może zdalnie uruchomić firmware update, recovery lub handlery diagnostyczne?

## Kontenery firmware oparte wyłącznie na checksumach są nadal firmware kontrolowanym przez atakującego

Kontener firmware chroniony wyłącznie przez **niekluczowany checksum** (CRC32, SHA-256, MD5 itd.) zapewnia wykrywanie uszkodzeń, **ale nie autentyczność**. Jeśli atakujący może uzyskać dostęp do procedury aktualizacji, może zmodyfikować obraz, ponownie obliczyć checksum i wgrać dowolny kod.<sup>[[1]](#references)</sup>

Czerwone flagi podczas RE:

- Kod aktualizacji weryfikuje wyłącznie końcowy blob checksum, taki jak `CHK2`, `CRC` lub `SHA256`.
- Brak weryfikacji podpisu lub root of trust dla secure boot.
- Nie jest używany device-bound MAC / HMAC / authenticated encryption.
- Tryb recovery akceptuje ten sam nieuwierzytelniony format obrazu.

Praktyczny przebieg walidacji:

1. Wyodrębnij kontener firmware i zidentyfikuj bootloader, główny firmware oraz metadane integralności.
2. Zmodyfikuj nieszkodliwy string lub banner w obrazie.
3. Ponownie oblicz checksum dokładnie w sposób oczekiwany przez updater.
4. Wgraj obraz ponownie przez standardową ścieżkę aktualizacji.
5. Potwierdź zmianę podczas bootowania, aby dowieść możliwości dowolnej podmiany firmware.

Jeśli działa to przez zdalnie dostępny transport, taki jak BLE/Wi-Fi, błąd jest w praktyce **nieuwierzytelnioną podmianą firmware OTA**.

## Zmiana zaufanego urządzenia peryferyjnego USB w BadUSB przez reflashing firmware

Gdy urządzenie docelowe jest już zaufane przez hosta za pośrednictwem USB, złośliwy firmware może nie wymagać implementacji całego nowego stosu USB. Znacznie łatwiejszym pivotem jest często **ponowne wykorzystanie istniejącej obsługi HID**.<sup>[[1]](#references)</sup>

Przydatny schemat:

1. Sprawdź, czy urządzenie już enumeruje się jako interfejs **HID Consumer Control** / media / vendor HID.
2. Zlokalizuj istniejący **HID report descriptor** w firmware.
3. Dodaj lub zastąp wpisy descriptora, aby urządzenie reklamowało również możliwość działania jako **keyboard**.
4. Ponownie wykorzystaj istniejące rutyny firmware, które już wysyłają raporty HID, zamiast pisać nową implementację transportu.
5. Wstrzykuj raporty key press + key release, aby wpisywać komendy na hoście.

Zamienia to kompromitację firmware w **kompromitację hosta**, ponieważ PC zaufa przeprogramowanemu urządzeniu peryferyjnemu jako prawidłowej klawiaturze.

### Minimalna checklista oceny

- Czy `dmesg`, Device Manager lub descriptory USB pokazują istniejący interfejs HID?
- Czy w pobliżu report descriptora lub relokowalnej tabeli descriptorów jest wolne miejsce?
- Czy istniejące rutyny wysyłające sterowanie multimediami można ponownie wykorzystać do raportów klawiatury?
- Czy host automatycznie zaakceptuje nowy interfejs klawiatury po reflashing?

## Niezawodne wykonywanie payloadu wewnątrz firmware RTOS

Zamiast wstawiać kruche trampoliny w losowe ścieżki kodu, szukaj **istniejących zadań RTOS**, które są nieużywane lub mają niewielki wpływ podczas normalnego działania.<sup>[[1]](#references)</sup>

Dlaczego jest to przydatne:

- Scheduler uruchamia payload naturalnie podczas bootowania.
- Unikasz uszkodzenia krytycznego flow sterowania.
- Opóźnione payloady rzadziej wywołują resety watchdogu niż w przypadku uruchamiania ich wewnątrz wrażliwego czasowo handlera USB/network.

Dobrymi celami są zadania diagnostyczne, factory-test, telemetryczne lub obsługi coprocessora, które podczas normalnego użycia wydają się nieaktywne.

## Szybka iteracja exploita: ponowne wykorzystanie nieszkodliwych handlerów protokołu

Gdy patchowanie firmware jest możliwe, zwięzłym sposobem przyspieszenia RE jest nadpisanie nieszkodliwego command handlera (na przykład **echo/debug opcode**) własnymi prymitywami **memory read / write / execute**. Eliminuje to konieczność pełnego reflashing przy każdym eksperymencie i jest szczególnie przydatne, gdy urządzenie obsługuje zmodyfikowany handler przez szybki transport przewodowy.<sup>[[1]](#references)</sup>

Użyj tego, aby:

- Zweryfikować scatter-loaded memory maps
- Badać na żywo stan heap/task
- Testować małe payloady przed zapisaniem ich do flash
- Bezpiecznie odzyskiwać function pointers, stringi i tabele descriptorów

## References

- [1] [Pwnd Blaster: Hackowanie komputera za pomocą głośnika bez dotykania go](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
