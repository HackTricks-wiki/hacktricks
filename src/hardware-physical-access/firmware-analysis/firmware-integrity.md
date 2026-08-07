# Integralność firmware

{{#include ../../banners/hacktricks-training.md}}

**Niestandardowy firmware i/lub skompilowane binary mogą zostać wgrane w celu wykorzystania błędów integralności lub weryfikacji podpisu**. W celu skompilowania backdoored bind shell można wykonać następujące kroki:

1. Firmware można wyodrębnić za pomocą firmware-mod-kit (FMK).
2. Należy określić architekturę i kolejność bajtów docelowego firmware.
3. Można zbudować cross compiler za pomocą Buildroot lub innych odpowiednich metod dla danego środowiska.
4. Backdoor można zbudować za pomocą cross compilera.
5. Backdoor można skopiować do katalogu /usr/bin wyodrębnionego firmware.
6. Odpowiedni binary QEMU można skopiować do głównego systemu plików wyodrębnionego firmware.
7. Backdoor można emulować za pomocą chroot i QEMU.
8. Z backdoorem można połączyć się za pomocą netcat.
9. Binary QEMU należy usunąć z głównego systemu plików wyodrębnionego firmware.
10. Zmodyfikowany firmware można ponownie spakować za pomocą FMK.
11. Backdoored firmware można przetestować, emulując go za pomocą firmware analysis toolkit (FAT) i łącząc się z docelowym adresem IP oraz portem backdoora za pomocą netcat.

Jeśli root shell został już uzyskany za pomocą analizy dynamicznej, manipulacji bootloaderem lub testów bezpieczeństwa sprzętu, można uruchomić wstępnie skompilowane złośliwe binary, takie jak implanty lub reverse shells. Zautomatyzowane narzędzia payload/implant, takie jak framework Metasploit i 'msfvenom', można wykorzystać za pomocą następujących kroków:

1. Należy określić architekturę i kolejność bajtów docelowego firmware.
2. Msfvenom może zostać użyty do określenia docelowego payloadu, adresu IP hosta atakującego, numeru portu nasłuchującego, typu pliku, architektury, platformy i pliku wyjściowego.
3. Payload można przesłać na zaatakowane urządzenie i upewnić się, że ma uprawnienia do wykonywania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payloadem.
5. Na zaatakowanym urządzeniu można uruchomić meterpreter reverse shell.

## Nieuwierzytelnione mosty transportowe do uprzywilejowanych protokołów aktualizacji

Częstym błędem w projektowaniu systemów embedded jest udostępnianie **tego samego wewnętrznego protokołu poleceń przez kilka transportów**, przy jednoczesnym wymuszaniu uwierzytelniania tylko w jednym z nich. Przykładowo USB może wymagać challenge-response, podczas gdy BLE po prostu przekazuje nieuwierzytelnione **zapisy GATT** do tego samego uprzywilejowanego handlera aktualizacji firmware.<sup>[[1]](#references)</sup>

Typowy workflow offensive:

1. Należy wyliczyć bazę danych BLE GATT i zidentyfikować zapisywalne characteristics używane przez oficjalną aplikację mobilną.
2. Należy przechwycić ruch aplikacji i poszukać **magic bytes / opcodes** odpowiadających protokołowi przewodowemu.
3. Należy odtworzyć uprzywilejowane polecenia przez BLE **bez parowania** i sprawdzić, czy wrażliwe operacje nadal działają.
4. Jeśli dostępne są opcodes aktualizacji firmware, zapisu konfiguracji, debugowania lub testów fabrycznych, BLE należy traktować jako **osiągalny drogą radiową port administracyjny**.

Szybkie kontrole:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Rzeczy do zweryfikowania podczas reversing:

- Czy BLE wymaga **pairing/bonding**, czy tylko zwykłego połączenia?
- Czy wszystkie transporty są kierowane do tej samej wewnętrznej tabeli dispatcherów?
- Czy uprzywilejowane opcodes są filtrowane inaczej przez USB / BLE / UART / Wi-Fi?
- Czy aplikacja mobilna może zdalnie wywołać firmware update, recovery lub diagnostic handlers?

## Kontenery firmware chronione wyłącznie przez checksum są nadal firmware kontrolowanym przez atakującego

Kontener firmware chroniony wyłącznie przez **niesygnowany checksum** (CRC32, SHA-256, MD5 itd.) zapewnia wykrywanie uszkodzeń, **nie autentyczność**. Jeśli atakujący może dotrzeć do update routine, może zmodyfikować obraz, ponownie obliczyć checksum i wgrać dowolny kod.<sup>[[1]](#references)</sup>

Czerwone flagi podczas RE:

- Kod aktualizacji weryfikuje wyłącznie końcowy blok checksum, taki jak `CHK2`, `CRC` lub `SHA256`.
- Brak signature verification lub secure-boot root of trust.
- Nie jest używany device-bound MAC / HMAC / authenticated encryption.
- Recovery mode akceptuje ten sam nieuwierzytelniony format obrazu.

Praktyczny przebieg walidacji:

1. Wyodrębnij kontener firmware i zidentyfikuj bootloader, główny firmware oraz metadane integralności.
2. Zmodyfikuj nieszkodliwy string lub banner w obrazie.
3. Ponownie oblicz checksum dokładnie tak, jak oczekuje tego updater.
4. Wgraj obraz ponownie przez standardową ścieżkę aktualizacji.
5. Potwierdź zmianę podczas bootowania, aby dowieść możliwości dowolnej podmiany firmware.

Jeśli działa to przez zdalnie dostępny transport, taki jak BLE/Wi-Fi, błąd jest w praktyce **nieuwierzytelnioną zamianą firmware OTA**.

## Zmiana zaufanego urządzenia peryferyjnego USB w BadUSB przez reflashing firmware

Gdy urządzenie docelowe jest już zaufane przez hosta za pośrednictwem USB, złośliwy firmware może nie wymagać implementacji całego nowego stosu USB. Znacznie łatwiejszym pivotem jest często **ponowne użycie istniejącego wsparcia HID**.<sup>[[1]](#references)</sup>

Przydatny schemat:

1. Sprawdź, czy urządzenie już enumeruje się jako interfejs **HID Consumer Control** / media / vendor HID.
2. Znajdź istniejący **HID report descriptor** w firmware.
3. Dodaj lub zastąp wpisy descriptora, aby urządzenie reklamowało również obsługę **keyboard**.
4. Ponownie użyj istniejących routines firmware, które już wysyłają HID reports, zamiast pisać nową implementację transportu.
5. Wstrzykuj reports naciśnięcia + zwolnienia klawiszy, aby wpisywać polecenia na hoście.

Zamienia to compromise firmware w **compromise hosta**, ponieważ PC zaufa przeprogramowanemu urządzeniu peryferyjnemu jako prawidłowej klawiaturze.

### Minimalna checklista oceny

- Czy `dmesg`, Device Manager lub descriptors USB pokazują istniejący interfejs HID?
- Czy w pobliżu report descriptora lub relokowalnej tabeli descriptorów jest wolne miejsce?
- Czy istniejące routines wysyłające media-control można ponownie wykorzystać dla keyboard reports?
- Czy host automatycznie zaakceptuje nowy interfejs keyboard po reflashing?

## Niezawodne wykonywanie payloadu wewnątrz firmware RTOS

Zamiast wstawiać kruche trampolines w przypadkowe ścieżki kodu, szukaj **istniejących zadań RTOS**, które są nieużywane lub mają niewielki wpływ podczas normalnej pracy.<sup>[[1]](#references)</sup>

Dlaczego jest to przydatne:

- Scheduler naturalnie uruchamia payload podczas bootowania.
- Unikasz uszkodzenia krytycznego control flow.
- Opóźnione payloady rzadziej wywołują watchdog resets niż w przypadku uruchamiania ich wewnątrz wrażliwego na opóźnienia handlera USB/network.

Dobrymi celami są zadania diagnostyczne, factory-test, telemetryczne lub coprocessor service tasks, które podczas normalnego użycia wydają się nieaktywne.

## Szybka iteracja exploitów: ponowne wykorzystanie nieszkodliwych protocol handlers

Gdy patchowanie firmware jest możliwe, zwięzłym sposobem na przyspieszenie RE jest nadpisanie nieszkodliwego command handlera (na przykład **echo/debug opcode**) własnymi primitives **memory read / write / execute**. Eliminuje to konieczność pełnego reflashing przy każdym eksperymencie i jest szczególnie przydatne, gdy urządzenie obsługuje zmodyfikowany handler przez szybki transport przewodowy.<sup>[[1]](#references)</sup>

Wykorzystaj to do:

- Weryfikowania scatter-loaded memory maps
- Live inspekcji stanu heap/task
- Testowania małych payloadów przed zapisaniem ich w flash
- Bezpiecznego odzyskiwania function pointers, stringów i descriptor tables

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
