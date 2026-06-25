# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**Niestandardowy firmware i/lub skompilowane binaria mogą zostać przesłane, aby wykorzystać luki w integralności lub weryfikacji podpisu**. Następujące kroki można wykonać przy kompilacji backdoor bind shell:

1. Firmware można wyekstrahować za pomocą firmware-mod-kit (FMK).
2. Należy zidentyfikować architekturę i endianness docelowego firmware.
3. Cross compiler można zbudować przy użyciu Buildroot lub innych odpowiednich metod dla tego środowiska.
4. Backdoor można zbudować przy użyciu cross compiler.
5. Backdoor można skopiować do wyodrębnionego katalogu firmware /usr/bin.
6. Odpowiedni binarny plik QEMU można skopiować do wyodrębnionego rootfs firmware.
7. Backdoor można emulować przy użyciu chroot i QEMU.
8. Backdoor można uzyskać dostęp przez netcat.
9. Binarny plik QEMU należy usunąć z wyodrębnionego rootfs firmware.
10. Zmodyfikowany firmware można ponownie spakować przy użyciu FMK.
11. Firmware z backdoorem można przetestować, emulując go za pomocą firmware analysis toolkit (FAT) i łącząc się z docelowym adresem IP i portem backdoor przy użyciu netcat.

Jeśli shell root został już uzyskany przez dynamic analysis, manipulację bootloaderem lub hardware security testing, można uruchamiać wcześniej skompilowane złośliwe binaria, takie jak implanty lub reverse shells. Zautomatyzowane narzędzia do payload/implant, takie jak Metasploit framework i 'msfvenom', można wykorzystać, wykonując następujące kroki:

1. Należy zidentyfikować architekturę i endianness docelowego firmware.
2. Msfvenom można użyć do określenia docelowego payload, IP hosta atakującego, numeru portu nasłuchiwania, filetype, architektury, platformy oraz pliku wyjściowego.
3. Payload można przenieść na skompromitowane urządzenie i upewnić się, że ma uprawnienia do wykonania.
4. Metasploit można przygotować do obsługi przychodzących żądań, uruchamiając msfconsole i konfigurując ustawienia zgodnie z payload.
5. Reverse shell meterpreter można uruchomić na skompromitowanym urządzeniu.

## Uwierzytelnione mosty transportowe do uprzywilejowanych protokołów aktualizacji

Częstym błędem w projektowaniu embedded jest wystawienie **tego samego wewnętrznego protokołu komend przez kilka transportów** przy egzekwowaniu uwierzytelniania tylko na jednym z nich. Na przykład USB może wymagać challenge-response, podczas gdy BLE po prostu przekazuje nieuwierzytelnione **GATT writes** do tego samego uprzywilejowanego handlera aktualizacji firmware.

Typowy ofensywny workflow:

1. Wylicz bazę BLE GATT i zidentyfikuj zapisywalne characteristic używane przez oficjalną aplikację mobilną.
2. Podsłuchaj ruch aplikacji i szukaj **magic bytes / opcodes**, które pasują do przewodowego protokołu.
3. Odtwórz uprzywilejowane komendy przez BLE **bez pairing** i sprawdź, czy wrażliwe operacje nadal działają.
4. Jeśli opcode aktualizacji firmware, zapisu konfiguracji, debug lub testów fabrycznych są osiągalne, traktuj BLE jako **radio-reachable admin port**.

Szybkie sprawdzenia:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Rzeczy do sprawdzenia podczas reversing:

- Czy BLE wymaga **pairing/bonding** czy tylko zwykłego połączenia?
- Czy wszystkie transporty są kierowane do tej samej wewnętrznej tablicy dispatcher?
- Czy uprzywilejowane opcode są filtrowane inaczej na USB / BLE / UART / Wi-Fi?
- Czy mobile app może zdalnie wywołać firmware update, recovery lub diagnostic handlers?

## Kontenery firmware oparte tylko na checksum nadal są firmware kontrolowanym przez attacker

Kontener firmware chroniony wyłącznie przez **niekluczowany checksum** (CRC32, SHA-256, MD5, itd.) zapewnia wykrywanie uszkodzeń, a **nie authenticity**. Jeśli attacker może dotrzeć do procedury update, może zmodyfikować obraz, przeliczyć checksum i wgrać dowolny kod.

Czerwone flagi podczas RE:

- Kod update weryfikuje tylko końcowy blob checksum, taki jak `CHK2`, `CRC` lub `SHA256`.
- Brak weryfikacji signature lub root of trust secure-boot.
- Brak użycia MAC / HMAC / authenticated encryption powiązanego z urządzeniem.
- Recovery mode akceptuje ten sam nieautentykowany format obrazu.

Praktyczny flow walidacji:

1. Wyodrębnij kontener firmware i zidentyfikuj bootloader, główny firmware oraz metadane integralności.
2. Zmień nieszkodliwy string lub banner w obrazie.
3. Przelicz checksum dokładnie tak, jak oczekuje updater.
4. Wgraj obraz ponownie przez normalny path update.
5. Potwierdź zmianę przy boot, aby wykazać dowolną podmianę firmware.

Jeśli działa to przez zdalnie osiągalny transport, taki jak BLE/Wi-Fi, błąd jest w praktyce **unauthenticated OTA firmware replacement**.

## Zamiana zaufanego peryferium USB w BadUSB przez reflashing firmware

Gdy urządzenie docelowe jest już zaufane przez host przez USB, złośliwy firmware może nie potrzebować implementować pełnego nowego USB stack. Często znacznie łatwiejszym pivotem jest **reuse istniejącego wsparcia HID**.

Przydatny pattern:

1. Sprawdź, czy urządzenie już enumeruje jako interfejs **HID Consumer Control** / media / vendor HID.
2. Zlokalizuj istniejący **HID report descriptor** w firmware.
3. Dołącz lub zastąp wpisy descriptor tak, aby urządzenie reklamowało też możliwość działania jako **keyboard**.
4. Ponownie użyj istniejących rutyn firmware, które już wysyłają HID reports, zamiast pisać nową implementację transportu.
5. Wstrzykuj raporty key press + key release, aby wpisywać komendy na hoście.

To zamienia compromise firmware w **host compromise**, ponieważ PC będzie ufał przeflashowanemu peryferium jako legalnej klawiaturze.

### Minimalna checklista oceny

- Czy `dmesg`, Device Manager lub USB descriptors pokazują istniejący interfejs HID?
- Czy jest wolne miejsce przy report descriptor albo relokowalna tablica descriptor?
- Czy istniejące rutyny wysyłania media-control mogą być użyte ponownie do raportów keyboard?
- Czy host automatycznie akceptuje nowy interfejs keyboard po reflashing?

## Niezawodne wykonanie payload wewnątrz firmware RTOS

Zamiast wstawiać kruche trampoline w losowe ścieżki kodu, szukaj **istniejących tasków RTOS**, które są nieużywane albo mają niski wpływ podczas normalnej pracy.

Dlaczego to jest użyteczne:

- Scheduler uruchamia twój payload naturalnie podczas boot.
- Unikasz uszkadzania krytycznego flow sterowania.
- Opóźnione payloads rzadziej wywołują watchdog resets niż gdy działają wewnątrz handler USB/network wrażliwego na opóźnienia.

Dobre cele to taski diagnostyczne, factory-test, telemetry lub coprocessor service, które wydają się uśpione w normalnym użyciu.

## Szybka iteracja exploit: reuse benign protocol handlers

Gdy patching firmware jest możliwy, kompaktowym sposobem przyspieszenia RE jest nadpisanie nieszkodliwego command handlera (na przykład **echo/debug opcode**) własnymi prymitywami **memory read / write / execute**. Pozwala to uniknąć pełnego reflashing przy każdym eksperymencie i jest szczególnie przydatne, gdy urządzenie obsługuje zmodyfikowany handler przez szybki wired transport.

Użyj tego do:

- Weryfikacji scatter-loaded memory maps
- Podglądu stanu heap/task na żywo
- Testowania małych payloads przed zapisaniem ich do flash
- Bezpiecznego odzyskiwania function pointers, strings i descriptor tables

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
