# Цілісність firmware

{{#include ../../banners/hacktricks-training.md}}

**Custom firmware та/або скомпільовані бінарні файли можна завантажити для експлуатації вразливостей перевірки цілісності або підпису**. Для компіляції bind shell із backdoor можна виконати такі кроки:

1. Firmware можна витягти за допомогою firmware-mod-kit (FMK).
2. Необхідно визначити архітектуру та endianness цільової firmware.
3. За допомогою Buildroot або інших відповідних методів для цього середовища можна створити cross compiler.
4. Backdoor можна зібрати за допомогою cross compiler.
5. Backdoor можна скопіювати до директорії /usr/bin витягнутої firmware.
6. Відповідний бінарний файл QEMU можна скопіювати до rootfs витягнутої firmware.
7. Backdoor можна емулювати за допомогою chroot і QEMU.
8. Доступ до backdoor можна отримати через netcat.
9. Бінарний файл QEMU слід видалити з rootfs витягнутої firmware.
10. Модифіковану firmware можна перепакувати за допомогою FMK.
11. Backdoored firmware можна протестувати, емулювавши її за допомогою firmware analysis toolkit (FAT) і підключившись до IP-адреси та порту цільового backdoor через netcat.

Якщо root shell уже отримано за допомогою dynamic analysis, маніпуляцій із bootloader або hardware security testing, можна виконати попередньо скомпільовані malicious binaries, наприклад implants або reverse shells. Automated payload/implant tools, такі як Metasploit framework і 'msfvenom', можна використати за допомогою таких кроків:

1. Необхідно визначити архітектуру та endianness цільової firmware.
2. Msfvenom можна використати для визначення цільового payload, IP-адреси host атакувальника, номера порту для прослуховування, filetype, архітектури, платформи та вихідного файлу.
3. Payload можна передати на скомпрометований пристрій і переконатися, що він має права на виконання.
4. Metasploit можна підготувати для обробки вхідних запитів, запустивши msfconsole і налаштувавши параметри відповідно до payload.
5. Reverse shell meterpreter можна виконати на скомпрометованому пристрої.

## Неавтентифіковані transport bridges до privileged update protocols

Поширена помилка embedded design полягає у відкритті **того самого внутрішнього command protocol через кілька transport**, але автентифікація застосовується лише до одного з них. Наприклад, USB може вимагати challenge-response, тоді як BLE просто пересилає неавтентифіковані **GATT writes** до того самого privileged firmware-update handler.<sup>[[1]](#references)</sup>

Типовий offensive workflow:

1. Перерахувати BLE GATT database і визначити writable characteristics, які використовує офіційний mobile app.
2. Перехопити app traffic і знайти **magic bytes / opcodes**, що відповідають wired protocol.
3. Повторно надіслати privileged commands через BLE **без pairing** і перевірити, чи досі працюють sensitive operations.
4. Якщо доступні firmware upgrade, config write, debug або factory-test opcodes, розглядати BLE як **radio-reachable admin port**.

Швидкі перевірки:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Що потрібно перевірити під час reverse engineering:

- Чи потребує BLE **pairing/bonding**, чи достатньо звичайного з'єднання?
- Чи всі transport спрямовуються до однієї внутрішньої таблиці dispatcher?
- Чи фільтруються привілейовані opcodes по-різному через USB / BLE / UART / Wi-Fi?
- Чи може mobile app віддалено запускати firmware update, recovery або diagnostic handlers?

## Контейнери прошивки, захищені лише контрольною сумою, усе одно містять firmware під контролем attacker

Контейнер firmware, захищений лише **невмонтованою контрольною сумою** (CRC32, SHA-256, MD5 тощо), забезпечує виявлення пошкоджень, **але не автентичність**. Якщо attacker може отримати доступ до update routine, він може пропатчити image, повторно обчислити checksum і прошити довільний code.<sup>[[1]](#references)</sup>

Red flags під час RE:

- Update code перевіряє лише кінцевий checksum blob, наприклад `CHK2`, `CRC` або `SHA256`.
- Відсутня перевірка signature або root of trust для secure boot.
- Не використовується device-bound MAC / HMAC / authenticated encryption.
- Recovery mode приймає такий самий неавтентифікований формат image.

Практичний validation flow:

1. Витягніть firmware container і визначте bootloader, основну firmware та integrity metadata.
2. Змініть нешкідливий string або banner в image.
3. Повторно обчисліть checksum точно так, як очікує updater.
4. Прошийте image через звичайний update path.
5. Підтвердьте зміну під час boot, щоб довести можливість довільної заміни firmware.

Якщо це працює через remotely reachable transport, наприклад BLE/Wi-Fi, вразливість фактично є **unauthenticated OTA firmware replacement**.

## Перетворення довіреного USB peripheral на BadUSB через повторне прошивання firmware

Коли target device уже trusted host через USB, malicious firmware може не потребувати реалізації повного нового USB stack. Значно простішим pivot часто є **повторне використання наявної HID support**.<sup>[[1]](#references)</sup>

Корисний pattern:

1. Перевірте, чи вже enumerates device як **HID Consumer Control** / media / vendor HID interface.
2. Знайдіть наявний **HID report descriptor** у firmware.
3. Додайте або замініть descriptor entries, щоб device також оголошував **keyboard** capability.
4. Повторно використайте наявні firmware routines, які вже надсилають HID reports, замість написання нової transport implementation.
5. Інжектуйте key press + key release reports, щоб вводити commands на host.

Це перетворює firmware compromise на **host compromise**, оскільки PC довірятиме повторно прошитому peripheral як легітимній keyboard.

### Мінімальний assessment checklist

- Чи показують `dmesg`, Device Manager або USB descriptors наявний HID interface?
- Чи є вільне місце поруч із report descriptor або relocatable descriptor table?
- Чи можна повторно використати наявні media-control send routines для keyboard reports?
- Чи host автоматично приймає новий keyboard interface після повторного прошивання?

## Надійне виконання payload усередині RTOS firmware

Замість вставлення fragile trampolines у випадкові code paths шукайте **наявні RTOS tasks**, які не використовуються або мають низький вплив під час нормальної роботи.<sup>[[1]](#references)</sup>

Чому це корисно:

- Scheduler природно запускає ваш payload під час boot.
- Ви уникаєте пошкодження критичного control flow.
- Delayed payloads із меншою ймовірністю спричинять watchdog resets, ніж payloads, запущені всередині latency-sensitive USB/network handler.

Добрі targets — diagnostic, factory-test, telemetry або coprocessor service tasks, які виглядають dormant під час звичайного використання.

## Швидка ітерація exploit: повторне використання benign protocol handlers

Коли patching firmware можливе, компактний спосіб прискорити RE — перезаписати нешкідливий command handler (наприклад **echo/debug opcode**) власними примітивами **memory read / write / execute**. Це усуває потребу в повному reflashing для кожного експерименту й особливо корисно, коли device підтримує modified handler через fast wired transport.<sup>[[1]](#references)</sup>

Використовуйте це, щоб:

- Перевіряти scatter-loaded memory maps
- У реальному часі переглядати heap/task state
- Тестувати невеликі payloads перед їх записом у flash
- Безпечно відновлювати function pointers, strings і descriptor tables

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
