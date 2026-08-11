# Цілісність прошивки

{{#include ../../banners/hacktricks-training.md}}

Якщо під час авторизованої оцінки виявлено слабку або відсутню перевірку підпису прошивки, модифікований образ прошивки може продемонструвати вплив на її цілісність. Наведений нижче лабораторний workflow додає bind shell, зберігаючи оригінальні кроки видобування, емуляції та перепакування.<sup>[[2]](#references)[[3]](#references)</sup>

1. Прошивку можна видобути за допомогою firmware-mod-kit (FMK).
2. Необхідно визначити архітектуру та endianness цільової прошивки.
3. За допомогою Buildroot або інших відповідних методів для цього середовища можна зібрати cross compiler.
4. Backdoor можна зібрати за допомогою cross compiler.
5. Backdoor можна скопіювати до каталогу /usr/bin видобутої прошивки.
6. Відповідний бінарний файл QEMU можна скопіювати до rootfs видобутої прошивки.
7. Backdoor можна емулювати за допомогою chroot і QEMU.
8. Доступ до backdoor можна отримати через netcat.
9. Бінарний файл QEMU слід видалити з rootfs видобутої прошивки.
10. Модифіковану прошивку можна перепакувати за допомогою FMK.
11. Прошивку з backdoor можна протестувати, емулювавши її за допомогою firmware analysis toolkit (FAT) і підключившись до IP-адреси та порту цільового backdoor через netcat.

Якщо root shell уже отримано за допомогою dynamic analysis, маніпуляцій із bootloader або тестування hardware security, можна виконати попередньо скомпільовані тестові бінарні файли, такі як implants або reverse shells. `msfvenom` у Metasploit може згенерувати payload для певної архітектури в межах цього workflow перевірки:<sup>[[4]](#references)</sup>

1. Необхідно визначити архітектуру та endianness цільової прошивки.
2. Msfvenom можна використати для визначення цільового payload, IP-адреси хоста атакуючого, номера порту для прослуховування, типу файлу, архітектури, платформи та вихідного файлу.
3. Payload можна передати на скомпрометований пристрій і перевірити, що він має права на виконання.
4. Metasploit можна підготувати для обробки вхідних запитів, запустивши msfconsole і налаштувавши параметри відповідно до payload.
5. Reverse shell meterpreter можна виконати на скомпрометованому пристрої.

## Неавтентифіковані транспортні мости до привілейованих протоколів оновлення

Поширеною помилкою в дизайні embedded-пристроїв є передавання **того самого внутрішнього командного протоколу через кілька транспортів**, але застосування автентифікації лише на одному з них. Наприклад, USB може вимагати challenge-response, тоді як BLE просто пересилає неавтентифіковані **GATT writes** до того самого привілейованого обробника оновлення прошивки.<sup>[[1]](#references)</sup>

Типовий offensive workflow:

1. Перелічити BLE GATT database та визначити writable characteristics, які використовує офіційний mobile app.
2. Перехопити app traffic і пошукати **magic bytes / opcodes**, що відповідають дротовому протоколу.
3. Повторно передати привілейовані команди через BLE **без pairing** і перевірити, чи продовжують працювати чутливі операції.
4. Якщо доступні opcodes для оновлення прошивки, запису конфігурації, debug або factory-test, розглядати BLE як **admin port, доступний через радіоканал**.

Швидкі перевірки:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Що слід перевірити під час reverse engineering:

- Чи потребує BLE **pairing/bonding**, чи достатньо звичайного підключення?
- Чи всі transport-и маршрутизуються до однієї внутрішньої таблиці dispatcher-а?
- Чи фільтруються privileged opcodes по-різному через USB / BLE / UART / Wi-Fi?
- Чи може mobile app віддалено запускати firmware update, recovery або diagnostic handlers?

## Checksum-only firmware containers are still attacker-controlled firmware

Firmware container, захищений лише **unkeyed checksum** (CRC32, SHA-256, MD5 тощо), забезпечує виявлення пошкоджень, **але не автентичність**. Якщо attacker може отримати доступ до update routine, він може змінити image, повторно обчислити checksum і прошити довільний код.<sup>[[1]](#references)</sup>

Червоні прапорці під час RE:

- Update code перевіряє лише кінцевий checksum blob, наприклад `CHK2`, `CRC` або `SHA256`.
- Відсутня перевірка signature або secure-boot root of trust.
- Не використовується device-bound MAC / HMAC / authenticated encryption.
- Recovery mode приймає той самий неавтентифікований формат image.

Практичний процес перевірки:

1. Витягніть firmware container і визначте bootloader, main firmware та integrity metadata.
2. Змініть нешкідливий рядок або banner в image.
3. Повторно обчисліть checksum точно так, як цього очікує updater.
4. Повторно прошийте image через звичайний update path.
5. Підтвердьте зміну під час boot, щоб довести можливість довільної заміни firmware.

Якщо це працює через remotely reachable transport, наприклад BLE/Wi-Fi, помилка фактично є **unauthenticated OTA firmware replacement**.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Коли target device уже є trusted для host через USB, malicious firmware може не потребувати реалізації повного нового USB stack. Значно простішим pivot часто є **повторне використання наявної HID support**.<sup>[[1]](#references)</sup>

Корисний підхід:

1. Перевірте, чи вже визначається device як **HID Consumer Control** / media / vendor HID interface.
2. Знайдіть наявний **HID report descriptor** у firmware.
3. Додайте або замініть entries descriptor-а, щоб device також оголошував **keyboard** capability.
4. Повторно використайте наявні firmware routines, які вже надсилають HID reports, замість написання нової transport implementation.
5. Інжектуйте reports натискання + відпускання клавіш, щоб вводити команди на host.

Це перетворює compromise firmware на **compromise host**, оскільки PC довірятиме перепрошитому peripheral як легітимній keyboard.

### Minimal assessment checklist

- Чи показують `dmesg`, Device Manager або USB descriptors наявний HID interface?
- Чи є вільне місце поблизу report descriptor або relocatable descriptor table?
- Чи можна повторно використати наявні media-control send routines для keyboard reports?
- Чи host автоматично приймає новий keyboard interface після reflashing?

## Reliable payload execution inside RTOS firmware

Замість вставлення fragile trampolines у випадкові code paths шукайте **наявні RTOS tasks**, які не використовуються або мають низький вплив під час нормальної роботи.<sup>[[1]](#references)</sup>

Чому це корисно:

- Scheduler природним чином запускає ваш payload під час boot.
- Ви уникаєте пошкодження critical control flow.
- Delayed payloads із меншою ймовірністю спричинять watchdog resets, ніж під час виконання всередині latency-sensitive USB/network handler.

Хорошими targets є diagnostic, factory-test, telemetry або coprocessor service tasks, які виглядають dormant під час звичайного використання.

## Fast exploit iteration: repurpose benign protocol handlers

Коли patching firmware можливий, компактний спосіб прискорити RE — перезаписати нешкідливий command handler (наприклад **echo/debug opcode**) власними **memory read / write / execute** primitives. Це усуває потребу в повному reflashing для кожного експерименту й особливо корисно, коли device підтримує змінений handler через fast wired transport.<sup>[[1]](#references)</sup>

Використовуйте це, щоб:

- Перевіряти scatter-loaded memory maps
- У реальному часі інспектувати heap/task state
- Тестувати невеликі payloads перед записом у flash
- Безпечно відновлювати function pointers, strings і descriptor tables

## References

- [1] [Pwnd Blaster: Hacking вашого PC за допомогою speaker, не торкаючись його](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Як використовувати `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
