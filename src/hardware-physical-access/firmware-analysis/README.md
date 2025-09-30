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


Прошивка — це необхідне програмне забезпечення, яке дозволяє пристроям працювати коректно, керуючи й полегшуючи обмін між апаратними компонентами та програмним забезпеченням, з яким взаємодіють користувачі. Вона зберігається в постійній пам'яті, що гарантує пристрою доступ до важливих інструкцій з моменту його ввімкнення та забезпечує запуск операційної системи. Аналіз і, за потреби, модифікація прошивки — критично важливий крок у виявленні вразливостей безпеки.

## **Збирання інформації**

**Збирання інформації** — ключовий початковий етап для розуміння складу пристрою та технологій, які він використовує. Цей процес включає збір даних про:

- Архітектуру CPU та операційну систему, яку він запускає
- Особливості завантажувача (bootloader)
- Аппаратну схему та datasheets
- Метрики кодової бази та місця розташування вихідного коду
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень та регуляторні сертифікати
- Архітектурні діаграми та діаграми потоків
- Оцінки безпеки та виявлені вразливості

Для цього незамінні інструменти open-source intelligence (OSINT), а також аналіз будь-яких доступних компонентів open-source програмного забезпечення вручну та автоматизованими методами. Інструменти, такі як [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore), пропонують безкоштовний статичний аналіз, який можна використовувати для виявлення потенційних проблем.

## **Отримання прошивки**

Отримання прошивки можна здійснити різними способами, кожен з яких має свій рівень складності:

- **Безпосередньо** від джерела (розробники, виробники)
- **Збираючи** її за наданими інструкціями
- **Завантаження** з офіційних сайтів підтримки
- Використовуючи запити **Google dork** для пошуку розміщених файлів прошивки
- Прямий доступ до **cloud storage**, з використанням інструментів на кшталт [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплення **updates** за допомогою технік man-in-the-middle
- **Екстракція** з пристрою через роз'єми, такі як **UART**, **JTAG** або **PICit**
- **Sniffing** запитів оновлення в комунікаціях пристрою
- Виявлення та використання **hardcoded update endpoints**
- **Dumping** з завантажувача або мережі
- **Витяг і читання** чіпа пам'яті, коли інші способи не допомагають, з використанням відповідних апаратних інструментів

## Аналіз прошивки

Тепер, коли ви **маєте прошивку**, потрібно витягти з неї інформацію, щоб знати, як працювати з нею. Різні інструменти, які можна для цього використовувати:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо ви не знайдете багато за допомогою цих інструментів, перевірте **ентропію** образу за допомогою `binwalk -E <bin>`: якщо ентропія низька — швидше за все він не зашифрований. Якщо ентропія висока — ймовірно зашифрований (або якось стиснутий).

Крім того, ви можете використовувати ці інструменти для витягання **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) щоб переглянути файл.

### Отримання файлової системи

За допомогою згаданих вище інструментів, таких як `binwalk -ev <bin>`, ви повинні були змогти **витягти файлову систему**.\
Binwalk зазвичай розпаковує її всередині **папки з назвою типу файлової системи**, яка зазвичай є однією з наступних: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ручне вилучення файлової системи

Іноді binwalk **не матиме magic byte файлової системи у своїх сигнатурах**. У таких випадках використовуйте binwalk, щоб **знайти offset файлової системи та carve стиснену файлову систему** з бінарного файлу і **вручну витягнути** файлову систему відповідно до її типу, використовуючи кроки нижче.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть наступну **dd command** carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Як альтернативу, можна також виконати наступну команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використаного в прикладі вище)

`$ unsquashfs dir.squashfs`

Файли будуть у директорії "`squashfs-root`" після цього.

- CPIO архіви

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs з NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз прошивки

Після отримання прошивки важливо її розібрати, щоб зрозуміти структуру та потенційні вразливості. Цей процес включає використання різних інструментів для аналізу та вилучення корисних даних із образу прошивки.

### Інструменти початкового аналізу

Нижче наведено набір команд для початкового огляду бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, витягнути рядки, проаналізувати бінарні дані та зрозуміти деталі розділів і файлових систем:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **entropy** за допомогою `binwalk -E <bin>`. Низька **entropy** вказує на відсутність шифрування, тоді як висока — на можливе шифрування або стиск.

Для витягнення **embedded files** рекомендуються інструменти та ресурси, як-от документація **file-data-carving-recovery-tools** та **binvis.io** для інспекції файлів.

### Витягнення файлової системи

Використовуючи `binwalk -ev <bin>`, зазвичай можна витягти файлову систему, часто в директорію, названу за типом файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутність magic bytes, потрібне ручне витягнення. Це передбачає використання `binwalk` для знаходження зсуву файлової системи, після чого командою `dd` вирізають файлову систему:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного витягання вмісту використовуються різні команди.

### Filesystem Analysis

Після витягнення файлової системи починається пошук вразливостей. Увага звертається на ненадійні мережеві демони, жорстко вбудовані облікові дані, API endpoints, функції сервера оновлень, нескомпільований код, скрипти запуску та скомпільовані бінарні файли для офлайн-аналізу.

**Ключові локації** та **елементи** для перевірки включають:

- **etc/shadow** and **etc/passwd** для облікових даних користувачів
- SSL-сертифікати та ключі в **etc/ssl**
- Конфігураційні файли та скрипти на наявність вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Поширені веб-сервери та бінарники IoT-пристроїв

Декілька інструментів допомагають виявляти чутливу інформацію та вразливості у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Security Checks on Compiled Binaries

Як вихідний код, так і скомпільовані бінарні файли, знайдені у файловій системі, повинні бути ретельно перевірені на наявність вразливостей. Інструменти на кшталт **checksec.sh** для Unix-бінарників та **PESecurity** для Windows-бінарів допомагають виявити незахищені бінарні файли, які можуть бути використані для експлуатації.

## Emulating Firmware for Dynamic Analysis

Процес емулювання прошивки дозволяє виконувати **dynamic analysis** як роботи пристрою в цілому, так і окремої програми. Цей підхід може стикатися з проблемами, пов'язаними з апаратними або архітектурними залежностями, але перенесення root filesystem або окремих бінарників на пристрій з відповідною архітектурою та порядком байтів, наприклад Raspberry Pi, або на готову віртуальну машину, може полегшити подальші тести.

### Emulating Individual Binaries

Для дослідження окремих програм важливо визначити порядок байтів (endianness) програми та CPU-архітектуру.

#### Example with MIPS Architecture

Щоб емулювати бінарний файл архітектури MIPS, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А для встановлення необхідних інструментів емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian), `qemu-mips` використовується, а для little-endian бінарників вибір падає на `qemu-mipsel`.

#### Емуляція архітектури ARM

Для ARM бінарників процес аналогічний — для емулювання використовується `qemu-arm`.

### Повна емуляція системи

Інструменти на кшталт [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші полегшують повну емуляцію firmware, автоматизують процес і допомагають у dynamic analysis.

## Динамічний аналіз на практиці

На цьому етапі для аналізу використовується або реальний пристрій, або емульоване середовище. Важливо зберегти shell-доступ до OS і filesystem. Емуляція може не ідеально відтворювати взаємодію з апаратурою, тому іноді потрібно перезапускати емуляцію. Аналіз має повторно перевіряти filesystem, досліджувати відкриті webpages та мережеві сервіси, а також шукати вразливості bootloader'а. Тести цілісності firmware критичні для виявлення потенційних backdoor вразливостей.

## Техніки runtime-аналізу

Аналіз під час виконання передбачає взаємодію з процесом або бінарником у його робочому середовищі, використовуючи інструменти на кшталт gdb-multiarch, Frida та Ghidra для встановлення breakpoints і виявлення вразливостей через fuzzing та інші техніки.

## Binary Exploitation and Proof-of-Concept

Розробка PoC для виявлених вразливостей вимагає глибокого розуміння цільової архітектури та програмування на низькорівневих мовах. Захисти runtime бінарників в embedded-системах рідкісні, але коли вони присутні, можуть знадобитися техніки на кшталт Return Oriented Programming (ROP).

## Попередньо підготовлені операційні системи для аналізу firmware

ОС на кшталт [AttifyOS](https://github.com/adi0x90/attifyos) та [EmbedOS](https://github.com/scriptingxss/EmbedOS) забезпечують попередньо налаштоване середовище для firmware security testing, укомплектоване необхідними інструментами.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — дистрибутив, призначений для допомоги у виконанні security assessment та penetration testing пристроїв Internet of Things (IoT). Він економить багато часу, надаючи попередньо налаштоване середовище з усіма необхідними інструментами.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Операційна система для embedded security testing на базі Ubuntu 18.04, попередньо завантажена інструментами для firmware security testing.

## Атаки пониження версії firmware та ненадійні механізми оновлення

Навіть якщо виробник реалізує перевірку криптографічної підпису для образів firmware, **захист від version rollback (downgrade) часто відсутній**. Якщо boot- або recovery-loader лише перевіряє підпис за вбудованим public key, але не порівнює *version* (або монотонний лічильник) образу, який прошивається, атакуючий може легітимно встановити **старіший уразливий firmware, який все ще має дійсну підпис**, і таким чином повторно ввести виправлені вразливості.

Типовий сценарій атаки:

1. **Отримати старіший підписаний образ**
* Скачати його з публічного порталу завантажень виробника, CDN або сайту підтримки.
* Витягти його з супровідних мобільних/десктопних додатків (наприклад, всередині Android APK у `assets/firmware/`).
* Отримати його з репозиторіїв третіх сторін, таких як VirusTotal, інтернет-архіви, форуми тощо.
2. **Завантажити або подати образ на пристрій** через будь-який відкритий канал оновлення:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Багато consumer IoT пристроїв виставляють *unauthenticated* HTTP(S) endpoints, які приймають Base64-encoded firmware blobs, декодують їх на сервері та ініціюють recovery/upgrade.
3. Після downgrade експлуатувати вразливість, яку було виправлено в новішому релізі (наприклад, фільтр від command-injection, який додали пізніше).
4. За бажанням прошити назад останній образ або вимкнути оновлення, щоб уникнути виявлення після отримання персистенції.

### Приклад: Command Injection після downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (пониженій) прошивці параметр `md5` конкатенується безпосередньо в shell-команду без санітизації, що дозволяє ін'єкцію довільних команд (here – enabling SSH key-based root access). У наступних версіях прошивки було введено базовий фільтр символів, але відсутність захисту від пониження версії робить це виправлення марним.

### Отримання прошивки з мобільних додатків

Багато виробників упаковують повні образи прошивки всередині своїх супутніх мобільних додатків, щоб додаток міг оновлювати пристрій через Bluetooth/Wi‑Fi. Ці пакети зазвичай зберігаються незашифрованими в APK/APEX за шляхами на кшталт `assets/fw/` або `res/raw/`. Інструменти на кшталт `apktool`, `ghidra` або навіть простий `unzip` дозволяють витягти підписані образи без взаємодії з фізичним обладнанням.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Контрольний список для оцінки логіки оновлень

* Чи належним чином захищено транспорт/аутентифікацію *endpoint оновлення* (TLS + authentication)?
* Чи порівнює пристрій **номери версій** або **монотонний anti-rollback лічильник** перед прошивкою?
* Чи перевіряється образ у межах secure boot chain (наприклад, підписи перевіряються ROM code)?
* Чи виконує userland code додаткові перевірки коректності (наприклад, allowed partition map, model number)?
* Чи повторно використовують *partial* або *backup* потоки оновлення ту саму логіку валідації?

> 💡  Якщо будь-який із наведеного відсутній, платформа, ймовірно, вразлива до rollback-атак.

## Вразлива прошивка для практики

Для практики пошуку вразливостей у прошивці використовуйте наступні проекти вразливої прошивки як відправну точку.

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

## Тренінги та сертифікація

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
