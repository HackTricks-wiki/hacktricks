# NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

**NVRAM** (Non-Volatile Random-Access Memory) зберігає конфігурацію **часу завантаження та рівня firmware** на апаратному забезпеченні Mac. Найважливіші з погляду безпеки змінні:

| Змінна | Призначення |
|---|---|
| `boot-args` | Аргументи завантаження kernel (прапорці налагодження, verbose boot, обхід AMFI) |
| `csr-active-config` | **Бітова маска конфігурації SIP** — керує активними захисними механізмами |
| `SystemAudioVolume` | Рівень гучності під час завантаження |
| `prev-lang:kbd` | Бажана мова / розкладка клавіатури |
| `efi-boot-device-data` | Вибір завантажувального пристрою |

У сучасних Mac змінні NVRAM поділяються на **системні** змінні (захищені Secure Boot) та **несистемні** змінні. У Mac на базі Apple Silicon використовується **Secure Storage Component (SSC)** для криптографічної прив’язки стану NVRAM до ланцюжка завантаження.<sup>[[1]](#references)</sup>

## Доступ до NVRAM із User Space

### Читання NVRAM
```bash
# List all NVRAM variables
nvram -p

# Read a specific variable
nvram boot-args

# Export all NVRAM as XML plist
nvram -xp

# Read SIP configuration
nvram csr-active-config
csrutil status
```
### Запис NVRAM

Для запису змінних NVRAM потрібні **права root**, а для системно критичних змінних (наприклад, `csr-active-config`) процес повинен мати певні flags або entitlements для code-signing:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Прапорець CS_NVRAM_UNRESTRICTED

Бінарні файли з прапорцем підпису коду **`CS_NVRAM_UNRESTRICTED`** можуть змінювати змінні NVRAM, які зазвичай захищені навіть від root.

### Пошук бінарних файлів із необмеженим доступом до NVRAM
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Наслідки для безпеки

### Послаблення SIP через NVRAM

Якщо зловмисник може записувати дані до NVRAM (через скомпрометований бінарний файл із необмеженим доступом до NVRAM або використовуючи вразливість), він може змінити `csr-active-config`, щоб **вимкнути захист SIP під час наступного завантаження**:
```bash
# SIP configuration is a bitmask stored in NVRAM
# Each bit controls a different SIP protection:
#   Bit 0 (0x1):  Filesystem protection
#   Bit 1 (0x2):  Kext signing
#   Bit 2 (0x4):  Task-for-pid restriction
#   Bit 3 (0x8):  Unrestricted filesystem
#   Bit 4 (0x10): Apple Internal (debug)
#   Bit 5 (0x20): Unrestricted DTrace
#   Bit 6 (0x40): Unrestricted NVRAM
#   Bit 7 (0x80): Device configuration

# Current SIP configuration
nvram csr-active-config | xxd

# On older hardware, a compromised NVRAM-unrestricted binary could:
# nvram csr-active-config=%7f%00%00%00   # Disable most SIP protections
```
> [!WARNING]
> На сучасних Mac з Apple Silicon ланцюжок **Secure Boot перевіряє зміни NVRAM** і запобігає модифікації SIP під час виконання. Зміни `csr-active-config` набувають чинності лише через recoveryOS. Однак на **Mac з процесорами Intel** або системах із **reduced security mode** маніпуляції з NVRAM усе ще можуть послабити SIP.

### Увімкнення налагодження ядра
```bash
# Enable kernel debug flags via boot-args
sudo nvram boot-args="debug=0x144"

# Common debug flags:
#   0x01  DB_HALT      — Wait for debugger at boot
#   0x04  DB_KPRT      — Send kernel printf to serial
#   0x40  DB_KERN_DUMP — Dump kernel core on NMI
#   0x100 DB_REBOOT_POST_PANIC — Reboot after panic

# Use development kernel
sudo nvram boot-args="kcsuffix=development"
```
### Постійність у прошивці

Зміни NVRAM **переживають перевстановлення ОС** — вони зберігаються на рівні прошивки. Зловмисник може записати власні змінні NVRAM, які механізм persistence зчитує під час завантаження:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence переживає очищення диска та перевстановлення OS. Для очищення потрібен **PRAM/NVRAM reset** (Command+Option+P+R на Intel Macs) або **DFU restore** (Apple Silicon).

### AMFI Bypass

Аргумент завантаження `amfi_get_out_of_my_way=1` вимикає **Apple Mobile File Integrity**, дозволяючи виконувати непідписаний code:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE у реальних сценаріях

| CVE | Опис |
|---|---|
| CVE-2020-9839 | Маніпуляції з NVRAM, що забезпечують постійний обхід SIP |
| CVE-2019-8779 | Persistence на рівні firmware через NVRAM на Mac із T2 |
| CVE-2022-22583 | Підвищення привілеїв, пов’язане з NVRAM, у PackageKit |
| CVE-2020-10004 | Логічна проблема в обробці NVRAM, що дає змогу змінювати систему |

## Скрипт Enumeration
```bash
#!/bin/bash
echo "=== NVRAM Security Audit ==="

# Current SIP status
echo -e "\n[*] SIP Status:"
csrutil status

# Current boot-args
echo -e "\n[*] Boot Arguments:"
nvram boot-args 2>/dev/null || echo "  (none set)"

# All NVRAM variables
echo -e "\n[*] All NVRAM Variables:"
nvram -p | grep -v "^$" | wc -l
echo "  variables total"

# Security-relevant variables
echo -e "\n[*] Security-Relevant Variables:"
for var in csr-active-config boot-args StartupMute SystemAudioVolume efi-boot-device; do
echo "  $var: $(nvram "$var" 2>/dev/null || echo 'not set')"
done

# Check for custom (non-Apple) variables
echo -e "\n[*] Non-Standard Variables (potential persistence):"
nvram -p | grep -v "^$" | grep -vE "^(SystemAudioVolume|boot-args|csr-active-config|prev-lang|LocationServicesEnabled|fmm-mobileme-token|bluetoothInternalControllerAddress|bluetoothActiveControllerInfo|SystemAudioVolumeExtension|efi-)" | head -20
```
## Посилання

- [1] [Посібник Apple з безпеки платформи — процес завантаження](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Оновлення безпеки Apple — CVE, пов'язані з NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — безпека Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
