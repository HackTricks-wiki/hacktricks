# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

**NVRAM** (енергонезалежна пам'ять з довільним доступом) зберігає **конфігурацію під час завантаження та налаштування на рівні прошивки** на апаратному забезпеченні Mac. Найбільш критичні для безпеки змінні включають:

| Змінна | Призначення |
|---|---|
| `boot-args` | аргументи завантаження ядра (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **бітова маска конфігурації SIP** — контролює, які механізми захисту активні |
| `SystemAudioVolume` | гучність звуку при завантаженні |
| `prev-lang:kbd` | переважна мова / розкладка клавіатури |
| `efi-boot-device-data` | вибір пристрою для завантаження |

У сучасних Mac змінні NVRAM поділені між **system** змінними (захищені Secure Boot) та **non-system** змінними. Mac на Apple Silicon використовують **компонент захищеного зберігання (SSC)** для криптографічного прив'язування стану NVRAM до ланцюга завантаження.

## Доступ до NVRAM з користувацького простору

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

Запис змінних NVRAM вимагає **root privileges**, і для системно-критичних змінних (наприклад, `csr-active-config`) процес повинен мати специфічні code-signing flags або entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED флаг

Бінарні файли з флагом підпису коду **`CS_NVRAM_UNRESTRICTED`** можуть змінювати змінні NVRAM, які зазвичай захищені навіть від root.

### Пошук бінарів з CS_NVRAM_UNRESTRICTED
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Наслідки для безпеки

### Ослаблення SIP через NVRAM

Якщо зловмисник може записувати в NVRAM (наприклад, через скомпрометований бінарний файл з необмеженим доступом до NVRAM або шляхом експлуатації вразливості), він може змінити `csr-active-config`, щоб **відключити захист SIP при наступному завантаженні**:
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
> На сучасних Apple Silicon Macs **ланцюг Secure Boot перевіряє зміни NVRAM** і не дозволяє змінювати SIP під час виконання. Зміни `csr-active-config` набирають чинності лише через recoveryOS. Однак на **Intel Macs** або системах у **reduced security mode** маніпуляції з NVRAM все ще можуть послабити SIP.
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
### Постійність на рівні прошивки

NVRAM модифікації **зберігаються після перевстановлення OS** — вони залишаються на рівні прошивки. Зловмисник може записати власні змінні NVRAM, які механізм персистенції читає при завантаженні:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Постійність NVRAM зберігається після очищення диска та перевстановлення ОС. Для її очищення потрібен **PRAM/NVRAM reset** (Command+Option+P+R на Intel Macs) або **DFU restore** (Apple Silicon).

### AMFI Bypass

Аргумент завантаження `amfi_get_out_of_my_way=1` вимикає **Apple Mobile File Integrity**, дозволяючи виконувати непідписаний код:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Реальні CVE

| CVE | Опис |
|---|---|
| CVE-2020-9839 | Маніпуляція NVRAM, що дозволяє постійний SIP bypass |
| CVE-2019-8779 | Персистентність NVRAM на рівні firmware на T2 Macs |
| CVE-2022-22583 | PackageKit: NVRAM-пов'язане privilege escalation |
| CVE-2020-10004 | Логічна помилка в обробці NVRAM, що дозволяє модифікацію системи |

## Enumeration Script
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

* [Apple Platform Security Guide — Процес завантаження](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Оновлення безпеки Apple — CVE, пов'язані з NVRAM](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Безпека Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
