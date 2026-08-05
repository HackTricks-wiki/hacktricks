# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**NVRAM** (Non-Volatile Random-Access Memory), Mac donanımındaki **önyükleme zamanı ve firmware düzeyindeki yapılandırmayı** depolar. Güvenlik açısından en kritik değişkenler şunlardır:

| Değişken | Amaç |
|---|---|
| `boot-args` | Kernel önyükleme argümanları (debug flag'leri, ayrıntılı önyükleme, AMFI bypass) |
| `csr-active-config` | **SIP yapılandırma bitmask'i** — hangi korumaların etkin olduğunu kontrol eder |
| `SystemAudioVolume` | Önyükleme sırasındaki ses düzeyi |
| `prev-lang:kbd` | Tercih edilen dil / klavye düzeni |
| `efi-boot-device-data` | Önyükleme aygıtı seçimi |

Modern Mac'lerde NVRAM değişkenleri **system** değişkenleri (Secure Boot tarafından korunan) ve **non-system** değişkenleri olarak ayrılır. Apple Silicon Mac'ler, NVRAM durumunu boot chain'e kriptografik olarak bağlamak için bir **Secure Storage Component (SSC)** kullanır.<sup>[1]</sup>

## User Space'ten NVRAM Erişimi

### NVRAM'i Okuma
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
### NVRAM Yazma

NVRAM değişkenlerini yazmak **root yetkileri** gerektirir ve sistem açısından kritik değişkenler (örneğin `csr-active-config`) için işlemin belirli code-signing flag'lerine veya entitlement'lara sahip olması gerekir:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

**`CS_NVRAM_UNRESTRICTED`** code-signing flag'ine sahip binary'ler, normalde root kullanıcısından bile korunan NVRAM değişkenlerini değiştirebilir.

### NVRAM-Unrestricted Binary'lerini Bulma
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Güvenlik Etkileri

### NVRAM aracılığıyla SIP'nin zayıflatılması

Bir saldırgan NVRAM'a yazabiliyorsa (NVRAM kısıtlaması olmayan ele geçirilmiş bir binary aracılığıyla veya bir güvenlik açığından yararlanarak), `csr-active-config` değerini değiştirerek **sonraki açılışta SIP korumalarını devre dışı bırakabilir**:
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
> Modern Apple Silicon Mac'lerde **Secure Boot chain**, NVRAM değişikliklerini doğrular ve çalışma zamanında SIP değişikliğini engeller. `csr-active-config` değişiklikleri yalnızca recoveryOS üzerinden etkili olur. Ancak **Intel Mac'lerde** veya **reduced security mode** kullanılan sistemlerde NVRAM manipülasyonu SIP'i hâlâ zayıflatabilir.

### Kernel Debugging'i Etkinleştirme
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
### Firmware Kalıcılığı

NVRAM değişiklikleri **OS yeniden kurulumundan sonra da varlığını sürdürür** — firmware düzeyinde kalıcıdır. Bir saldırgan, bir persistence mekanizmasının boot sırasında okuduğu özel NVRAM değişkenlerini yazabilir:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM kalıcılığı, disk silme ve işletim sistemi yeniden kurulumlarından sonra da devam eder. Temizlemek için **PRAM/NVRAM reset** (Intel Mac'lerde Command+Option+P+R) veya **DFU restore** (Apple Silicon) gerekir.

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument'ı **Apple Mobile File Integrity** özelliğini devre dışı bırakarak imzasız kodun çalıştırılmasına izin verir:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Gerçek Dünyadaki CVE'ler

| CVE | Açıklama |
|---|---|
| CVE-2020-9839 | Kalıcı SIP bypass sağlayan NVRAM manipulation |
| CVE-2019-8779 | T2 Mac'lerde firmware-level NVRAM persistence |
| CVE-2022-22583 | PackageKit ile ilişkili privilege escalation |
| CVE-2020-10004 | Sistem modification'a olanak tanıyan NVRAM handling mantık sorunu |

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
## Referanslar

- [1] [Apple Platform Security Guide — Önyükleme süreci](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM ile ilgili CVE'ler](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Güvenliği](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
