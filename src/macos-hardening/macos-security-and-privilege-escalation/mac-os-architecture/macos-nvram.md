# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**NVRAM** (Uçucu Olmayan Rastgele Erişim Belleği) Mac donanımında **önyükleme zamanı ve firmware düzeyindeki yapılandırmayı** saklar. Güvenlik açısından en kritik değişkenler şunlardır:

| Variable | Purpose |
|---|---|
| `boot-args` | Kernel önyükleme argümanları (hata ayıklama bayrakları, ayrıntılı önyükleme, AMFI atlatma) |
| `csr-active-config` | **SIP yapılandırma bitmaskesi** — hangi korumaların etkin olduğunu kontrol eder |
| `SystemAudioVolume` | Önyüklemede ses düzeyi |
| `prev-lang:kbd` | Tercih edilen dil / klavye düzeni |
| `efi-boot-device-data` | Önyükleme cihazı seçimi |

Modern Mac'lerde, NVRAM değişkenleri **system** değişkenleri (Secure Boot tarafından korunur) ve **non-system** değişkenleri olarak ayrılır. Apple Silicon Mac'ler, NVRAM durumunu önyükleme zincirine kriptografik olarak bağlamak için bir **Secure Storage Component (SSC)** kullanır.

## Kullanıcı Alanından NVRAM Erişimi

### NVRAM Okuma
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
### Writing NVRAM

NVRAM değişkenlerini yazmak **root privileges** gerektirir ve sistem için kritik olan değişkenler (ör. `csr-active-config`) söz konusu olduğunda süreç belirli code-signing flags veya entitlements'a sahip olmalıdır:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Bayrağı

Kod imzalama bayrağı **`CS_NVRAM_UNRESTRICTED`** olan ikili dosyalar, normalde root'tan bile korunan NVRAM değişkenlerini değiştirebilir.

### NVRAM-Unrestricted Binaries'ı Bulma
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Güvenlik Etkileri

### NVRAM aracılığıyla SIP'in zayıflatılması

Bir saldırgan NVRAM'a yazabiliyorsa (ya ele geçirilmiş bir NVRAM-unrestricted binary aracılığıyla ya da bir güvenlik açığını istismar ederek), `csr-active-config` değiştirerek bir sonraki önyüklemede SIP korumalarını **devre dışı bırakabilir**:
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
> Modern Apple Silicon Mac'lerde, **Secure Boot zinciri NVRAM değişikliklerini doğrular** ve çalışma zamanı SIP değişikliğini engeller. `csr-active-config` değişiklikleri yalnızca recoveryOS üzerinden etkili olur. Ancak, **Intel Mac'lerde** veya **reduced security mode** olan sistemlerde, NVRAM manipülasyonu SIP'i hala zayıflatabilir.

### Çekirdek Hata Ayıklamayı Etkinleştirme
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

NVRAM değişiklikleri **OS yeniden kurulmasından sonra da devam eder** — firmware düzeyinde kalırlar. Bir saldırgan, boot'ta bir persistence mechanism tarafından okunan özel NVRAM değişkenleri yazabilir:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence disk silme ve işletim sistemi yeniden yüklemelerini atlatır. Temizlemek için **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) veya **DFU restore** (Apple Silicon) gerekir.

### AMFI Bypass

The `amfi_get_out_of_my_way=1` boot argument disables **Apple Mobile File Integrity**, allowing unsigned code to execute:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2020-9839 | Kalıcı SIP atlatmayı mümkün kılan NVRAM manipülasyonu |
| CVE-2019-8779 | T2 Macs üzerinde firmware düzeyinde NVRAM kalıcılığı |
| CVE-2022-22583 | PackageKit NVRAM ile ilgili privilege escalation |
| CVE-2020-10004 | Sistem değişikliğine izin veren NVRAM işleme mantık hatası |

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

* [Apple Platform Security Guide — Önyükleme süreci](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM ile ilgili CVE'ler](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Güvenliği](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
