# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**NVRAM** (Non-Volatile Random-Access Memory) memorizza la **configurazione a livello di firmware e di avvio** sull'hardware Mac. Le variabili più critiche per la sicurezza includono:

| Variable | Purpose |
|---|---|
| `boot-args` | Argomenti di boot del kernel (flag di debug, boot verboso, AMFI bypass) |
| `csr-active-config` | **bitmask di configurazione SIP** — controlla quali protezioni sono attive |
| `SystemAudioVolume` | Volume audio all'avvio |
| `prev-lang:kbd` | Lingua preferita / layout tastiera |
| `efi-boot-device-data` | Selezione del dispositivo di avvio |

Sui Mac moderni, le variabili NVRAM sono suddivise tra variabili **di sistema** (protette da Secure Boot) e variabili **non di sistema**. I Mac Apple Silicon utilizzano un **Secure Storage Component (SSC)** per vincolare crittograficamente lo stato della NVRAM alla catena di boot.

## Accesso alla NVRAM dallo spazio utente

### Lettura della NVRAM
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
### Scrittura di NVRAM

Scrivere le variabili NVRAM richiede **root privileges** e, per le variabili critiche di sistema (come `csr-active-config`), il processo deve avere specifici code-signing flags o entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

I binari con il flag di code-signing **`CS_NVRAM_UNRESTRICTED`** possono modificare le variabili NVRAM che sono normalmente protette anche dall'utente root.

### Individuazione dei binari NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicazioni di sicurezza

### Indebolimento di SIP tramite NVRAM

Se un attaccante può scrivere nella NVRAM (tramite un binario compromesso senza restrizioni sulla NVRAM o sfruttando una vulnerabilità), può modificare `csr-active-config` per **disabilitare le protezioni SIP al prossimo avvio**:
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
> Su moderni Apple Silicon Macs, **la catena di Secure Boot convalida le modifiche alla NVRAM** e impedisce la modifica di SIP a runtime. Le modifiche a `csr-active-config` hanno effetto solo tramite recoveryOS. Tuttavia, su **Intel Macs** o sistemi con **reduced security mode**, la manipolazione della NVRAM può comunque indebolire SIP.

### Abilitazione del Kernel Debugging
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
### Persistenza del firmware

Modifiche alla NVRAM **sopravvivono alla reinstallazione del sistema operativo** — persistono a livello di firmware. Un attacker può scrivere variabili NVRAM personalizzate che un meccanismo di persistenza legge all'avvio:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> La persistenza in NVRAM sopravvive alle cancellazioni del disco e alle reinstallazioni del sistema operativo. Richiede **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) o **DFU restore** (Apple Silicon) per essere cancellata.

### AMFI Bypass

L'argomento di boot `amfi_get_out_of_my_way=1` disabilita **Apple Mobile File Integrity**, permettendo l'esecuzione di codice non firmato:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE del mondo reale

| CVE | Descrizione |
|---|---|
| CVE-2020-9839 | Manipolazione della NVRAM che permette un bypass persistente di SIP |
| CVE-2019-8779 | Persistenza della NVRAM a livello firmware sui Mac con T2 |
| CVE-2022-22583 | Escalation di privilegi correlata alla NVRAM in PackageKit |
| CVE-2020-10004 | Problema logico nella gestione della NVRAM che consente modifiche al sistema |

## Script di enumerazione
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
## Riferimenti

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
