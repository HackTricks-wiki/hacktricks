# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**NVRAM** (Non-Volatile Random-Access Memory) memorizza la configurazione **a tempo di avvio e a livello firmware** sull'hardware Mac. Le variabili più importanti per la sicurezza includono:

| Variabile | Scopo |
|---|---|
| `boot-args` | Argomenti di avvio del kernel (flag di debug, avvio verbose, AMFI bypass) |
| `csr-active-config` | **Bitmask di configurazione SIP** — controlla quali protezioni sono attive |
| `SystemAudioVolume` | Volume audio all'avvio |
| `prev-lang:kbd` | Lingua / layout di tastiera preferiti |
| `efi-boot-device-data` | Selezione del dispositivo di avvio |

Sui Mac moderni, le variabili NVRAM sono suddivise tra variabili **di sistema** (protette da Secure Boot) e variabili **non di sistema**. I Mac Apple Silicon utilizzano un **Secure Storage Component (SSC)** per associare crittograficamente lo stato della NVRAM alla catena di avvio.<sup>[1]</sup>

## Accesso alla NVRAM dallo User Space

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

La scrittura delle variabili NVRAM richiede **privilegi di root** e, per le variabili critiche di sistema (come `csr-active-config`), il processo deve avere flag di code-signing o entitlements specifici:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Flag CS_NVRAM_UNRESTRICTED

I binari con il flag di code-signing **`CS_NVRAM_UNRESTRICTED`** possono modificare le variabili NVRAM normalmente protette persino da root.

### Individuazione dei binari NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicazioni sulla sicurezza

### Indebolire SIP tramite NVRAM

Se un attacker può scrivere nella NVRAM (tramite un binary senza restrizioni sulla NVRAM o sfruttando una vulnerabilità), può modificare `csr-active-config` per **disabilitare le protezioni SIP al prossimo avvio**:
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
> Sui moderni Mac Apple Silicon, la **Secure Boot chain convalida le modifiche a NVRAM** e impedisce la modifica runtime di SIP. Le modifiche a `csr-active-config` hanno effetto solo tramite recoveryOS. Tuttavia, sui **Mac Intel** o sui sistemi con **reduced security mode**, la manipolazione di NVRAM può ancora indebolire SIP.

### Abilitazione del debugging del kernel
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

Le modifiche alla NVRAM **sopravvivono alla reinstallazione del sistema operativo** e persistono a livello firmware. Un attaccante può scrivere variabili NVRAM personalizzate che un meccanismo di persistenza legge durante l'avvio:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> La persistenza NVRAM sopravvive alla cancellazione dei dischi e alle reinstallazioni del sistema operativo. Per cancellarla è necessario un **reset PRAM/NVRAM** (Command+Option+P+R sui Mac Intel) o un **ripristino DFU** (Apple Silicon).

### AMFI Bypass

L'argomento di boot `amfi_get_out_of_my_way=1` disabilita **Apple Mobile File Integrity**, consentendo l'esecuzione di codice non firmato:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE nel mondo reale

| CVE | Descrizione |
|---|---|
| CVE-2020-9839 | Manipolazione della NVRAM che consente l'elusione persistente del SIP |
| CVE-2019-8779 | Persistenza della NVRAM a livello firmware sui Mac con T2 |
| CVE-2022-22583 | Escalation dei privilegi correlata alla NVRAM in PackageKit |
| CVE-2020-10004 | Problema logico nella gestione della NVRAM che consente la modifica del sistema |

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

- [1] [Apple Platform Security Guide — Processo di avvio](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVE correlati a NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Sicurezza Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
