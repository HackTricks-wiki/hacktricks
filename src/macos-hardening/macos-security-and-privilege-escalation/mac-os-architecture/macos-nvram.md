# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**NVRAM** (Non-Volatile Random-Access Memory) speichert **Konfigurationen für die Boot-Phase und auf Firmware-Ebene** auf Mac-Hardware. Zu den sicherheitskritischsten Variablen gehören:

| Variable | Zweck |
|---|---|
| `boot-args` | Kernel-Boot-Argumente (Debug-Flags, Verbose Boot, AMFI Bypass) |
| `csr-active-config` | **SIP-Konfigurationsbitmaske** — steuert, welche Schutzmechanismen aktiv sind |
| `SystemAudioVolume` | Audio-Lautstärke beim Booten |
| `prev-lang:kbd` | Bevorzugte Sprache / Tastaturbelegung |
| `efi-boot-device-data` | Auswahl des Boot-Geräts |

Auf modernen Macs werden NVRAM-Variablen in **Systemvariablen** (durch Secure Boot geschützt) und **Nicht-Systemvariablen** aufgeteilt. Apple-Silicon-Macs verwenden eine **Secure Storage Component (SSC)**, um den NVRAM-Zustand kryptografisch an die Boot-Kette zu binden.<sup>[1]</sup>

## NVRAM-Zugriff aus dem User Space

### NVRAM lesen
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
### NVRAM schreiben

Das Schreiben von NVRAM-Variablen erfordert **root privileges**. Für systemkritische Variablen (wie `csr-active-config`) muss der Prozess außerdem über bestimmte Code-Signing-Flags oder Entitlements verfügen:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED-Flag

Binärdateien mit dem Code-Signierungsflag **`CS_NVRAM_UNRESTRICTED`** können NVRAM-Variablen ändern, die normalerweise sogar vor root geschützt sind.

### NVRAM-Unrestricted-Binärdateien finden
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Sicherheitsauswirkungen

### Abschwächung von SIP über NVRAM

Wenn ein Angreifer in NVRAM schreiben kann (entweder über eine kompromittierte, NVRAM-unrestricted-Binärdatei oder durch das Ausnutzen einer Schwachstelle), kann er `csr-active-config` ändern, um **die SIP-Schutzmechanismen beim nächsten Start zu deaktivieren**:
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
> Auf modernen Macs mit Apple Silicon validiert die **Secure Boot chain** Änderungen an NVRAM und verhindert Laufzeitänderungen an SIP. Änderungen an `csr-active-config` werden nur über recoveryOS wirksam. Auf **Intel Macs** oder Systemen mit **reduced security mode** kann die Manipulation des NVRAM SIP jedoch weiterhin schwächen.

### Kernel-Debugging aktivieren
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
### Firmware-Persistenz

NVRAM modifications **überstehen eine Neuinstallation des Betriebssystems** — sie bleiben auf Firmware-Ebene bestehen. Ein Angreifer kann benutzerdefinierte NVRAM-Variablen schreiben, die ein Persistence-Mechanismus beim Booten ausliest:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM-Persistenz überlebt das Löschen von Datenträgern und Neuinstallationen des Betriebssystems. Zum Löschen ist ein **PRAM/NVRAM-Reset** (Command+Option+P+R auf Intel-Macs) oder eine **DFU-Wiederherstellung** (Apple Silicon) erforderlich.

### AMFI Bypass

Das Boot-Argument `amfi_get_out_of_my_way=1` deaktiviert **Apple Mobile File Integrity** und ermöglicht die Ausführung unsignierten Codes:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVEs aus der Praxis

| CVE | Beschreibung |
|---|---|
| CVE-2020-9839 | NVRAM-Manipulation ermöglicht dauerhaften SIP-Bypass |
| CVE-2019-8779 | Firmware-level NVRAM-Persistenz auf T2-Macs |
| CVE-2022-22583 | Privilege Escalation in PackageKit im Zusammenhang mit NVRAM |
| CVE-2020-10004 | Logikfehler bei der NVRAM-Verarbeitung ermöglicht Systemänderungen |

## Enumerationsskript
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
## Referenzen

- [1] [Apple Platform Security Guide — Boot-Prozess](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-bezogene CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
