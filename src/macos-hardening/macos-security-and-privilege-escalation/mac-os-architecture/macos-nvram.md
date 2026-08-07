# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **NVRAM** (Non-Volatile Random-Access Memory) αποθηκεύει **ρυθμίσεις κατά την εκκίνηση και σε επίπεδο firmware** στο hardware των Mac. Οι σημαντικότερες μεταβλητές από άποψη ασφάλειας περιλαμβάνουν:

| Μεταβλητή | Σκοπός |
|---|---|
| `boot-args` | Παράμετροι εκκίνησης του kernel (σημαίες debug, verbose boot, AMFI bypass) |
| `csr-active-config` | **Bitmask ρυθμίσεων SIP** — ελέγχει ποιες προστασίες είναι ενεργές |
| `SystemAudioVolume` | Ένταση ήχου κατά την εκκίνηση |
| `prev-lang:kbd` | Προτιμώμενη γλώσσα / διάταξη πληκτρολογίου |
| `efi-boot-device-data` | Επιλογή συσκευής εκκίνησης |

Στα σύγχρονα Mac, οι μεταβλητές NVRAM διαχωρίζονται σε **system** μεταβλητές (που προστατεύονται από το Secure Boot) και **non-system** μεταβλητές. Τα Mac με Apple Silicon χρησιμοποιούν ένα **Secure Storage Component (SSC)** για να συνδέουν κρυπτογραφικά την κατάσταση του NVRAM με την αλυσίδα εκκίνησης.<sup>[[1]](#references)</sup>

## Πρόσβαση στο NVRAM από τον χώρο χρήστη

### Ανάγνωση του NVRAM
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
### Εγγραφή στο NVRAM

Η εγγραφή μεταβλητών NVRAM απαιτεί **δικαιώματα root** και, για κρίσιμες για το σύστημα μεταβλητές (όπως η `csr-active-config`), η διεργασία πρέπει να διαθέτει συγκεκριμένες σημαίες code-signing ή entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Σημαία CS_NVRAM_UNRESTRICTED

Τα **`CS_NVRAM_UNRESTRICTED`** code-signing flags επιτρέπουν στα Binaries να τροποποιούν μεταβλητές NVRAM που κανονικά προστατεύονται ακόμη και από τον root.

### Εντοπισμός Binaries με NVRAM-Unrestrictedેણ
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Επιπτώσεις ασφαλείας

### Αποδυνάμωση του SIP μέσω NVRAM

Αν ένας attacker μπορεί να γράψει στο NVRAM (είτε μέσω ενός παραβιασμένου binary χωρίς περιορισμούς NVRAM είτε εκμεταλλευόμενος ένα vulnerability), μπορεί να τροποποιήσει το `csr-active-config` για να **απενεργοποιήσει τις προστασίες του SIP στην επόμενη εκκίνηση**:
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
> Σε σύγχρονα Mac με Apple Silicon, η αλυσίδα **Secure Boot** επικυρώνει τις αλλαγές στο NVRAM και αποτρέπει την τροποποίηση του SIP κατά το runtime. Οι αλλαγές στο `csr-active-config` εφαρμόζονται μόνο μέσω του recoveryOS. Ωστόσο, σε **Intel Macs** ή σε συστήματα με **reduced security mode**, η χειραγώγηση του NVRAM μπορεί ακόμη να αποδυναμώσει το SIP.

### Ενεργοποίηση Kernel Debugging
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
### Persistence στο Firmware

Οι τροποποιήσεις του NVRAM **επιβιώνουν από την επανεγκατάσταση του OS** — παραμένουν σε επίπεδο firmware. Ένας attacker μπορεί να γράψει custom μεταβλητές NVRAM, τις οποίες ένας μηχανισμός persistence διαβάζει κατά το boot:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Η persistence του NVRAM επιβιώνει από διαγραφές δίσκου και επανεγκαταστάσεις του OS. Απαιτεί **PRAM/NVRAM reset** (Command+Option+P+R σε Intel Mac) ή **DFU restore** (Apple Silicon) για να εκκαθαριστεί.

### AMFI Bypass

Το `amfi_get_out_of_my_way=1` boot argument απενεργοποιεί το **Apple Mobile File Integrity**, επιτρέποντας την εκτέλεση unsigned code:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVEs Πραγματικού Κόσμου

| CVE | Περιγραφή |
|---|---|
| CVE-2020-9839 | Χειρισμός του NVRAM που επιτρέπει persistent SIP bypass <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | Persistence του NVRAM σε επίπεδο firmware σε Mac με T2 <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | Privilege escalation σχετικό με το NVRAM στο PackageKit |
| CVE-2020-10004 | Λογικό ζήτημα στον χειρισμό του NVRAM που επιτρέπει τροποποίηση του συστήματος |

## Script Enumeration
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
## Αναφορές

- [1] [Apple Platform Security Guide — Διαδικασία εκκίνησης](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVE που σχετίζονται με το NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Ασφάλεια Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
