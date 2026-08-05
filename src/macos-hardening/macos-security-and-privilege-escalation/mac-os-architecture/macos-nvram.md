# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **NVRAM** (Non-Volatile Random-Access Memory) αποθηκεύει **ρυθμίσεις εκκίνησης και firmware** στο hardware των Mac. Οι σημαντικότερες από άποψη ασφάλειας μεταβλητές περιλαμβάνουν:

| Μεταβλητή | Σκοπός |
|---|---|
| `boot-args` | Ορίσματα εκκίνησης του kernel (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **Bitmask ρύθμισης του SIP** — ελέγχει ποιες προστασίες είναι ενεργές |
| `SystemAudioVolume` | Ένταση ήχου κατά την εκκίνηση |
| `prev-lang:kbd` | Προτιμώμενη γλώσσα / διάταξη πληκτρολογίου |
| `efi-boot-device-data` | Επιλογή συσκευής εκκίνησης |

Στα σύγχρονα Mac, οι μεταβλητές NVRAM χωρίζονται σε **system** μεταβλητές (που προστατεύονται από το Secure Boot) και **non-system** μεταβλητές. Τα Apple Silicon Mac χρησιμοποιούν ένα **Secure Storage Component (SSC)** για την κρυπτογραφική σύνδεση της κατάστασης του NVRAM με την αλυσίδα εκκίνησης.<sup>[1]</sup>

## Πρόσβαση στο NVRAM από το User Space

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

Η εγγραφή μεταβλητών NVRAM απαιτεί **δικαιώματα root** και, για system-critical μεταβλητές (όπως η `csr-active-config`), η διεργασία πρέπει να διαθέτει συγκεκριμένα flags υπογραφής κώδικα ή entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Σημαία CS_NVRAM_UNRESTRICTED

Τα binaries με τη σημαία code-signing **`CS_NVRAM_UNRESTRICTED`** μπορούν να τροποποιούν μεταβλητές NVRAM που κανονικά προστατεύονται ακόμη και από τον root.

### Εντοπισμός Binaries με NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Επιπτώσεις στην ασφάλεια

### Αποδυνάμωση του SIP μέσω του NVRAM

Αν ένας επιτιθέμενος μπορεί να γράψει στο NVRAM (είτε μέσω ενός binary χωρίς περιορισμούς NVRAM είτε εκμεταλλευόμενος μια ευπάθεια), μπορεί να τροποποιήσει το `csr-active-config` ώστε να **απενεργοποιήσει τις προστασίες του SIP κατά την επόμενη εκκίνηση**:
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
> Σε σύγχρονα Mac με Apple Silicon, το **Secure Boot chain επικυρώνει τις** αλλαγές στο NVRAM και αποτρέπει την τροποποίηση του SIP κατά τον χρόνο εκτέλεσης. Οι αλλαγές στο `csr-active-config` εφαρμόζονται μόνο μέσω του recoveryOS. Ωστόσο, σε **Intel Macs** ή σε συστήματα με **reduced security mode**, η χειραγώγηση του NVRAM μπορεί ακόμη να αποδυναμώσει το SIP.

### Ενεργοποίηση του Kernel Debugging
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
### Firmware Persistence

Οι τροποποιήσεις του NVRAM **επιβιώνουν από την επανεγκατάσταση του OS** — παραμένουν στο επίπεδο του firmware. Ένας attacker μπορεί να γράψει custom μεταβλητές NVRAM, τις οποίες ένας μηχανισμός persistence διαβάζει κατά την εκκίνηση:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Η NVRAM persistence επιβιώνει από διαγραφές δίσκων και επανεγκαταστάσεις του OS. Απαιτεί **PRAM/NVRAM reset** (Command+Option+P+R σε Intel Macs) ή **DFU restore** (Apple Silicon) για εκκαθάριση.

### AMFI Bypass

Το όρισμα εκκίνησης `amfi_get_out_of_my_way=1` απενεργοποιεί το **Apple Mobile File Integrity**, επιτρέποντας την εκτέλεση unsigned code:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE στον πραγματικό κόσμο

| CVE | Περιγραφή |
|---|---|
| CVE-2020-9839 | Manipulation του NVRAM που επιτρέπει persistent παράκαμψη του SIP |
| CVE-2019-8779 | Persistence του NVRAM σε επίπεδο firmware σε Mac με T2 |
| CVE-2022-22583 | Escalation προνομίων που σχετίζεται με το NVRAM στο PackageKit |
| CVE-2020-10004 | Πρόβλημα λογικής στη διαχείριση του NVRAM που επιτρέπει τροποποίηση του συστήματος |

## Script απαρίθμησης
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
## Παραπομπές

- [1] [Apple Platform Security Guide — Διαδικασία εκκίνησης](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVEs που σχετίζονται με το NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
