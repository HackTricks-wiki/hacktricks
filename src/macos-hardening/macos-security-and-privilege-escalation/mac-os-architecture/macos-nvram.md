# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

**NVRAM** (Μη πτητική μνήμη τυχαίας προσπέλασης) αποθηκεύει **ρυθμίσεις εκκίνησης και σε επίπεδο firmware** στο υλικό των Mac. Οι πιο κρίσιμες για την ασφάλεια μεταβλητές περιλαμβάνουν:

| Μεταβλητή | Σκοπός |
|---|---|
| `boot-args` | Παράμετροι εκκίνησης του kernel (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — ελέγχει ποιες προστασίες είναι ενεργές |
| `SystemAudioVolume` | Ένταση ήχου κατά την εκκίνηση |
| `prev-lang:kbd` | Προτιμώμενη γλώσσα / διάταξη πληκτρολογίου |
| `efi-boot-device-data` | Επιλογή συσκευής εκκίνησης |

Σε σύγχρονα Mac, οι μεταβλητές NVRAM χωρίζονται μεταξύ **system** μεταβλητών (προστατευόμενων από Secure Boot) και **non-system** μεταβλητών. Τα Apple Silicon Macs χρησιμοποιούν ένα **Secure Storage Component (SSC)** για να δέσουν κρυπτογραφικά την κατάσταση του NVRAM με την αλυσίδα εκκίνησης.

## Πρόσβαση στο NVRAM από τον χώρο χρήστη

### Ανάγνωση NVRAM
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
### Εγγραφή NVRAM

Η εγγραφή μεταβλητών NVRAM απαιτεί **δικαιώματα root** και, για συστημικά κρίσιμες μεταβλητές (όπως `csr-active-config`), η διαδικασία πρέπει να έχει συγκεκριμένες σημαίες υπογραφής κώδικα ή entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Σημαία CS_NVRAM_UNRESTRICTED

Τα Binaries με τη σημαία code-signing **`CS_NVRAM_UNRESTRICTED`** μπορούν να τροποποιήσουν μεταβλητές NVRAM που κανονικά προστατεύονται ακόμη και από τον root.

### Εύρεση NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Επιπτώσεις Ασφαλείας

### Αποδυνάμωση του SIP μέσω NVRAM

Εάν ένας επιτιθέμενος μπορεί να γράψει σε NVRAM (είτε μέσω ενός παραβιασμένου NVRAM-unrestricted binary είτε εκμεταλλευόμενος κάποια ευπάθεια), μπορεί να τροποποιήσει το `csr-active-config` ώστε να **απενεργοποιήσει τις προστασίες SIP στην επόμενη εκκίνηση**:
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
> Σε σύγχρονα Apple Silicon Macs, η **Secure Boot chain επικυρώνει τις αλλαγές στο NVRAM** και αποτρέπει την τροποποίηση του SIP κατά την εκτέλεση. Οι αλλαγές του `csr-active-config` εφαρμόζονται μόνο μέσω του recoveryOS. Ωστόσο, σε **Intel Macs** ή συστήματα με **reduced security mode**, η χειραγώγηση του NVRAM μπορεί ακόμα να αποδυναμώσει το SIP.
 
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
### Μόνιμη παρουσία στο firmware

Οι τροποποιήσεις του NVRAM **επιβιώνουν την επανεγκατάσταση του OS** — παραμένουν στο επίπεδο του firmware. Ένας επιτιθέμενος μπορεί να γράψει προσαρμοσμένες μεταβλητές NVRAM που ένας μηχανισμός επίμονης παρουσίας διαβάζει κατά την εκκίνηση:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Η μόνιμη αποθήκευση στο NVRAM επιβιώνει από διαγραφές δίσκου και επανεγκαταστάσεις του OS. Απαιτεί **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) ή **DFU restore** (Apple Silicon) για να καθαριστεί.

### AMFI Bypass

Το όρισμα εκκίνησης `amfi_get_out_of_my_way=1` απενεργοποιεί την **Apple Mobile File Integrity**, επιτρέποντας την εκτέλεση unsigned code:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Πραγματικά CVE

| CVE | Περιγραφή |
|---|---|
| CVE-2020-9839 | Χειρισμός του NVRAM που επιτρέπει επίμονη SIP bypass |
| CVE-2019-8779 | Μόνιμη παρουσία NVRAM σε επίπεδο firmware σε T2 Macs |
| CVE-2022-22583 | PackageKit ευπάθεια σχετική με NVRAM που οδηγεί σε privilege escalation |
| CVE-2020-10004 | Λογικό σφάλμα στον χειρισμό του NVRAM που επιτρέπει τροποποίηση του συστήματος |

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
## Αναφορές

* [Apple Platform Security Guide — Διαδικασία εκκίνησης](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — CVEs σχετικά με NVRAM](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Ασφάλεια Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
