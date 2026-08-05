# Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Βασικές πληροφορίες

Από το **macOS Big Sur (11.0)**, το system volume είναι κρυπτογραφικά σφραγισμένο με χρήση ενός **APFS snapshot hash tree**. Αυτό ονομάζεται **Sealed System Volume (SSV)**. Το system partition προσαρτάται ως **read-only** και οποιαδήποτε τροποποίηση παραβιάζει τη σφραγίδα, κάτι που επαληθεύεται κατά το boot.

Το SSV παρέχει:
- **Ανίχνευση παραποίησης** — οποιαδήποτε τροποποίηση σε system binaries/frameworks μπορεί να εντοπιστεί μέσω της παραβιασμένης κρυπτογραφικής σφραγίδας
- **Προστασία από rollback** — η διαδικασία boot επαληθεύει την ακεραιότητα του system snapshot
- **Αποτροπή rootkit** — ακόμη και ο root δεν μπορεί να τροποποιεί μόνιμα αρχεία στο system volume (χωρίς να παραβιάσει τη σφραγίδα)

### Έλεγχος της κατάστασης του SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Δικαιώματα SSV Writers

Ορισμένα Apple system binaries διαθέτουν δικαιώματα που τους επιτρέπουν να τροποποιούν ή να διαχειρίζονται το sealed system volume:

| Entitlement | Σκοπός |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Επαναφορά του system volume σε προηγούμενο snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Δημιουργία νέου sealed snapshot μετά από system updates |
| `com.apple.rootless.install.heritable` | Εγγραφή σε SIP-protected paths (κληρονομείται από child processes) |
| `com.apple.rootless.install` | Εγγραφή σε SIP-protected paths |

### Εντοπισμός SSV Writers
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Σενάρια Επίθεσης

#### Snapshot Rollback Attack

Αν ένας attacker παραβιάσει ένα binary με `com.apple.private.apfs.revert-to-snapshot`, μπορεί να **επαναφέρει το system volume σε κατάσταση πριν από την ενημέρωση**, επαναφέροντας γνωστά vulnerabilities:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Η επαναφορά snapshot ουσιαστικά **αναιρεί τις ενημερώσεις ασφαλείας**, επαναφέροντας προηγουμένως διορθωμένες ευπάθειες του kernel και του συστήματος. Πρόκειται για μία από τις πιο επικίνδυνες δυνατές λειτουργίες στο σύγχρονο macOS.

#### Αντικατάσταση Δυαδικού Αρχείου Συστήματος

Με παράκαμψη του SIP + δυνατότητα εγγραφής στο SSV, ένας attacker μπορεί να:

1. Προσαρτήσει το system volume με δικαιώματα ανάγνωσης-εγγραφής
2. Αντικαταστήσει έναν system daemon ή μια framework library με trojaned έκδοση
3. Επανασφραγίσει το snapshot (ή να αποδεχτεί τη σπασμένη σφραγίδα, αν το SIP έχει ήδη υποβαθμιστεί)
4. Το rootkit παραμένει μετά τις επανεκκινήσεις και δεν είναι ορατό στα userland detection tools

### CVEs στον Πραγματικό Κόσμο

| CVE | Περιγραφή |
|---|---|
| CVE-2021-30892 | **Shrootless** — παράκαμψη του SIP που εκμεταλλεύεται το entitlement `com.apple.rootless.install.heritable` του `system_installd` για την εκτέλεση αυθαίρετων post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Παράκαμψη του SIP: το `system_installd` τοποθετούσε το post-install script σε έναν φάκελο που προστατεύεται από το SIP κάτω από το `/tmp`, όμως το ίδιο το `/tmp` δεν προστατεύεται από το SIP, επομένως ο φάκελος μπορούσε να αντικατασταθεί με την προσάρτηση ενός image πάνω του ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race στο copy-on-write του XNU που επιτρέπει εγγραφές σε αρχεία μόνο για ανάγνωση, τα οποία ανήκουν στον root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Βασικές Πληροφορίες

Το **DataVault** είναι το protection layer της Apple για ευαίσθητες system databases. Ακόμη και ο **root δεν μπορεί να αποκτήσει πρόσβαση σε αρχεία που προστατεύονται από το DataVault** — μόνο processes με συγκεκριμένα entitlements μπορούν να τα διαβάσουν ή να τα τροποποιήσουν. Τα προστατευμένα stores περιλαμβάνουν:

| Προστατευμένη Database | Path | Περιεχόμενο |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Αποφάσεις απορρήτου TCC σε ολόκληρο το σύστημα |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Αποφάσεις απορρήτου TCC ανά user |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

Η προστασία του DataVault επιβάλλεται σε **επίπεδο filesystem** με τη χρήση extended attributes και volume protection flags, τα οποία επαληθεύονται από τον kernel.

### Entitlements του DataVault Controller
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Εντοπισμός DataVault Controllers
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Σενάρια Επίθεσης

#### Άμεση Τροποποίηση της Βάσης Δεδομένων TCC

Αν ένας attacker παραβιάσει ένα DataVault controller binary (π.χ. μέσω code injection σε μια διεργασία με `com.apple.private.tcc.manager`), μπορεί να **τροποποιήσει απευθείας τη βάση δεδομένων TCC** ώστε να παραχωρήσει σε οποιαδήποτε εφαρμογή οποιοδήποτε TCC permission:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Η τροποποίηση της βάσης δεδομένων TCC είναι το **απόλυτο privacy bypass** — παρέχει οποιαδήποτε άδεια αθόρυβα, χωρίς προτροπή χρήστη ή ορατή ένδειξη. Ιστορικά, πολλές αλυσίδες privilege escalation στο macOS έχουν καταλήξει σε εγγραφές στη βάση δεδομένων TCC ως τελικό payload.

#### Πρόσβαση στη βάση δεδομένων του Keychain

Το DataVault προστατεύει επίσης τα backing files του keychain. Ένας παραβιασμένος controller του DataVault μπορεί να:

1. Διαβάσει τα raw αρχεία της βάσης δεδομένων του keychain
2. Εξαγάγει κρυπτογραφημένα keychain items
3. Επιχειρήσει offline αποκρυπτογράφηση χρησιμοποιώντας τον κωδικό πρόσβασης του χρήστη ή keys που έχουν ανακτηθεί

### CVEs σε πραγματικές συνθήκες που αφορούν DataVault/TCC Bypass

| CVE | Περιγραφή |
|---|---|
| CVE-2024-44131 | FileProvider symlink race που επιτρέπει σε έναν privileged helper να αποκτήσει πρόσβαση σε δεδομένα που προστατεύονται από το TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Ως root, **δημιουργία νέου χρήστη του οποίου το `NFSHomeDirectory` δείχνει σε ένα `TCC.db` που ελέγχεται από τον attacker**· κατά το login, το `tccd` το καταναλώνει και οι grants εφαρμόζονται, παρέχοντας πρόσβαση στα δεδομένα άλλων χρηστών ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": αλλαγή του home directory του χρήστη για την τοποθέτηση ενός TCC.db που ελέγχεται από τον attacker ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Αδυναμία bundle-conclusion που επιτρέπει σε μια εφαρμογή να **κληρονομήσει τα TCC grants ενός donor bundle** χωρίς prompt· έγινε exploit in the wild από το **XCSSET** για τη λήψη screenshot της επιφάνειας εργασίας ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | Το `tccd` δημιουργούσε το path της DB από το `$HOME`, επομένως το `launchctl setenv HOME` το ανακατεύθυνε σε ένα `TCC.db` που ελεγχόταν από τον attacker ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | Το `coreaudiod` διέθετε το `com.apple.private.tcc.manager` **και** είχε απενεργοποιημένο το library validation, επομένως ένα HAL plug-in που τοποθετούνταν στο `/Library/Audio/Plug-Ins/HAL` μπορούσε να εκχωρήσει αυθαίρετα δικαιώματα TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Αναφορές

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
