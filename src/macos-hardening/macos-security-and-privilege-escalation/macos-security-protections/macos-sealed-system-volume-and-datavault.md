# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

Ξεκινώντας με **macOS Big Sur (11.0)**, ο όγκος συστήματος είναι κρυπτογραφικά σφραγισμένος χρησιμοποιώντας ένα **APFS snapshot hash tree**. Αυτό ονομάζεται **Sealed System Volume (SSV)**. Το διαμέρισμα συστήματος προσαρτάται ως **read-only** και οποιαδήποτε τροποποίηση σπάει τη σφραγίδα, η οποία επαληθεύεται κατά την εκκίνηση.

The SSV provides:
- **Tamper detection** — οποιαδήποτε τροποποίηση στα system binaries/frameworks είναι ανιχνεύσιμη μέσω της σπασμένης κρυπτογραφικής σφραγίδας
- **Rollback protection** — η διαδικασία boot επαληθεύει την ακεραιότητα του system snapshot
- **Rootkit prevention** — ακόμη και ο root δεν μπορεί μόνιμα να τροποποιήσει αρχεία στον system volume (χωρίς να σπάσει τη σφραγίδα)

### Checking SSV Status
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
### Δικαιώματα SSV Writer

Ορισμένα system binaries της Apple έχουν entitlements που τους επιτρέπουν να τροποποιούν ή να διαχειρίζονται τον σφραγισμένο τόμο συστήματος:

| Entitlement | Σκοπός |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Επαναφέρει τον τόμο συστήματος σε προηγούμενο snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Δημιουργεί ένα νέο σφραγισμένο snapshot μετά από ενημερώσεις του συστήματος |
| `com.apple.rootless.install.heritable` | Γράφει σε διαδρομές προστατευμένες από SIP (κληρονομείται από θυγατρικές διεργασίες) |
| `com.apple.rootless.install` | Γράφει σε διαδρομές προστατευμένες από SIP |

### Εύρεση SSV Writers
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
### Σενάρια Επιθέσεων

#### Snapshot Rollback Attack

Εάν ένας επιτιθέμενος παραβιάσει ένα binary με `com.apple.private.apfs.revert-to-snapshot`, μπορεί να **επαναφέρει τον τόμο συστήματος σε κατάσταση πριν από την ενημέρωση**, αποκαθιστώντας γνωστές ευπάθειες:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Η επαναφορά snapshot στην πράξη **αναιρεί ενημερώσεις ασφαλείας**, επαναφέροντας ευπάθειες του kernel και του συστήματος που είχαν ήδη επιδιορθωθεί. Αυτή είναι μία από τις πιο επικίνδυνες ενέργειες που μπορούν να γίνουν σε σύγχρονο macOS.

#### System Binary Replacement

Με bypass του SIP + δυνατότητα εγγραφής στην SSV, ένας επιτιθέμενος μπορεί:

1. Προσαρμόσει (mount) τον system volume σε ανάγνωση/εγγραφή
2. Αντικαταστήσει έναν system daemon ή μια framework βιβλιοθήκη με μια trojaned έκδοση
3. Επανασφραγίσει το snapshot (ή αποδεχτεί τη σπασμένη σφραγίδα εάν το SIP έχει ήδη υποβαθμιστεί)
4. Το rootkit επιμένει μετά από επανεκκινήσεις και είναι αόρατο σε εργαλεία ανίχνευσης στο userland

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass του SIP που επιτρέπει την τροποποίηση της SSV μέσω του `system_installd` |
| CVE-2022-22583 | Παράκαμψη της SSV μέσω του χειρισμού snapshot του PackageKit |
| CVE-2022-46689 | Race condition που επιτρέπει εγγραφές σε αρχεία προστατευμένα από SIP |

---

## DataVault

### Βασικές Πληροφορίες

**DataVault** είναι το επίπεδο προστασίας της Apple για ευαίσθητες βάσεις δεδομένων του συστήματος. Ακόμα και ο **root δεν μπορεί να έχει πρόσβαση σε αρχεία προστατευμένα από το DataVault** — μόνο διεργασίες με συγκεκριμένα entitlements μπορούν να τα διαβάσουν ή να τα τροποποιήσουν. Τα προστατευμένα αποθετήρια περιλαμβάνουν:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Αποφάσεις απορρήτου TCC σε επίπεδο συστήματος |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Αποφάσεις απορρήτου TCC ανά χρήστη |
| Keychain (system) | `/Library/Keychains/System.keychain` | Keychain συστήματος |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Keychain χρήστη |

Η προστασία του DataVault επιβάλλεται στο επίπεδο του filesystem χρησιμοποιώντας extended attributes και volume protection flags, με επαλήθευση από τον kernel.

### DataVault Controller Entitlements
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
### Σενάρια Επιθέσεων

#### Άμεση Τροποποίηση Βάσης Δεδομένων TCC

Εάν ένας attacker συμβιβάσει ένα DataVault controller binary (π.χ., μέσω code injection σε μια διεργασία με `com.apple.private.tcc.manager`), μπορεί να **τροποποιήσει άμεσα τη βάση δεδομένων TCC** για να χορηγήσει σε οποιαδήποτε εφαρμογή οποιαδήποτε άδεια TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Η τροποποίηση της TCC database είναι το **ultimate privacy bypass** — χορηγεί οποιαδήποτε άδεια αθόρυβα, χωρίς καμία προτροπή χρήστη ή εμφανές δείκτη. Ιστορικά, πολλές αλυσίδες macOS privilege escalation έχουν καταλήξει με εγγραφές στην TCC database ως το τελικό payload.

#### Πρόσβαση στη βάση δεδομένων Keychain

Το DataVault προστατεύει επίσης τα αρχεία υποστήριξης (backing files) του Keychain. Ένας παραβιασμένος ελεγκτής DataVault μπορεί:

1. Διαβάσει τα ακατέργαστα αρχεία της keychain database
2. Εξαγάγει κρυπτογραφημένα στοιχεία του keychain
3. Προσπαθήσει αποκρυπτογράφηση εκτός σύνδεσης χρησιμοποιώντας τον κωδικό του χρήστη ή ανακτημένα κλειδιά

### Πραγματικά CVEs που αφορούν DataVault/TCC Bypass

| CVE | Περιγραφή |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Αναφορές

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
