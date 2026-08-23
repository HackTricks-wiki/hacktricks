# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Βασικές πληροφορίες

Από το **macOS Big Sur (11.0)**, το system volume είναι κρυπτογραφικά sealed με χρήση ενός **APFS snapshot hash tree**. Αυτό ονομάζεται **Sealed System Volume (SSV)**. Το system partition προσαρτάται σε **read-only** λειτουργία και οποιαδήποτε τροποποίηση καταστρέφει το seal, το οποίο επαληθεύεται κατά την εκκίνηση.<sup>[[11]](#references)</sup>

Το SSV παρέχει:
- **Ανίχνευση tampering** — οποιαδήποτε τροποποίηση σε system binaries/frameworks αλλάζει το Merkle-tree root και ακυρώνει το Apple-signed seal
- **Authentication κατά την εκκίνηση** — η boot chain επαληθεύει το επιλεγμένο system snapshot πριν αυτό γίνει το root filesystem
- **Ανθεκτικότητα σε rootkits** — ακόμη και ο root δεν μπορεί να αντικαταστήσει μόνιμα αρχεία στο authenticated system snapshot χωρίς να απενεργοποιήσει το authenticated root ή να παραβιάσει ένα εξουσιοδοτημένο update path

Το SSV προστατεύει το **System** volume, όχι το εγγράψιμο **Data** volume που είναι συνδεδεμένο με αυτό. Τα Firmlinks συγχωνεύουν και τα δύο volumes στο namespace που είναι ορατό στο `/`, επομένως ένα path που φαίνεται εγγράψιμο δεν αποδεικνύει ότι το underlying object ανήκει στο sealed snapshot. Το FileVault και το Data Protection καλύπτουν την εμπιστευτικότητα των δεδομένων σε κατάσταση ηρεμίας· είναι ξεχωριστά από την ακεραιότητα του SSV.<sup>[[11]](#references)</sup>

### Έλεγχος κατάστασης SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### Αποτελεσματική προβολή συστήματος: SSV + Cryptex grafts

Σε πρόσφατες εκδόσεις του macOS, δεν προέρχεται απαραίτητα κάθε executable που εμφανίζεται κάτω από το `/System` από το εκκινημένο SSV snapshot. Τα **Cryptexes** είναι ξεχωριστά authenticated APFS disk images, των οποίων το περιεχόμενο γίνεται graft πάνω από επιλεγμένους καταλόγους· επομένως, τα Rapid Security Responses μπορούν να αντικαθιστούν security-sensitive components χωρίς να απαιτείται rebuilding του βασικού SSV. Κατά το triaging persistence ή το diffing system code, κάντε inventory των live mounts και του Preboot Cryptex store αντί να κάνετε hashing μόνο του base snapshot:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Η αλυσίδα εκκίνησης και οι λεπτομέρειες του Rapid Security Response καλύπτονται στο [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)· αυτή η ενότητα εστιάζει στο ίδιο το όριο του SSV.

### Entitlements για SSV Writers

Ορισμένα δυαδικά αρχεία συστήματος της Apple διαθέτουν entitlements που τους επιτρέπουν να τροποποιούν ή να διαχειρίζονται το sealed system volume:

| Entitlement | Σκοπός |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Επαναφορά του system volume σε προηγούμενο snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Δημιουργία νέου sealed snapshot μετά από system updates |
| `com.apple.rootless.install.heritable` | Εγγραφή σε διαδρομές που προστατεύονται από το SIP (κληρονομείται από child processes) |
| `com.apple.rootless.install` | Εγγραφή σε διαδρομές που προστατεύονται από το SIP |

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

Αν ένας attacker θέσει υπό έλεγχο ένα binary με το `com.apple.private.apfs.revert-to-snapshot`, μπορεί να **επαναφέρει το system volume σε κατάσταση πριν από ένα update**, επαναφέροντας γνωστά vulnerabilities:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Η επαναφορά snapshot ουσιαστικά **αναιρεί τις ενημερώσεις ασφαλείας**, επαναφέροντας προηγουμένως διορθωμένες ευπάθειες του kernel και του συστήματος. Πρόκειται για μία από τις πιο επικίνδυνες δυνατές ενέργειες σε σύγχρονα macOS.

#### System Binary Replacement

Με παράκαμψη του SIP και δυνατότητα εγγραφής στο SSV, ένας attacker μπορεί να:

1. Κάνει mount το system volume με δυνατότητα read-write
2. Αντικαταστήσει ένα system daemon ή framework library με trojaned έκδοση
3. Επανασφραγίσει το snapshot ή να αποδεχτεί το broken seal, αν το SIP έχει ήδη υποβαθμιστεί
4. Το rootkit παραμένει μετά από reboot και δεν είναι ορατό στα userland detection tools

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — παράκαμψη του SIP μέσω κατάχρησης του entitlement `com.apple.rootless.install.heritable` του `system_installd`, ώστε να εκτελούνται αυθαίρετα post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Παράκαμψη του SIP: το `system_installd` τοποθετούσε το post-install script σε φάκελο που προστατεύεται από το SIP κάτω από το `/tmp`, όμως το ίδιο το `/tmp` δεν προστατεύεται από το SIP, επομένως ο φάκελος μπορούσε να αντικατασταθεί με την προσάρτηση ενός image πάνω από αυτόν ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write στο XNU, που επιτρέπει εγγραφές σε read-only αρχεία που ανήκουν στον root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

Το **DataVault** είναι filesystem protection για ευαίσθητα αρχεία και directories, η οποία απαιτεί entitlement. Το BSD flag `UF_DATAVAULT` (`0x00000080`) επισημαίνει ένα object ως απαιτούν entitlement τόσο για read όσο και για write· σε αντίθεση με το κανονικό DAC, το να γίνει κάποιος απλώς **root** ή να λάβει Full Disk Access δεν ικανοποιεί αυτόν τον έλεγχο όσο η προστασία εφαρμόζεται.<sup>[[4]](#references)[[13]](#references)</sup>

Μην χρησιμοποιείτε το “DataVault” ως συνώνυμο κάθε protected database. Οι TCC databases διέπονται από πολιτική ειδικά για TCC/FDA και SIP (δείτε το [macOS TCC](macos-tcc/README.md)), ενώ η πρόσβαση σε keychain items εξαρτάται επίσης από τα Keychain ACLs και την cryptographic protection (δείτε το [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Πραγματικά παραδείγματα DataVault εμφανίζονται συνήθως ως service-owned stores κάτω από το `/private/var/folders/.../0/`, όπως το Screen Time store· το flag εμφανίζεται ως `datavault` στα BSD file flags, όταν είναι δυνατή η εκτέλεση stat στον parent.

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | Πρόσβαση και διαχείριση αντικειμένων `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Διαχείριση αποφάσεων TCC· πρόκειται για σχετική αλλά ξεχωριστή privacy boundary |
| `com.apple.private.tcc.allow` | Παράκαμψη επιλεγμένων TCC services που ονομάζονται στην τιμή του entitlement |
| `com.apple.rootless.storage.TCC` | Εγγραφή στο SIP-protected TCC store |

Μία process που συνδυάζει entitlement DataVault-controller με λειτουργικότητα FDA, backup, indexing ή IPC είναι ιδιαίτερα ενδιαφέρουσα: αναζητήστε ένα confused-deputy primitive που αντιγράφει ένα protected object σε ένα ordinary path, αντί να προσπαθεί να ανοίξει απευθείας το vault.<sup>[[14]](#references)</sup>

### Finding DataVault Controllers
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
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

#### Άμεση Τροποποίηση της Βάσης Δεδομένων TCC (ξεχωριστό όριο TCC)

Αν ένας attacker παραβιάσει μια διεργασία TCC manager (π.χ. μέσω code injection σε μια διεργασία που διαθέτει `com.apple.private.tcc.manager`), μπορεί να **τροποποιήσει άμεσα τη βάση δεδομένων TCC**, ώστε να εκχωρήσει σε οποιαδήποτε εφαρμογή οποιοδήποτε δικαίωμα TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Η τροποποίηση της βάσης δεδομένων TCC είναι το **απόλυτο privacy bypass** — παρέχει αθόρυβα οποιαδήποτε άδεια, χωρίς κανένα prompt χρήστη ή ορατή ένδειξη. Ιστορικά, πολλές αλυσίδες privilege escalation στο macOS έχουν καταλήξει σε εγγραφές στη βάση δεδομένων TCC ως τελικό payload.

#### Πρόσβαση στη βάση δεδομένων Keychain

Η άμεση πρόσβαση σε μια υποστηρικτική βάση δεδομένων Keychain δεν ισοδυναμεί με πρόσβαση σε plaintext secrets. Αν ένα άλλο privilege boundary επιτρέπει σε έναν attacker να αντιγράψει τη βάση δεδομένων, πρέπει και πάλι να γίνει επίθεση στο key material και στα item ACLs· δείτε τη dedicated σελίδα [macOS Keychain](../../macos-red-teaming/macos-keychain.md) αντί να υποθέσετε ότι ένα entitlement του DataVault-controller αρκεί.

#### Όριο αντιγράφου backup: Time Machine

Μια ανάλυση του 2026 κατέδειξε ένα χρήσιμο γενικό pattern: το `backupd` διαθέτει τόσο το `com.apple.rootless.datavault.controller` όσο και Full Disk Access, ώστε να μπορεί να αντιγράφει protected stores. Στη configuration που εξετάστηκε, το `/private/var/folders` περιλαμβανόταν στο Time Machine και το mounted backup copy δεν εφάρμοζε το live DataVault boundary. Ο researcher το χρησιμοποίησε για να εντοπίσει το SQLite store του Screen Time και να διαβάσει το plaintext restrictions PIN του, χωρίς να ανοίξει το live vault. Αντιμετωπίστε το ως **copy-boundary attack**: κάντε enumerate τους backup, export, migration, indexing και diagnostic deputies που μπορούν να materialize vault data κάτω από ένα weaker mount ή path.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Αυτή η συμπεριφορά εξαρτάται από την έκδοση και τη διάταξη των backup. Επικύρωσέ την στο build-στόχο και θυμήσου ότι ένας κρυπτογραφημένος προορισμός Time Machine προστατεύει το αντίγραφο μόνο όσο είναι κλειδωμένος· μόλις προσαρτηθεί, οι έλεγχοι πρόσβασης γίνονται μέρος της επιφάνειας επίθεσης.

### CVEs από τον πραγματικό κόσμο που περιλαμβάνουν παράκαμψη DataVault/TCC

| CVE | Περιγραφή |
|---|---|
| CVE-2024-44131 | Race condition με symlink στο FileProvider, που επιτρέπει σε έναν privileged helper να αποκτήσει πρόσβαση σε δεδομένα που προστατεύονται από το TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Ως root, **δημιουργία νέου χρήστη του οποίου το `NFSHomeDirectory` δείχνει σε ένα `TCC.db` που ελέγχεται από τον attacker**· κατά τη σύνδεση, το `tccd` το καταναλώνει και οι grants εφαρμόζονται, επιτρέποντας πρόσβαση στα δεδομένα άλλων χρηστών ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": αλλαγή του home dir του χρήστη για την τοποθέτηση ενός TCC.db που ελέγχεται από τον attacker ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Ελάττωμα στο bundle conclusion που επιτρέπει σε μια εφαρμογή να **κληρονομήσει τα TCC grants ενός donor bundle** χωρίς prompt· εκμεταλλεύτηκε στη φύση από το **XCSSET** για τη λήψη screenshot της επιφάνειας εργασίας ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | Το `tccd` κατασκεύαζε το DB path από το `$HOME`, επομένως το `launchctl setenv HOME` το ανακατεύθυνε σε ένα `TCC.db` που ελέγχεται από τον attacker ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | Το `coreaudiod` διέθετε το `com.apple.private.tcc.manager` **και** είχε απενεργοποιημένο το library validation, επομένως ένα HAL plug-in που τοποθετούνταν στο `/Library/Audio/Plug-Ins/HAL` μπορούσε να εκχωρήσει αυθαίρετα δικαιώματα TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Η Microsoft εντοπίζει μια νέα ευπάθεια στο macOS, τη Shrootless, που θα μπορούσε να παρακάμψει το System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Τεχνική ανάλυση: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Αξίζει να γίνει άσχημα](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Προστασία δεδομένων](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: Η παράκαμψη TCC κλέβει δεδομένα από το iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Αποκάλυψη malware στο macOS: Παράκαμψη TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Νέα ευπάθεια στο macOS, "powerdir", που θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση σε δεδομένα χρηστών](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Εντοπίστηκε zero-day παράκαμψη TCC στο malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Παράκαμψη του macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Παίξε μουσική και παράκαμψε το TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Ο εφιάλτης των Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Εκμετάλλευση TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Πώς να παρακάμψετε τον δικό σας κωδικό Screen Time — ανάλυση source και Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
