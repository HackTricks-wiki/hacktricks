# Sealed System Volume macOS και DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Βασικές πληροφορίες

Από το **macOS Big Sur (11.0)** και μετά, ο τόμος συστήματος σφραγίζεται κρυπτογραφικά με ένα **δέντρο κατακερματισμού snapshot APFS**. Αυτό ονομάζεται **Sealed System Volume (SSV)**. Το διαμέρισμα συστήματος προσαρτάται ως **μόνο για ανάγνωση** και οποιαδήποτε τροποποίησή του καταστρέφει τη σφραγίδα, η οποία επαληθεύεται κατά την εκκίνηση.<sup>[[11]](#references)</sup>

Το SSV παρέχει:
- **Εντοπισμό αλλοίωσης** — οποιαδήποτε τροποποίηση σε δυαδικά αρχεία ή frameworks του συστήματος αλλάζει τη ρίζα του Merkle tree και ακυρώνει τη σφραγίδα που έχει υπογράψει η Apple
- **Έλεγχο ταυτότητας κατά την εκκίνηση** — η αλυσίδα εκκίνησης επαληθεύει το επιλεγμένο snapshot συστήματος πριν αυτό γίνει το root filesystem
- **Ανθεκτικότητα σε rootkit** — ακόμη και ο root δεν μπορεί να αντικαταστήσει μόνιμα αρχεία στο πιστοποιημένο snapshot συστήματος χωρίς να απενεργοποιήσει το authenticated root ή να παραβιάσει μια εξουσιοδοτημένη διαδρομή ενημέρωσης

Το SSV προστατεύει τον τόμο **System**, όχι τον εγγράψιμο τόμο **Data** που είναι συζευγμένος με αυτόν. Τα firmlinks συγχωνεύουν και τους δύο τόμους στον χώρο ονομάτων που είναι ορατός στο `/`, επομένως μια διαδρομή που φαίνεται εγγράψιμη δεν αποδεικνύει ότι το υποκείμενο αντικείμενο ανήκει στο σφραγισμένο snapshot. Το FileVault και το Data Protection καλύπτουν την εμπιστευτικότητα των δεδομένων σε κατάσταση αδράνειας· είναι ξεχωριστά από την ακεραιότητα του SSV.<sup>[[11]](#references)</sup>

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

### Αποτελεσματική προβολή συστήματος: grafts SSV + Cryptex

Σε πρόσφατες εκδόσεις του macOS, δεν προέρχεται κατ’ ανάγκη κάθε εκτελέσιμο που εμφανίζεται κάτω από το `/System` από το ενεργό snapshot του SSV. Τα **Cryptexes** είναι ξεχωριστά, πιστοποιημένα images δίσκου APFS, των οποίων το περιεχόμενο προσαρτάται σε επιλεγμένους καταλόγους. Έτσι, οι Rapid Security Responses μπορούν να αντικαθιστούν στοιχεία ευαίσθητα ως προς την ασφάλεια χωρίς να απαιτείται αναδόμηση του βασικού SSV. Κατά τη διερεύνηση persistence ή τη σύγκριση κώδικα συστήματος, καταγράψτε τα ενεργά mounts και το Preboot Cryptex store, αντί να υπολογίσετε hash μόνο του βασικού snapshot:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Η αλυσίδα εκκίνησης και οι λεπτομέρειες του Rapid Security Response καλύπτονται στο [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)· αυτή η ενότητα εστιάζει στα όρια του SSV.

### Δικαιώματα SSV Writer

Ορισμένα δυαδικά αρχεία συστήματος της Apple διαθέτουν δικαιώματα που τους επιτρέπουν να τροποποιούν ή να διαχειρίζονται τον σφραγισμένο τόμο συστήματος:

| Δικαίωμα | Σκοπός |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Επαναφορά του τόμου συστήματος σε προηγούμενο snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Δημιουργία νέου σφραγισμένου snapshot μετά από ενημερώσεις συστήματος |
| `com.apple.rootless.install.heritable` | Εγγραφή σε διαδρομές που προστατεύονται από SIP (κληρονομείται από τις θυγατρικές διεργασίες) |
| `com.apple.rootless.install` | Εγγραφή σε διαδρομές που προστατεύονται από SIP |

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

Αν ένας attacker παραβιάσει ένα binary με το `com.apple.private.apfs.revert-to-snapshot`, μπορεί να **επαναφέρει το system volume σε κατάσταση πριν από την ενημέρωση**, επαναφέροντας γνωστά vulnerabilities:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Η επαναφορά snapshot ουσιαστικά **αναιρεί τις ενημερώσεις ασφαλείας**, επαναφέροντας ευπάθειες του kernel και του συστήματος που είχαν ήδη επιδιορθωθεί. Πρόκειται για μία από τις πιο επικίνδυνες ενέργειες που μπορούν να πραγματοποιηθούν σε σύγχρονο macOS.

#### Αντικατάσταση Binary Συστήματος

Με παράκαμψη του SIP + δυνατότητα εγγραφής στο SSV, ένας εισβολέας μπορεί να:

1. Προσαρτήσει τον τόμο συστήματος με δικαίωμα ανάγνωσης-εγγραφής
2. Αντικαταστήσει έναν daemon του συστήματος ή μια framework library με trojaned έκδοση
3. Επανασφραγίσει το snapshot (ή αποδεχτεί τη μη έγκυρη σφραγίδα, αν το SIP είναι ήδη υποβαθμισμένο)
4. Το rootkit παραμένει μετά από επανεκκινήσεις και είναι αόρατο στα εργαλεία εντοπισμού του userland

### CVE στον Πραγματικό Κόσμο

| CVE | Περιγραφή |
|---|---|
| CVE-2021-30892 | **Shrootless** — παράκαμψη του SIP που καταχράται το entitlement `com.apple.rootless.install.heritable` του `system_installd` για την εκτέλεση αυθαίρετων post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Παράκαμψη του SIP: το `system_installd` αποθήκευε προσωρινά το post-install script σε φάκελο προστατευμένο από το SIP κάτω από το `/tmp`, αλλά το ίδιο το `/tmp` δεν προστατεύεται από το SIP, επομένως ο φάκελος μπορούσε να αντικατασταθεί με προσάρτηση ενός image πάνω του ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write στο XNU που επιτρέπει εγγραφές σε αρχεία μόνο για ανάγνωση, τα οποία ανήκουν στον root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Βασικές Πληροφορίες

Το **DataVault** είναι προστασία συστήματος αρχείων, ελεγχόμενη από entitlement, για ευαίσθητα αρχεία και καταλόγους. Το BSD flag `UF_DATAVAULT` (`0x00000080`) επισημαίνει ένα αντικείμενο ως απαιτούν entitlement τόσο για ανάγνωση όσο και για εγγραφή· σε αντίθεση με το συνηθισμένο DAC, το να γίνει κάποιος απλώς **root** ή να αποκτήσει Full Disk Access δεν αρκεί για να ικανοποιηθεί αυτός ο έλεγχος όσο η προστασία είναι ενεργή.<sup>[[4]](#references)[[13]](#references)</sup>

Μη χρησιμοποιείτε το «DataVault» ως συνώνυμο για κάθε προστατευμένη βάση δεδομένων. Οι βάσεις δεδομένων TCC διέπονται από πολιτική ειδική για τα TCC/FDA και το SIP (βλ. [macOS TCC](macos-tcc/README.md)), ενώ η πρόσβαση σε στοιχεία keychain εξαρτάται επίσης από τα ACL του Keychain και την κρυπτογραφική προστασία (βλ. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Πραγματικά παραδείγματα DataVault εμφανίζονται συχνά ως χώροι αποθήκευσης που ανήκουν σε υπηρεσίες, κάτω από το `/private/var/folders/.../0/`, όπως ο χώρος αποθήκευσης του Screen Time· το flag εμφανίζεται ως `datavault` στα BSD file flags, όταν είναι δυνατή η εκτέλεση stat στον γονικό κατάλογο.

### Entitlements Ελεγκτών DataVault

| Entitlement | Όριο |
|---|---|
| `com.apple.rootless.datavault.controller` | Πρόσβαση/διαχείριση αντικειμένων `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Διαχείριση αποφάσεων TCC· πρόκειται για σχετικό, αλλά ξεχωριστό, όριο απορρήτου |
| `com.apple.private.tcc.allow` | Παράκαμψη επιλεγμένων υπηρεσιών TCC που αναφέρονται στην τιμή του entitlement |
| `com.apple.rootless.storage.TCC` | Εγγραφή στον χώρο αποθήκευσης TCC που προστατεύεται από το SIP |

Μια διεργασία που συνδυάζει entitlement ελεγκτή DataVault με λειτουργίες FDA, backup, indexing ή IPC είναι ιδιαίτερα ενδιαφέρουσα: αναζητήστε ένα confused-deputy primitive που αντιγράφει ένα προστατευμένο αντικείμενο σε μια συνηθισμένη διαδρομή, αντί να επιχειρεί να ανοίξει απευθείας το vault.<sup>[[14]](#references)</sup>

### Εντοπισμός Ελεγκτών DataVault

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

### Σενάρια επίθεσης

#### Άμεση τροποποίηση της βάσης δεδομένων TCC (ξεχωριστό όριο TCC)

Αν ένας attacker παραβιάσει μια διεργασία διαχείρισης TCC (π.χ. μέσω code injection σε μια διεργασία που διαθέτει το `com.apple.private.tcc.manager`), μπορεί να **τροποποιήσει απευθείας τη βάση δεδομένων TCC** ώστε να παραχωρήσει οποιοδήποτε δικαίωμα TCC σε οποιαδήποτε εφαρμογή:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Η τροποποίηση της βάσης δεδομένων TCC είναι η **απόλυτη παράκαμψη απορρήτου** — χορηγεί οποιαδήποτε άδεια σιωπηρά, χωρίς προτροπή προς τον χρήστη ή ορατή ένδειξη. Ιστορικά, πολλές αλυσίδες κλιμάκωσης προνομίων στο macOS ολοκληρώνονταν με εγγραφή στη βάση δεδομένων TCC ως τελικό payload.

#### Πρόσβαση στη βάση δεδομένων Keychain

Η ακατέργαστη πρόσβαση σε μια βάση δεδομένων που υποστηρίζει ένα keychain δεν ισοδυναμεί με πρόσβαση σε μυστικά σε plaintext. Ακόμη κι αν ένα άλλο όριο προνομίων επιτρέψει σε έναν εισβολέα να αντιγράψει τη βάση δεδομένων, εξακολουθεί να πρέπει να παραβιάσει τα κλειδιά κρυπτογράφησης και τα ACL των στοιχείων· δείτε την ειδική σελίδα [macOS Keychain](../../macos-red-teaming/macos-keychain.md), αντί να θεωρήσετε ότι ένα entitlement DataVault-controller αρκεί.

#### Όριο αντιγράφου ασφαλείας: Time Machine

Μια ανάλυση του 2026 έδειξε ένα χρήσιμο γενικό μοτίβο: το `backupd` διαθέτει τόσο το `com.apple.rootless.datavault.controller` όσο και Full Disk Access, ώστε να μπορεί να αντιγράφει προστατευμένα αποθηκευμένα δεδομένα. Στη διαμόρφωση που δοκιμάστηκε, ο φάκελος `/private/var/folders` συμπεριλαμβανόταν στο Time Machine και το προσαρτημένο αντίγραφο ασφαλείας δεν εφάρμοζε το ενεργό όριο DataVault. Ο ερευνητής το χρησιμοποίησε για να εντοπίσει το SQLite store του Screen Time και να διαβάσει το PIN περιορισμών σε plaintext, χωρίς να ανοίξει το ενεργό vault. Αντιμετωπίστε το ως **επίθεση στο όριο του αντιγράφου**: εντοπίστε deputy για backup, export, migration, indexing και diagnostics που μπορούν να υλοποιήσουν δεδομένα vault σε ασθενέστερο mount ή path.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Αυτή η συμπεριφορά εξαρτάται από την έκδοση και τη διάταξη των backup. Επαλήθευσέ την στο build-στόχο και έχε υπόψη ότι ένας κρυπτογραφημένος προορισμός Time Machine προστατεύει το αντίγραφο μόνο όσο είναι κλειδωμένος· μόλις προσαρτηθεί, τα στοιχεία ελέγχου πρόσβασης γίνονται μέρος της επιφάνειας επίθεσης.

### Πραγματικά CVE που αφορούν DataVault/TCC Bypass

| CVE | Περιγραφή |
|---|---|
| CVE-2024-44131 | symlink race στο FileProvider που επιτρέπει σε έναν privileged helper να αποκτήσει πρόσβαση σε δεδομένα που προστατεύονται από το TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Ως root, **δημιουργία νέου χρήστη του οποίου το `NFSHomeDirectory` δείχνει σε ένα `TCC.db` που ελέγχεται από τον attacker**· κατά τη σύνδεση, το `tccd` το χρησιμοποιεί και εφαρμόζονται τα grants, παρέχοντας πρόσβαση στα δεδομένα άλλων χρηστών ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": αλλαγή του home directory του χρήστη για την τοποθέτηση ενός `TCC.db` που ελέγχεται από τον attacker ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Αδυναμία στο συμπέρασμα του bundle που επιτρέπει σε μια εφαρμογή να **κληρονομήσει τα TCC grants ενός donor bundle** χωρίς prompt· αξιοποιήθηκε στην πράξη από το **XCSSET** για λήψη screenshot της επιφάνειας εργασίας ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | Το `tccd` κατασκεύαζε τη διαδρομή της DB από το `$HOME`, επομένως το `launchctl setenv HOME` την ανακατεύθυνε σε ένα `TCC.db` που ελέγχεται από τον attacker ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | Το `coreaudiod` είχε το `com.apple.private.tcc.manager` **και** είχε απενεργοποιημένη την επικύρωση βιβλιοθηκών, επομένως ένα plug-in HAL τοποθετημένο στο `/Library/Audio/Plug-Ins/HAL` μπορούσε να εκχωρήσει αυθαίρετα δικαιώματα TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Η Microsoft εντοπίζει νέα ευπάθεια στο macOS, το Shrootless, που θα μπορούσε να παρακάμψει το System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Τεχνική ανάλυση: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Αξίζει να το κάνεις άσχημα](https://worthdoingbadly.com/macdirtycow/)
- [4] [Ασφάλεια πλατφορμών Apple — Προστασία δεδομένων](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: Το TCC bypass κλέβει δεδομένα από το iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Αποκάλυψη κακόβουλου λογισμικού macOS: Παράκαμψη του TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Νέα ευπάθεια στο macOS, το "powerdir", θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση σε δεδομένα χρηστών](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Εντοπίστηκε zero-day TCC bypass στο κακόβουλο λογισμικό XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Παράκαμψη του πλαισίου Transparency, Consent, and Control (TCC) του macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Παίξτε μουσική και παρακάμψτε το TCC, γνωστό και ως CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Ο εφιάλτης των OTA ενημερώσεων της Apple (στιγμιότυπα APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Εκμετάλλευση του TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Πώς να παρακάμψετε τον δικό σας κωδικό Screen Time — ανάλυση πηγαίου κώδικα και Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
