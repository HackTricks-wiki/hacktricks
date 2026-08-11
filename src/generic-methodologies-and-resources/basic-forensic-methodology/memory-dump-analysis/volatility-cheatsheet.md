# Volatility - Φύλλο αναφοράς

{{#include ../../../banners/hacktricks-training.md}}

Αν χρειάζεστε ένα εργαλείο που αυτοματοποιεί την ανάλυση μνήμης με διαφορετικά επίπεδα σάρωσης και εκτελεί πολλαπλά Volatility3 plugins παράλληλα, μπορείτε να χρησιμοποιήσετε το autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Αν θέλετε κάτι **γρήγορο και τρελό** που θα εκτελεί πολλά Volatility plugins παράλληλα, μπορείτε να χρησιμοποιήσετε: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Εγκατάσταση

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{{#tabs}}
{{#tab name="Method1"}}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{{#endtab}}

{{#tab name="Method 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Εντολές Volatility

Πρόσβαση στο επίσημο documentation στο [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Μια σημείωση σχετικά με τα plugins “list” και “scan”

Τα plugins `list` διατρέχουν δομές που διατηρεί ο kernel, επομένως είναι γρήγορα, αλλά ενδέχεται να παραλείψουν objects από τα οποία το malware έχει αποσυνδεθεί. Τα plugins `scan`, όπως το `psscan`, αναζητούν signatures objects στη μνήμη· μπορούν να ανακτήσουν τερματισμένες ή αποσυνδεδεμένες διεργασίες, αλλά είναι πιο αργά και ενδέχεται να παράγουν false positives όταν οι residual δομές έχουν υποστεί ζημιά.<sup>[[8]](#references)</sup>

## Προφίλ OS

### Volatility3

Το Volatility 3 απαιτεί symbol tables για το target operating system. Το README του project παραθέτει packs για Windows, Mac και Linux· τοποθετήστε τα στο `volatility3/symbols` ή σε έναν κατάλογο `symbols` δίπλα στο executable. Τα Windows symbols που λείπουν μπορούν να ληφθούν και να δημιουργηθούν αυτόματα, ενώ οι Mac και Linux tables ενδέχεται να πρέπει να παραχθούν ξεχωριστά.<sup>[[9]](#references)</sup>

Symbol table packs για τα διάφορα operating systems είναι διαθέσιμα για **download** στη διεύθυνση:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

Μπορείτε να λάβετε τη λίστα των υποστηριζόμενων profiles εκτελώντας:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Αν θέλετε να χρησιμοποιήσετε ένα **νέο profile που έχετε κατεβάσει** (για παράδειγμα ένα linux), πρέπει να δημιουργήσετε κάπου την ακόλουθη δομή φακέλων: _plugins/overlays/linux_ και να τοποθετήσετε μέσα σε αυτόν τον φάκελο το αρχείο zip που περιέχει το profile. Στη συνέχεια, βρείτε τον αριθμό των profiles χρησιμοποιώντας:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Μπορείτε να **κατεβάσετε Linux και Mac profiles** από το [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Στο προηγούμενο τμήμα μπορείτε να δείτε ότι το profile ονομάζεται `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` και μπορείτε να το χρησιμοποιήσετε για να εκτελέσετε κάτι όπως:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Ανακάλυψη Προφίλ
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Διαφορές μεταξύ των imageinfo και kdbgscan**

Οι [σημειώσεις της Andrea Fortuna για την αναγνώριση image](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/) εξηγούν ότι το `imageinfo` παράγει προτάσεις για profiles, ενώ το `kdbgscan` πραγματοποιεί σάρωση για signatures KDBG και εφαρμόζει sanity checks, ώστε να εντοπίσει υποψήφια profiles και διευθύνσεις KDBG. Η έξοδός του εξαρτάται εν μέρει από το αν το Volatility μπορεί να εντοπίσει ένα DTB, επομένως κατά την εκτέλεσή του πρέπει να παρέχετε ένα γνωστό ή προτεινόμενο profile.<sup>[[1]](#references)</sup>

Όταν επιστρέφονται πολλοί υποψήφιοι, συγκρίνετε τον αριθμό των processes και των modules: ένας υποψήφιος με μηδενικά processes ή modules είναι λιγότερο αξιόπιστος από έναν με συμπληρωμένες λίστες. Αντιμετωπίστε το ως sanity check και όχι ως απόδειξη ότι ένα profile είναι σωστό.<sup>[[1]](#references)</sup>
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Το `KdDebuggerDataBlock`, γνωστό στο Volatility ως KDBG, είναι μια δομή `_KDDEBUGGER_DATA64` που περιλαμβάνει το `PsActiveProcessHead`, την κεφαλή της λίστας διεργασιών που χρησιμοποιείται για την απαρίθμηση διεργασιών.<sup>[[2]](#references)</sup>

## Πληροφορίες λειτουργικού συστήματος
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Το plugin `banners.Banners` μπορεί να χρησιμοποιηθεί στο **vol3 για να προσπαθήσει να εντοπίσει linux banners** στο dump.

## Hashes/Κωδικοί πρόσβασης

Εξαγάγετε SAM hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) και [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{{#endtab}}
{{#endtabs}}

## Αποτύπωση Μνήμης

Η αποτύπωση μνήμης μιας διεργασίας θα **εξαγάγει τα πάντα** σχετικά με την τρέχουσα κατάσταση της διεργασίας. Η ενότητα **procdump** θα **εξαγάγει** μόνο τον **κώδικα**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Διεργασίες

### Λίστα διεργασιών

Προσπαθήστε να εντοπίσετε **ύποπτες** διεργασίες (με βάση το όνομα) ή **μη αναμενόμενες** θυγατρικές **διεργασίες** (για παράδειγμα, ένα cmd.exe ως θυγατρική διεργασία του iexplorer.exe).\
Μπορεί να είναι χρήσιμο να **συγκρίνετε** το αποτέλεσμα του pslist με εκείνο του psscan, ώστε να εντοπίσετε κρυφές διεργασίες.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{{#endtab}}
{{#endtabs}}

### Απόρριψη διεργασίας

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

### Γραμμή εντολών

Εκτελέστηκε κάτι ύποπτο;

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{{#endtab}}
{{#endtabs}}

Οι εντολές που εκτελούνται στο `cmd.exe` διαχειρίζονται από το **`conhost.exe`** (ή το **`csrss.exe`** σε συστήματα πριν από τα Windows 7). Αυτό σημαίνει ότι, αν το **`cmd.exe`** τερματιστεί από έναν attacker πριν από τη λήψη ενός memory dump, εξακολουθεί να είναι δυνατή η ανάκτηση του command history της συνεδρίας από τη μνήμη του **`conhost.exe`**. Για να γίνει αυτό, αν εντοπιστεί ασυνήθιστη δραστηριότητα μέσα στα modules της κονσόλας, θα πρέπει να γίνει dump της μνήμης της σχετικής διεργασίας **`conhost.exe`**. Στη συνέχεια, με αναζήτηση για **strings** μέσα σε αυτό το dump, μπορούν ενδεχομένως να εξαχθούν οι command lines που χρησιμοποιήθηκαν στη συνεδρία.

### Περιβάλλον

Λάβετε τις μεταβλητές περιβάλλοντος κάθε εκτελούμενης διεργασίας. Ενδέχεται να υπάρχουν ενδιαφέρουσες τιμές.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{{#endtab}}
{{#endtabs}}

### Προνόμια token

Ελέγξτε για tokens προνομίων σε μη αναμενόμενες υπηρεσίες.\
Ίσως είναι χρήσιμο να καταγράψετε τις διεργασίες που χρησιμοποιούν κάποιο token με προνόμια.

{{#tabs}}
{{#tab name="vol3"}}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}
{{#endtabs}}

### SIDs

Ελέγξτε κάθε SSID που ανήκει σε μια διεργασία.\
Ίσως είναι ενδιαφέρον να καταγράψετε τις διεργασίες που χρησιμοποιούν ένα privileges SID (και τις διεργασίες που χρησιμοποιούν κάποιο service SID).

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{{#endtab}}
{{#endtabs}}

### Handles

Χρήσιμο να γνωρίζετε για ποια άλλα αρχεία, κλειδιά, threads, διεργασίες... ένα **process έχει handle** (έχει ανοίξει)

{{#tabs}}
{{#tab name="vol3"}}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{{#endtab}}
{{#endtabs}}

### DLLs

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{{#endtab}}
{{#endtabs}}

### Strings ανά διεργασία

Το Volatility μάς επιτρέπει να ελέγξουμε σε ποια διεργασία ανήκει ένα string.

{{#tabs}}
{{#tab name="vol3"}}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{{#endtab}}
{{#endtabs}}

Επιτρέπει επίσης την αναζήτηση συμβολοσειρών μέσα σε μια διεργασία χρησιμοποιώντας το module yarascan:

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{{#endtab}}
{{#endtabs}}

### UserAssist

Οι τιμές μητρώου `UserAssist` καταγράφουν τα προγράμματα που εκκινούνται μέσω του Windows Explorer, συμπεριλαμβανομένων των μετρητών εκτέλεσης και των χρονικών σημάνσεων τελευταίας εκτέλεσης· οι εκκινήσεις μέσω γραμμής εντολών δεν καταγράφονται σε αυτά τα κλειδιά.<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{{#endtab}}
{{#endtabs}}

## Υπηρεσίες

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Δίκτυο

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{{#endtab}}
{{#endtabs}}

## Registry hive

### Εμφάνιση διαθέσιμων hives

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{{#endtab}}
{{#endtabs}}

### Λήψη μιας τιμής

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{{#endtab}}
{{#endtabs}}

### Dump
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Σύστημα αρχείων

### Προσάρτηση

{{#tabs}}
{{#tab name="vol3"}}
```bash
#See vol2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{{#endtab}}
{{#endtabs}}

### Σάρωση/απόρριψη

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{{#endtab}}
{{#endtabs}}

### Κύριος Πίνακας Αρχείων

{{#tabs}}
{{#tab name="vol3"}}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{{#endtab}}
{{#endtabs}}

Στο NTFS, το MFT έχει τουλάχιστον μία καταχώριση ανά αρχείο στον τόμο, συμπεριλαμβανομένου του ίδιου. Τα metadata και τα περιεχόμενα των αρχείων αποθηκεύονται σε καταχωρίσεις του MFT ή σε τοποθεσίες που περιγράφονται από αυτές τις καταχωρίσεις· δείτε την [τεκμηρίωση της Microsoft](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

### SSL Keys/Certs

{{#tabs}}
{{#tab name="vol3"}}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Κακόβουλο λογισμικό

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{{#endtab}}
{{#endtabs}}

### Scanning με yara

Χρησιμοποιήστε αυτό το script για να κατεβάσετε και να συγχωνεύσετε όλους τους κανόνες malware του yara από το github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Δημιουργήστε τον κατάλογο _**rules**_ και εκτελέστε το. Αυτό θα δημιουργήσει ένα αρχείο με το όνομα _**malware_rules.yar**_, το οποίο περιέχει όλους τους κανόνες yara για malware.

{{#tabs}}
{{#tab name="vol3"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{{#endtab}}
{{#endtabs}}

## ΔΙΑΦΟΡΑ

### Εξωτερικά plugins

Αν θέλετε να χρησιμοποιήσετε εξωτερικά plugins, βεβαιωθείτε ότι οι φάκελοι που σχετίζονται με τα plugins είναι η πρώτη παράμετρος που χρησιμοποιείται.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{{#endtab}}
{{#endtabs}}

#### Autoruns

Κατεβάστε το από [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns).
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{{#endtab}}
{{#endtabs}}

### Symlinks

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{{#endtab}}
{{#endtabs}}

### Bash

Είναι δυνατό να **διαβάσετε από τη μνήμη το ιστορικό του bash.** Θα μπορούσατε επίσης να κάνετε dump του αρχείου _.bash_history_, αλλά αν αυτό ήταν απενεργοποιημένο, θα χαρείτε που μπορείτε να χρησιμοποιήσετε αυτό το volatility module.

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp linux.bash.Bash
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{{#endtab}}
{{#endtabs}}

### Χρονολόγιο

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{{#endtab}}
{{#endtabs}}

### Προγράμματα οδήγησης

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{{#endtab}}
{{#endtabs}}

### Λήψη clipboard
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Λήψη ιστορικού IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Λήψη κειμένου από το notepad
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
Δεν παρέχεται εικόνα ή κείμενο προς μετάφραση.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Κύρια εγγραφή εκκίνησης (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Σε συστήματα που βασίζονται σε BIOS, το MBR στον τομέα 0 περιέχει τον κύριο κώδικα εκκίνησης και τον πίνακα διαμερισμάτων. Η Microsoft τεκμηριώνει ότι το `bootsect /mbr` ενημερώνει τον κώδικα χωρίς να αλλάζει τον συγκεκριμένο πίνακα.<sup>[[7]](#references)</sup>

## References

- [1] [Volatility, το δικό μου cheatsheet (Μέρος 1): Αναγνώριση Image](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Εύρεση του Kernel Debugger Block](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (Τοπικά File Systems) - Εφαρμογές Win32](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [PC που βασίζεται σε UEFI, protective MBR: τι είναι; - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Οδηγός: Volatility plugins για ανάλυση malware](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)
- [7] [Επιλογές γραμμής εντολών του Bootsect](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bootsect-command-line-options?view=windows-11)
- [8] [Οδηγός - Volatility plugins και ανάλυση malware](https://tomchop.me/posts/volatility-plugin-malware-analysis/)
- [9] [Volatility 3 README](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
{{#include ../../../banners/hacktricks-training.md}}
