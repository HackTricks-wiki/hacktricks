# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

Ako vam je potreban alat koji automatizuje analizu memorije sa različitim nivoima skeniranja i paralelno pokreće više Volatility3 pluginova, možete koristiti autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Ako želite nešto **brzo i ludo** što će paralelno pokrenuti nekoliko Volatility plugins, možete koristiti: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalacija

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

## Volatility komande

Pristupite zvaničnoj dokumentaciji u [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Napomena o pluginima „list“ nasuprot pluginima „scan“

Volatility ima dva glavna pristupa pluginima, koji se ponekad odražavaju u njihovim nazivima. Plugin „list“ pokušaće da se kreće kroz strukture Windows kernela kako bi dohvatio informacije poput procesa (lociranje i prolazak kroz povezanu listu `_EPROCESS` struktura u memoriji), OS handle-ova (lociranje i izlistavanje tabele handle-ova, dereferenciranje pronađenih pokazivača itd.). Oni se manje-više ponašaju kao Windows API kada bi od njega bilo zatraženo da, na primer, izlista procese.

Zbog toga su plugin-i „list“ prilično brzi, ali su podjednako podložni manipulaciji od strane malware-a kao i Windows API. Na primer, ako malware koristi DKOM da ukloni proces iz povezane liste `_EPROCESS`, on se neće prikazati u Task Manager-u, a neće se prikazati ni u pslist-u.

Plugin-i „scan“, s druge strane, koriste pristup sličan carve-ovanju memorije u potrazi za stvarima koje bi imale smisla kada bi se dereferencirale kao određene strukture. `psscan`, na primer, čita memoriju i pokušava da od nje napravi `_EPROCESS` objekte (koristi skeniranje pool-tag-ova, odnosno pretražuje 4-bajtne stringove koji ukazuju na prisustvo tražene strukture). Prednost je u tome što može da pronađe procese koji su završeni, pa će plugin pronaći strukturu koja se i dalje nalazi u memoriji čak i ako malware manipuliše povezanom listom `_EPROCESS` (pošto ona i dalje mora da postoji da bi proces radio). Nedostatak je to što su plugin-i „scan“ nešto sporiji od plugin-a „list“ i što ponekad mogu proizvesti lažno pozitivne rezultate (proces koji je završen predugo i čiji su delovi strukture prepisani drugim operacijama).

Izvor: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## Profili OS-a

### Volatility3

Kao što je objašnjeno u readme-u, potrebno je da **symbol table OS-a** koji želite da podržite postavite u _volatility3/volatility/symbols_.\
Paketi symbol table-ova za različite operativne sisteme dostupni su za **download** na:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Spoljni profil

Listu podržanih profila možete dobiti pomoću:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Ako želite da koristite **novi profil koji ste preuzeli** (na primer, linux profil), potrebno je da negde kreirate sledeću strukturu fascikli: _plugins/overlays/linux_ i da unutar ove fascikle postavite zip datoteku koja sadrži profil. Zatim, preuzmite broj profila pomoću:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Možete **preuzeti Linux i Mac profile** sa [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

U prethodnom odeljku možete videti da se profil zove `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, a možete ga koristiti za izvršavanje nečega poput:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Otkrivanje profila
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Razlike između imageinfo i kdbgscan**

[**Odavde**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Za razliku od imageinfo, koji jednostavno pruža predloge profila, **kdbgscan** je dizajniran da pouzdano identifikuje ispravan profil i ispravnu KDBG adresu (ako ih ima više). Ovaj plugin pretražuje potpise KDBGHeader povezane sa Volatility profilima i primenjuje provere ispravnosti kako bi smanjio broj lažno pozitivnih rezultata. Nivo detalja izlaza i broj provera ispravnosti koje mogu da se izvrše zavise od toga da li Volatility može da pronađe DTB, pa ako već znate ispravan profil (ili imate predlog profila iz imageinfo), obavezno ga koristite iz .<sup>[[1]](#references)</sup>

Uvek obratite pažnju na **broj procesa koje je kdbgscan pronašao**. Ponekad imageinfo i kdbgscan mogu da pronađu **više od jednog** odgovarajućeg **profila**, ali samo **ispravan profil će imati povezane procese** (to je zato što je za izdvajanje procesa potrebna ispravna KDBG adresa)<sup>[[1]](#references)</sup>
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

**Blok za otklanjanje grešaka kernela**, koji Volatility označava kao **KDBG**, ključan je za forenzičke zadatke koje obavljaju Volatility i različiti debageri. Identifikovan je kao `KdDebuggerDataBlock` i tipa `_KDDEBUGGER_DATA64`, a sadrži važne reference kao što je `PsActiveProcessHead`. Ova konkretna referenca pokazuje na početak liste procesa, čime omogućava izlistavanje svih procesa, što je od ključne važnosti za detaljnu analizu memorije.<sup>[[2]](#references)</sup>

## Informacije o OS-u
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Plugin `banners.Banners` može da se koristi u **vol3 za pokušaj pronalaženja linux bannera** u dump-u.

## Hash-evi/Lozinke

Izdvojite SAM hash-eve, [keširane akreditive domena](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) i [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

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

## Damp memorije

Damp memorije procesa će **izvući sve** iz trenutnog stanja procesa. Modul **procdump** će samo **izvući** **code**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Procesi

### Izlistavanje procesa

Pokušajte da pronađete **sumnjive** procese (prema imenu) ili **neočekivane podređene procese** (na primer, cmd.exe kao podređeni proces iexplorer.exe).\
Može biti korisno **uporediti** rezultat komande pslist sa rezultatom komande psscan kako biste identifikovali skrivene procese.

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

### Dump proc

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

### Komandna linija

Da li je izvršeno nešto sumnjivo?

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

Komandama izvršenim u `cmd.exe` upravlja **`conhost.exe`** (ili **`csrss.exe`** na sistemima starijim od Windows 7). To znači da, ako napadač prekine **`cmd.exe`** pre kreiranja memory dump-a, istoriju komandi sesije je i dalje moguće oporaviti iz memorije procesa **`conhost.exe`**. Da bi se to uradilo, ako se otkrije neuobičajena aktivnost unutar modula konzole, potrebno je kreirati memory dump povezanim procesom **`conhost.exe`**. Zatim, pretraživanjem **strings** unutar ovog dump-a, potencijalno se mogu izdvojiti komandne linije korišćene u sesiji.

### Okruženje

Preuzmite env promenljive svakog pokrenutog procesa. Mogu sadržati neke zanimljive vrednosti.

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

### Privilegije tokena

Proverite tokene privilegija u neočekivanim servisima.\
Moglo bi biti zanimljivo izlistati procese koji koriste neki privilegovani token.

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

Proverite svaki SSID povezan sa procesom.\
Može biti korisno izlistati procese koji koriste SID sa privilegijama (i procese koji koriste neki service SID).

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

### Handle-ovi

Korisno je znati prema kojim drugim fajlovima, ključevima, nitima, procesima... **proces ima handle** (otvorio ih je)

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

### DLL-ovi

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

### Stringovi po procesima

Volatility nam omogućava da proverimo kom kojem procesu pripada string.

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

Takođe omogućava pretragu stringova unutar procesa pomoću modula yarascan:

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

**Windows** prati programe koje pokrećete pomoću funkcije u registry-ju pod nazivom **UserAssist keys**. Ovi ključevi beleže koliko je puta svaki program pokrenut i kada je poslednji put pokrenut.<sup>[[3]](#references)</sup>

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

## Servisi

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

## Mreža

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

### Prikaži dostupne hive-ove

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

### Dobijanje vrednosti

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
## Datotečni sistem

### Montiranje

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

### Skeniranje/dump

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

### Glavna tabela datoteka

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

**NTFS file system** koristi kritičnu komponentu poznatu kao _master file table_ (MFT). Ova tabela sadrži najmanje jedan unos za svaku datoteku na volumenu, uključujući i sam MFT. Važni detalji o svakoj datoteci, kao što su **veličina, vremenske oznake, dozvole i stvarni podaci**, sadržani su u MFT unosima ili u oblastima izvan MFT-a na koje ovi unosi upućuju. Više detalja možete pronaći u [zvaničnoj dokumentaciji](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

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

## Malware

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

### Skeniranje pomoću yara

Koristite ovu skriptu za preuzimanje i spajanje svih yara malware rules sa github-a: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Kreirajte direktorijum _**rules**_ i izvršite skriptu. Ovo će kreirati datoteku pod nazivom _**malware_rules.yar**_ koja sadrži sva yara pravila za malware.

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

## RAZNO

### Eksterni dodaci

Ako želite da koristite eksterne dodatke, uverite se da su fascikle povezane sa dodacima prvi korišćeni parametar.

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

Download it from [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
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

### Simboličke veze

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

Moguće je **čitati bash history iz memorije.** Takođe možete izvući datoteku _.bash_history_, ali ako je to bilo onemogućeno, biće vam drago što možete da koristite ovaj volatility modul

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

### Vremenska linija

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

### Drajveri

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

### Preuzimanje clipboard sadržaja
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Preuzimanje IE istorije
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Preuzimanje teksta iz notepad-a
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
Nisam primio screenshot. Molim vas pošaljite ga ponovo.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** igra ključnu ulogu u upravljanju logičkim particijama memorijskog medija, koje su strukturirane pomoću različitih [sistema datoteka](https://en.wikipedia.org/wiki/File_system). Ne sadrži samo informacije o rasporedu particija već i izvršni kod koji služi kao boot loader. Ovaj boot loader ili direktno pokreće drugu fazu učitavanja OS-a (pogledajte [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) ili funkcioniše zajedno sa [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) svake particije. Za detaljnije informacije pogledajte [MBR Wikipedia stranicu](https://en.wikipedia.org/wiki/Master_boot_record).<sup>[[5]](#references)</sup>

## Reference

- [1] [Volatility, moja cheatsheet lista (1. deo): Identifikacija image-a](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Pronalaženje Kernel Debugger Block-a](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist ključevi](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (lokalni sistemi datoteka) - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [Računar zasnovan na UEFI-ju, zaštitni MBR: šta je to? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: Volatility plugins za malware analizu](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
