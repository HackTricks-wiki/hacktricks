# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

​


Ikiwa unahitaji chombo kinachoweza kujiendesha kwa uchambuzi wa kumbukumbu kwa viwango tofauti vya skana na kuendesha plugins nyingi za Volatility3 kwa wakati mmoja, unaweza kutumia autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Ikiwa unataka kitu **haraka na cha ajabu** ambacho kitazindua plugins kadhaa za Volatility kwa pamoja unaweza kutumia: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installation

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

## Amri za Volatility

Fikia hati rasmi katika [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Kumbukumbu kuhusu plugins “list” vs. “scan”

Volatility ina mbinu mbili kuu za plugins, ambazo wakati mwingine zinaonekana katika majina yao. Plugins “list” zitajaribu kuvinjari kupitia muundo wa Windows Kernel ili kupata taarifa kama vile michakato (kupata na kutembea kwenye orodha iliyounganishwa ya `_EPROCESS` katika kumbukumbu), kushughulikia OS (kupata na kuorodhesha jedwali la kushughulikia, kuondoa viashiria vyovyote vilivyopatikana, nk). Zinajitahidi kutenda kama API ya Windows ingekuwa ikiwa itaombwa, kwa mfano, kuorodhesha michakato.

Hiyo inafanya plugins “list” kuwa za haraka, lakini pia zina hatari kama API ya Windows kwa ushawishi wa malware. Kwa mfano, ikiwa malware inatumia DKOM kuondoa mchakato kutoka kwenye orodha iliyounganishwa ya `_EPROCESS`, haitajitokeza katika Meneja wa Kazi wala katika pslist.

Plugins “scan”, kwa upande mwingine, zitachukua mbinu inayofanana na kuchonga kumbukumbu kwa vitu ambavyo vinaweza kuwa na maana wakati vinapondolewa kama muundo maalum. `psscan` kwa mfano itasoma kumbukumbu na kujaribu kutengeneza vitu vya `_EPROCESS` kutoka kwake (inatumia skanning ya pool-tag, ambayo inatafuta nyuzi za 4-byte zinazonyesha uwepo wa muundo wa interest). Faida ni kwamba inaweza kupata michakato ambayo imeondoka, na hata kama malware inaharibu orodha iliyounganishwa ya `_EPROCESS`, plugin bado itapata muundo huo ukiwa katika kumbukumbu (kwa kuwa bado inahitaji kuwepo ili mchakato ufanye kazi). Hasara ni kwamba plugins “scan” ni polepole kidogo kuliko plugins “list”, na wakati mwingine zinaweza kutoa matokeo yasiyo sahihi (mchakato ambao umeondoka kwa muda mrefu sana na sehemu za muundo wake zimeandikwa upya na operesheni nyingine).

Kutoka: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profaili za OS

### Volatility3

Kama ilivyoelezwa ndani ya readme unahitaji kuweka **meza ya alama ya OS** unayotaka kusaidia ndani ya _volatility3/volatility/symbols_.\
Pakiti za meza za alama za mifumo mbalimbali ya uendeshaji zinapatikana kwa **kupakua** katika:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profaili za Nje

Unaweza kupata orodha ya profaili zinazosaidiwa kwa kufanya:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Ikiwa unataka kutumia **wasifu mpya ulio pakuliwa** (kwa mfano wa linux) unahitaji kuunda mahali fulani muundo wa folda ufuatao: _plugins/overlays/linux_ na kuweka ndani ya folda hii faili ya zip inayoshikilia wasifu. Kisha, pata nambari ya wasifu kwa kutumia:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Unaweza **kupakua profaili za Linux na Mac** kutoka [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Katika kipande kilichopita unaweza kuona kwamba profaili inaitwa `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, na unaweza kuitumia kutekeleza kitu kama:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Gundua Profaili
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Tofauti kati ya imageinfo na kdbgscan**

[**Kutoka hapa**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Kinyume na imageinfo ambayo inatoa tu mapendekezo ya wasifu, **kdbgscan** imeundwa kubaini kwa uhakika wasifu sahihi na anwani sahihi ya KDBG (ikiwa kuna nyingi). Plugin hii inatafuta saini za KDBGHeader zinazohusiana na wasifu wa Volatility na inatekeleza ukaguzi wa akili ili kupunguza matokeo yasiyo sahihi. Ufanisi wa matokeo na idadi ya ukaguzi wa akili wanaoweza kufanywa inategemea ikiwa Volatility inaweza kupata DTB, hivyo ikiwa tayari unajua wasifu sahihi (au ikiwa una pendekezo la wasifu kutoka imageinfo), basi hakikisha unalitumia kutoka .

Daima angalia **idadi ya michakato ambayo kdbgscan imepata**. Wakati mwingine imageinfo na kdbgscan zinaweza kupata **zaidi ya moja** wasifu **unaofaa** lakini tu **ule halali utakuwa na mchakato wowote unaohusiana** (Hii ni kwa sababu ili kutoa michakato anwani sahihi ya KDBG inahitajika)
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

**KDBG** inaitwa **kernel debugger block**, ni muhimu kwa kazi za forensics zinazofanywa na Volatility na debuggers mbalimbali. Inatambulika kama `KdDebuggerDataBlock` na aina ya `_KDDEBUGGER_DATA64`, ina marejeleo muhimu kama `PsActiveProcessHead`. Marejeleo haya maalum yanaonyesha kichwa cha orodha ya michakato, kuruhusu orodha ya michakato yote, ambayo ni ya msingi kwa uchambuzi wa kina wa kumbukumbu.

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Plugin `banners.Banners` inaweza kutumika katika **vol3 kujaribu kupata mabango ya linux** katika dump.

## Hashes/Passwords

Toa SAM hashes, [credentials za domain zilizohifadhiwa](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) na [siri za lsa](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

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

## Memory Dump

Memory dump ya mchakato itatoa **kila kitu** cha hali ya sasa ya mchakato. Moduli ya **procdump** itatoa tu **kanuni**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Mchakato

### Orodha ya michakato

Jaribu kutafuta **michakato** ya **shaka** (kwa jina) au **michakato** ya mtoto isiyotarajiwa (kwa mfano cmd.exe kama mtoto wa iexplorer.exe).\
Inaweza kuwa ya kuvutia **kulinganisha** matokeo ya pslist na yale ya psscan ili kubaini michakato iliyofichwa.

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

### Command line

Je, kuna kitu chochote kinachoshuku kilitekelezwa?

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

Amri zinazotekelezwa katika `cmd.exe` zinadhibitiwa na **`conhost.exe`** (au `csrss.exe` kwenye mifumo kabla ya Windows 7). Hii ina maana kwamba ikiwa **`cmd.exe`** itakatishwa na mshambuliaji kabla ya kupatikana kwa dump ya kumbukumbu, bado inawezekana kurejesha historia ya amri za kikao kutoka kwenye kumbukumbu ya **`conhost.exe`**. Ili kufanya hivyo, ikiwa shughuli zisizo za kawaida zinagundulika ndani ya moduli za console, kumbukumbu ya mchakato wa **`conhost.exe`** inayohusiana inapaswa kutolewa. Kisha, kwa kutafuta **strings** ndani ya dump hii, mistari ya amri zilizotumika katika kikao inaweza kutolewa.

### Mazingira

Pata vigezo vya env vya kila mchakato unaotembea. Kunaweza kuwa na thamani za kuvutia. 

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

### Token privileges

Angalia kwa token za mamlaka katika huduma zisizotarajiwa.\
Inaweza kuwa ya kuvutia kuorodhesha michakato inayotumia token fulani za mamlaka.

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

Angalia kila SSID inayomilikiwa na mchakato.\
Inaweza kuwa ya kuvutia kuorodhesha michakato inayotumia SID ya ruhusa (na michakato inayotumia SID ya huduma). 

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

Ni muhimu kujua ni faili, funguo, nyuzi, michakato... zipi **mchakato una mkono** kwa ajili ya (amefungua)

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

### Mifumo ya nyuzi kwa michakato

Volatility inatuwezesha kuangalia ni mchakato gani nyuzi inahusiana nayo.

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

Inaruhusu pia kutafuta nyuzi ndani ya mchakato kwa kutumia moduli ya yarascan:

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

**Windows** inashika rekodi ya programu unazotumia kwa kutumia kipengele katika rejista kinachoitwa **UserAssist keys**. Funguo hizi zinaandika ni mara ngapi kila programu imefanywa na wakati ilifanya mara ya mwisho. 

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

​


## Huduma

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

## Mtandao

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

### Print available hives

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

### Pata thamani

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
## Mfumo wa Faili

### Pandisha

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

### Scan/dump

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

### Jedwali la Faili Kuu

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

Mfumo wa **NTFS** unatumia kipengele muhimu kinachojulikana kama _meza ya faili ya bwana_ (MFT). Meza hii ina angalau kiingilio kimoja kwa kila faili kwenye volumu, ikijumuisha MFT yenyewe pia. Maelezo muhimu kuhusu kila faili, kama vile **ukubwa, alama za muda, ruhusa, na data halisi**, yanajumuishwa ndani ya viingilio vya MFT au katika maeneo ya nje ya MFT lakini yanarejelea na viingilio hivi. Maelezo zaidi yanaweza kupatikana katika [nyaraka rasmi](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Funguo za SSL/Certs

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

### Skanning na yara

Tumia skripti hii kupakua na kuunganisha sheria zote za yara malware kutoka github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Unda saraka ya _**rules**_ na uifanye. Hii itaunda faili inayoitwa _**malware_rules.yar**_ ambayo ina sheria zote za yara za malware.

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

## MISC

### Vionge vya nje

Ikiwa unataka kutumia vionge vya nje hakikisha kwamba folda zinazohusiana na vionge ni kipimo cha kwanza kinachotumika.

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

Pakua kutoka [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
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

Inawezekana **kusoma kutoka kwa kumbukumbu historia ya bash.** Unaweza pia kutupa faili ya _.bash_history_, lakini ilizuiliwa utashukuru unaweza kutumia moduli hii ya volatility

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

### Muda

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

### Madereva
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

### Pata clipboard
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Pata historia ya IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Pata maandiko ya notepad
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Picha ya skrini
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Rekodi ya Kuanza ya Mwalimu (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** ina jukumu muhimu katika kusimamia sehemu za mantiki za kifaa cha kuhifadhi, ambazo zimeundwa na mifumo tofauti ya [file systems](https://en.wikipedia.org/wiki/File_system). Haishikilii tu taarifa za mpangilio wa sehemu bali pia ina msimbo unaoweza kutekelezwa ukifanya kazi kama kipakiaji cha boot. Kipakiaji hiki cha boot kinanzisha moja kwa moja mchakato wa upakiaji wa hatua ya pili wa OS (tazama [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) au hufanya kazi kwa ushirikiano na [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) ya kila sehemu. Kwa maarifa ya kina, rejelea [MBR Wikipedia page](https://en.wikipedia.org/wiki/Master_boot_record).

## References

- [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
- [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

{{#include ../../../banners/hacktricks-training.md}}
