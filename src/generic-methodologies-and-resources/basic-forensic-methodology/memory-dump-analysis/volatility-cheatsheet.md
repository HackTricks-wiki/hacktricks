# Volatility - Karatasi ya Marejeo

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa unahitaji tool inayofanya memory analysis kiotomatiki kwa kutumia viwango tofauti vya scanning na kuendesha Volatility3 plugins nyingi kwa wakati mmoja, unaweza kutumia autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Ikiwa unataka kitu **cha haraka na kichaa** kitakachozindua plugins kadhaa za Volatility kwa wakati mmoja, unaweza kutumia: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Usakinishaji

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

Fikia nyaraka rasmi katika [marejeo ya amri za Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Dokezo kuhusu plugins za “list” dhidi ya plugins za “scan”

Volatility ina mbinu kuu mbili za plugins, ambazo wakati mwingine huonekana katika majina yake. Plugins za “list” hujaribu kupitia miundo ya Windows Kernel ili kupata taarifa kama vile processes (kutafuta na kupitia linked list ya miundo ya `_EPROCESS` kwenye memory), OS handles (kutafuta na kuorodhesha handle table, kuondoa marejeo ya pointers yoyote yaliyopatikana, n.k.). Kwa kiasi kikubwa hufanya kazi kama Windows API ingefanya ikiwa ingeombwa, kwa mfano, kuorodhesha processes.

Hilo huzifanya plugins za “list” kuwa za haraka, lakini pia zikiwa hatarini kwa kiwango sawa na Windows API dhidi ya manipulation inayofanywa na malware. Kwa mfano, ikiwa malware itatumia DKOM kuondoa process kwenye `_EPROCESS` linked list, haitaonekana katika Task Manager wala katika pslist.

Kwa upande mwingine, plugins za “scan” hutumia mbinu inayofanana na kuchonga memory ili kutafuta vitu ambavyo vinaweza kuwa na maana vinaporejelewa kama miundo maalum. Kwa mfano, `psscan` itasoma memory na kujaribu kutengeneza vitu vya `_EPROCESS` kutoka humo (hutumia pool-tag scanning, ambayo ni kutafuta strings za baiti 4 zinazoashiria uwepo wa muundo unaohitajika). Faida yake ni kwamba inaweza kugundua processes ambazo zimetoka, na hata kama malware itabadilisha `_EPROCESS` linked list, plugin bado itapata muundo huo ukiwa kwenye memory (kwa kuwa bado unahitaji kuwepo ili process iendelee kufanya kazi). Hasara ni kwamba plugins za “scan” huwa polepole kidogo kuliko plugins za “list”, na wakati mwingine zinaweza kutoa false positives (process iliyotoka muda mrefu uliopita na sehemu za muundo wake kuandikwa juu na operations nyingine).

Imetoka: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## Profaili za OS

### Volatility3

Kama ilivyoelezwa ndani ya readme, unahitaji kuweka **symbol table ya OS** unayotaka kusaidia ndani ya _volatility3/volatility/symbols_.\
Vifurushi vya symbol table kwa mifumo mbalimbali ya uendeshaji vinapatikana kwa **kupakuliwa** katika:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profaili ya Nje

Unaweza kupata orodha ya profiles zinazotumika kwa kutekeleza:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Ikiwa unataka kutumia **profile mpya uliyopakua** (kwa mfano, ya linux), unahitaji kuunda muundo wa folda ufuatao mahali fulani: _plugins/overlays/linux_ na uweke ndani ya folda hii faili ya zip iliyo na profile. Kisha, pata nambari ya profiles kwa kutumia:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Unaweza **download Linux and Mac profiles** kutoka [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Katika kipande kilichotangulia unaweza kuona kwamba profile inaitwa `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, na unaweza kuitumia kutekeleza kitu kama:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Gundua Wasifu
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Tofauti kati ya imageinfo na kdbgscan**

[**Kutoka hapa**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Tofauti na imageinfo ambayo hutoa tu mapendekezo ya profile, **kdbgscan** imeundwa kutambua kwa uhakika profile sahihi na anwani sahihi ya KDBG (ikiwa kuna zaidi ya moja). Plugin hii hutafuta saini za KDBGHeader zinazohusishwa na Volatility profiles na kutumia ukaguzi wa sanity ili kupunguza matokeo yasiyo sahihi. Kiwango cha maelezo ya output na idadi ya ukaguzi wa sanity unaoweza kufanywa hutegemea ikiwa Volatility inaweza kupata DTB, kwa hiyo ikiwa tayari unajua profile sahihi (au una pendekezo la profile kutoka imageinfo), hakikisha unaitumia kutoka .<sup>[[1]](#references)</sup>

Daima angalia **idadi ya processes ambazo kdbgscan imepata**. Wakati mwingine imageinfo na kdbgscan zinaweza kupata **profile** zaidi ya moja inayofaa, lakini **profile halali pekee ndiyo itakayokuwa na baadhi ya taarifa zinazohusiana na processes** (Hii ni kwa sababu anwani sahihi ya KDBG inahitajika ili kutoa processes)<sup>[[1]](#references)</sup>
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

**kernel debugger block**, inayorejelewa kama **KDBG** na Volatility, ni muhimu kwa kazi za forensic zinazotekelezwa na Volatility na debuggers mbalimbali. Inatambuliwa kama `KdDebuggerDataBlock` na iko katika aina `_KDDEBUGGER_DATA64`; ina marejeleo muhimu kama `PsActiveProcessHead`. Rejeleo hili mahususi linaelekeza kwenye mwanzo wa orodha ya processes, hivyo kuwezesha kuorodheshwa kwa processes zote, jambo ambalo ni la msingi kwa memory analysis ya kina.<sup>[[2]](#references)</sup>

## Taarifa za OS
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` inaweza kutumika katika **vol3 kujaribu kutafuta linux banners** kwenye dump.

## Hashes/Passwords

Extract SAM hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) na [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

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

Memory dump ya mchakato ita-**extract kila kitu** kuhusu hali ya sasa ya mchakato. Moduli ya **procdump** ita-**extract** **code** pekee.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Michakato

### Orodhesha michakato

Jaribu kutafuta michakato **ya kutiliwa shaka** (kwa jina) au **michakato** tegemezi **isiyotarajiwa** (kwa mfano cmd.exe ikiwa ni mchakato tegemezi wa iexplorer.exe).\
Inaweza kuwa muhimu **kulinganisha** matokeo ya pslist na yale ya psscan ili kutambua michakato iliyofichwa.

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

### Mstari wa amri

Je, kuna chochote cha kutiliwa shaka kilitekelezwa?

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

Commands zilizotekelezwa katika `cmd.exe` hudhibitiwa na **`conhost.exe`** (au **`csrss.exe`** kwenye mifumo ya kabla ya Windows 7). Hii inamaanisha kwamba ikiwa **`cmd.exe`** itasitishwa na mshambuliaji kabla ya memory dump kupatikana, bado kuna uwezekano wa kurejesha historia ya commands za session kutoka kwenye memory ya **`conhost.exe`**. Ili kufanya hivi, ikiwa shughuli zisizo za kawaida zitagunduliwa ndani ya modules za console, memory ya process inayohusiana ya **`conhost.exe`** inapaswa kudumpiwa. Kisha, kwa kutafuta **strings** ndani ya dump hii, command lines zilizotumika kwenye session zinaweza kutolewa.

### Mazingira

Pata env variables za kila process inayoendesha. Huenda kukawa na values za kuvutia.

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

### Mapendeleo ya token

Chunguza tokeni za mapendeleo katika services zisizotarajiwa.\
Inaweza kuwa muhimu kuorodhesha processes zinazotumia token yenye mapendeleo.

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

Kagua kila SSID inayomilikiwa na process.\
Inaweza kuwa muhimu kuorodhesha processes zinazotumia privileges SID (na processes zinazotumia service SID).

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

Ni muhimu kujua ni faili, keys, threads, processes... zipi nyingine ambazo **process ina handle** (imefungua)

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

### Strings kwa kila process

Volatility hutuwezesha kuangalia string inahusishwa na process ipi.

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

Pia inaruhusu kutafuta strings ndani ya process kwa kutumia module ya yarascan:

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

**Windows** hufuatilia programu unazoendesha kwa kutumia kipengele katika registry kinachoitwa **UserAssist keys**. Keys hizi hurekodi idadi ya mara ambazo kila programu imetekelezwa na wakati ilipoendeshwa mara ya mwisho.<sup>[[3]](#references)</sup>

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

### Onyesha hives zinazopatikana

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
## Mfumo wa faili

### Mount

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

### Jedwali Kuu la Faili

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

Mfumo wa faili wa **NTFS** hutumia kipengele muhimu kinachojulikana kama _master file table_ (MFT). Jedwali hili lina angalau ingizo moja kwa kila faili kwenye volume, likijumuisha pia MFT yenyewe. Maelezo muhimu kuhusu kila faili, kama vile **ukubwa, mihuri ya muda, ruhusa, na data halisi**, yamehifadhiwa ndani ya maingizo ya MFT au katika maeneo yaliyo nje ya MFT lakini yanayorejelewa na maingizo hayo. Maelezo zaidi yanaweza kupatikana katika [nyaraka rasmi](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

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

### Kuchanganua kwa yara

Tumia script hii kupakua na kuunganisha kanuni zote za yara za malware kutoka github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Unda directory ya _**rules**_ na uiendeshe. Hii itaunda faili inayoitwa _**malware_rules.yar**_ ambayo ina kanuni zote za yara za malware.

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

### Plugins za nje

Ikiwa unataka kutumia plugins za nje, hakikisha kwamba folda zinazohusiana na plugins ndizo parameta ya kwanza inayotumika.

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

Ipakue kutoka [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns).
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

Inawezekana **kusoma historia ya bash kutoka kwenye memory.** Unaweza pia kutupa faili ya _.bash_history_, lakini ikiwa ilizimwa utafurahi kwamba unaweza kutumia volatility module hii

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

### Ratiba ya Matukio

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

### Viendeshi

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
### Pata maandishi ya notepad
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Picha ya skrini
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Rekodi Kuu ya Kuanzisha Mfumo (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** ina jukumu muhimu katika kudhibiti partitions za kimantiki za kifaa cha kuhifadhi, ambazo zimeundwa kwa [mifumo tofauti ya faili](https://en.wikipedia.org/wiki/File_system). Sio tu kwamba huhifadhi maelezo kuhusu mpangilio wa partitions, bali pia huwa na code inayoweza kutekelezwa inayofanya kazi kama boot loader. Boot loader hii huanzisha moja kwa moja mchakato wa upakiaji wa hatua ya pili wa OS (tazama [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) au hufanya kazi kwa pamoja na [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) ya kila partition. Kwa maarifa ya kina, rejelea [ukurasa wa MBR kwenye Wikipedia](https://en.wikipedia.org/wiki/Master_boot_record).<sup>[[5]](#references)</sup>

## Marejeo

- [1] [Volatility, cheatsheet yangu mwenyewe (Sehemu ya 1): Utambuzi wa Image](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Kutafuta Kernel Debugger Block](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (Mifumo ya Faili ya Ndani) - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI-based PC, protective MBR: ni nini? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Mafunzo: Volatility plugins kwa uchanganuzi wa malware](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
