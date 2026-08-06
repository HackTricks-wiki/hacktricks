# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

यदि आपको ऐसा tool चाहिए जो विभिन्न scan levels के साथ memory analysis को स्वचालित करता हो और कई Volatility3 plugins को parallel में चलाता हो, तो आप autoVolatility3 का उपयोग कर सकते हैं:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
अगर आप कुछ **तेज़ और ज़बरदस्त** चाहते हैं, जो कई Volatility plugins को समानांतर रूप से लॉन्च करे, तो आप इसका उपयोग कर सकते हैं: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## इंस्टॉलेशन

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

## Volatility Commands

[Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) में official doc देखें।

### “list” बनाम “scan” plugins पर एक नोट

Volatility में plugins के लिए दो मुख्य approaches हैं, जो कभी-कभी उनके names में भी दिखाई देते हैं। “list” plugins Windows Kernel structures के माध्यम से navigate करके processes जैसी information retrieve करने का प्रयास करते हैं (memory में linked list of `_EPROCESS` structures को locate और walk करना), OS handles (handle table को locate और list करना, मिले हुए किसी भी pointers को dereference करना आदि)। ये कमोबेश वैसे ही behave करते हैं जैसे Windows API behave करेगा, अगर उससे, उदाहरण के लिए, processes list करने के लिए कहा जाए।

इससे “list” plugins काफी fast हो जाते हैं, लेकिन malware द्वारा manipulation के प्रति Windows API जितने ही vulnerable भी होते हैं। उदाहरण के लिए, अगर malware DKOM का उपयोग करके किसी process को `_EPROCESS` linked list से unlink कर देता है, तो वह Task Manager में दिखाई नहीं देगा और न ही pslist में।

दूसरी ओर, “scan” plugins memory को carve करने जैसा approach अपनाते हैं, ताकि ऐसी चीजें खोजी जा सकें जो specific structures के रूप में dereference किए जाने पर meaningful लगें। उदाहरण के लिए `psscan` memory को read करेगा और उसमें से `_EPROCESS` objects बनाने का प्रयास करेगा (यह pool-tag scanning का उपयोग करता है, जिसमें 4-byte strings को search किया जाता है, जो किसी रुचिकर structure की मौजूदगी का संकेत देती हैं)। इसका advantage यह है कि यह उन processes को भी खोज सकता है जो exit हो चुके हैं। इसके अलावा, अगर malware `_EPROCESS` linked list के साथ tamper करता है, तब भी plugin memory में पड़ी structure को खोज लेगा (क्योंकि process के run करने के लिए उसका मौजूद रहना आवश्यक है)। इसकी कमी यह है कि “scan” plugins “list” plugins की तुलना में थोड़े slower होते हैं और कभी-कभी false positives दे सकते हैं (ऐसा process जो बहुत पहले exit हो चुका हो और जिसकी structure के कुछ parts अन्य operations द्वारा overwrite कर दिए गए हों)।

From: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## OS Profiles

### Volatility3

जैसा कि readme में बताया गया है, जिस **OS** को आप support करना चाहते हैं उसकी **symbol table** को _volatility3/volatility/symbols_ के अंदर रखना आवश्यक है।\
विभिन्न operating systems के लिए symbol table packs **download** के लिए उपलब्ध हैं:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

आप supported profiles की list इस तरह प्राप्त कर सकते हैं:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
यदि आप **download किया हुआ कोई नया profile** (उदाहरण के लिए linux वाला) इस्तेमाल करना चाहते हैं, तो आपको कहीं पर निम्न folder structure बनाना होगा: _plugins/overlays/linux_ और इस folder के अंदर profile वाली zip file रखनी होगी। फिर, profiles की संख्या प्राप्त करने के लिए:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
आप [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) से **Linux और Mac profiles** download कर सकते हैं।

पिछले भाग में आप देख सकते हैं कि profile का नाम `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` है, और इसका उपयोग करके आप कुछ इस तरह execute कर सकते हैं:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Profile खोजें
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo और kdbgscan के बीच अंतर**

[**यहाँ से**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): imageinfo के विपरीत, जो केवल profile suggestions प्रदान करता है, **kdbgscan** को सही profile और सही KDBG address की सकारात्मक पहचान करने के लिए डिज़ाइन किया गया है (यदि एक से अधिक हों)। यह plugin Volatility profiles से जुड़े KDBGHeader signatures को scan करता है और false positives को कम करने के लिए sanity checks लागू करता है। Output की verbosity और किए जा सकने वाले sanity checks की संख्या इस बात पर निर्भर करती है कि Volatility DTB ढूँढ सकता है या नहीं। इसलिए, यदि आप पहले से सही profile जानते हैं (या आपके पास imageinfo से profile suggestion है), तो सुनिश्चित करें कि आप उसका उपयोग  से करें।<sup>[[1]](#references)</sup>

हमेशा **kdbgscan द्वारा खोजे गए processes की संख्या** पर ध्यान दें। कभी-कभी imageinfo और kdbgscan एक से अधिक उपयुक्त **profile** खोज सकते हैं, लेकिन केवल **valid profile में कुछ process-related जानकारी होगी** (ऐसा इसलिए है क्योंकि processes extract करने के लिए सही KDBG address आवश्यक होता है)।<sup>[[1]](#references)</sup>
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

**kernel debugger block**, जिसे Volatility द्वारा **KDBG** कहा जाता है, Volatility और विभिन्न debuggers द्वारा किए जाने वाले forensic कार्यों के लिए महत्वपूर्ण है। इसे `KdDebuggerDataBlock` के रूप में पहचाना जाता है और इसका type `_KDDEBUGGER_DATA64` है। इसमें `PsActiveProcessHead` जैसे आवश्यक references होते हैं। यह specific reference process list के head की ओर point करता है, जिससे सभी processes की listing संभव होती है। यह thorough memory analysis के लिए fundamental है।<sup>[[2]](#references)</sup>

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` का उपयोग **vol3 में dump के अंदर linux banners खोजने का प्रयास करने के लिए किया जा सकता है**।

## Hashes/Passwords

SAM hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) और [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets) extract करें।

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

किसी process का memory dump process की वर्तमान स्थिति की **हर चीज़ extract** कर देगा। **procdump** module केवल **code** को **extract** करेगा।
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Processes

### List processes

**suspicious** processes (नाम के आधार पर) या अप्रत्याशित child **processes** खोजने का प्रयास करें (उदाहरण के लिए iexplorer.exe की child प्रक्रिया के रूप में cmd.exe)।\
छिपी हुई processes की पहचान करने के लिए pslist के परिणाम की तुलना psscan के परिणाम से करना उपयोगी हो सकता है।

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

### proc Dump

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

### कमांड लाइन

क्या कुछ संदिग्ध execute किया गया था?

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

`cmd.exe` में execute किए गए Commands को **`conhost.exe`** (या Windows 7 से पहले के systems पर **`csrss.exe`**) manage करता है। इसका अर्थ है कि यदि memory dump प्राप्त करने से पहले attacker द्वारा **`cmd.exe`** terminate कर दिया जाता है, तब भी **`conhost.exe`** की memory से session की command history recover करना संभव है। ऐसा करने के लिए, यदि console के modules में unusual activity detect होती है, तो संबंधित **`conhost.exe`** process की memory dump की जानी चाहिए। फिर, इस dump में **strings** search करके, session में उपयोग की गई command lines को संभावित रूप से extract किया जा सकता है।

### Environment

हर running process के env variables प्राप्त करें। इनमें कुछ interesting values हो सकती हैं।

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

अप्रत्याशित services में privilege tokens की जाँच करें।\
कुछ privileged token का उपयोग करने वाली processes को सूचीबद्ध करना उपयोगी हो सकता है।

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

किसी process के स्वामित्व वाले प्रत्येक SSID की जाँच करें।\
Privileges SID का उपयोग करने वाले processes (और किसी service SID का उपयोग करने वाले processes) की सूची बनाना उपयोगी हो सकता है।

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

यह जानना उपयोगी है कि कोई **process** किन अन्य files, keys, threads, processes... के लिए **handle** रखता है (जिन्हें उसने खोला है)

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

### Processes के अनुसार Strings

Volatility हमें यह जाँचने की अनुमति देता है कि कोई string किस process से संबंधित है।

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

यह yarascan module का उपयोग करके किसी process के अंदर strings खोजने की सुविधा भी देता है:

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

**Windows** registry में **UserAssist keys** नामक feature का उपयोग करके आपके द्वारा चलाए गए programs का track रखता है। ये keys प्रत्येक program के execution की संख्या और उसके last run का समय record करती हैं।<sup>[[3]](#references)</sup>

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

## सेवाएँ

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

## नेटवर्क

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

### उपलब्ध hives प्रिंट करें

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

### कोई मान प्राप्त करें

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
## फाइल सिस्टम

### माउंट

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

### स्कैन/डंप

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

### मास्टर फ़ाइल टेबल

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

**NTFS file system** एक महत्वपूर्ण component का उपयोग करता है, जिसे _master file table_ (MFT) के नाम से जाना जाता है। इस table में volume की प्रत्येक file के लिए कम-से-कम एक entry होती है, जिसमें स्वयं MFT भी शामिल है। प्रत्येक file से संबंधित महत्वपूर्ण details, जैसे **size, timestamps, permissions, और actual data**, MFT entries के भीतर या MFT से बाहर के उन areas में encapsulated होती हैं, जिनका reference इन entries द्वारा दिया जाता है। अधिक details [official documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table) में मिल सकती हैं।<sup>[[4]](#references)</sup>

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

### YARA से स्कैनिंग

GitHub से सभी YARA malware rules डाउनलोड और merge करने के लिए इस script का उपयोग करें: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ directory बनाएं और इसे execute करें। इससे _**malware_rules.yar**_ नाम की एक file बनेगी, जिसमें malware के सभी YARA rules होंगे।

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

## विविध

### बाहरी plugins

यदि आप बाहरी plugins का उपयोग करना चाहते हैं, तो सुनिश्चित करें कि plugins से संबंधित folders उपयोग किया जाने वाला पहला parameter हों।

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

इसे [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) से डाउनलोड करें।
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

**memory से bash history पढ़ना संभव है।** आप _.bash_history_ file को भी dump कर सकते हैं, लेकिन यदि वह disabled थी, तो आपको खुशी होगी कि आप इस volatility module का उपयोग कर सकते हैं।

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

### टाइमलाइन

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

### ड्राइवर्स

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

### Clipboard प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE history प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Notepad text प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### स्क्रीनशॉट
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### मास्टर बूट रिकॉर्ड (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** storage medium के logical partitions को प्रबंधित करने में महत्वपूर्ण भूमिका निभाता है, जो अलग-अलग [file systems](https://en.wikipedia.org/wiki/File_system) के साथ संरचित होते हैं। इसमें न केवल partition layout की जानकारी होती है, बल्कि executable code भी मौजूद होता है जो boot loader के रूप में कार्य करता है। यह boot loader या तो OS की second-stage loading प्रक्रिया को सीधे शुरू करता है (देखें [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) या प्रत्येक partition के [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) के साथ मिलकर कार्य करता है। गहन जानकारी के लिए [MBR Wikipedia page](https://en.wikipedia.org/wiki/Master_boot_record) देखें।<sup>[[5]](#references)</sup>

## संदर्भ

- [1] [Volatility, मेरी अपनी cheatsheet (भाग 1): Image Identification](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Kernel Debugger Block ढूँढना](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (Local File Systems) - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI-आधारित PC, protective MBR: यह क्या है? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: malware analysis के लिए Volatility plugins](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
