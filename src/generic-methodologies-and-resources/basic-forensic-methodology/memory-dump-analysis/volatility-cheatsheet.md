# Volatility - CheatSheet
{{#include /banners/hacktricks-training.md}}


{{#include ../../../banners/hacktricks-training.md}}

​


If you need a tool that automates memory analysis with different scan levels and runs multiple Volatility3 plugins in parallel, you can use autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)

```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```

If you want something **fast and crazy** that will launch several Volatility plugins on parallel you can use: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)

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

## Volatility Commands

Access the official doc in [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### A note on “list” vs. “scan” plugins

Volatility has two main approaches to plugins, which are sometimes reflected in their names. “list” plugins will try to navigate through Windows Kernel structures to retrieve information like processes (locate and walk the linked list of `_EPROCESS` structures in memory), OS handles (locating and listing the handle table, dereferencing any pointers found, etc). They more or less behave like the Windows API would if requested to, for example, list processes.

That makes “list” plugins pretty fast, but just as vulnerable as the Windows API to manipulation by malware. For instance, if malware uses DKOM to unlink a process from the `_EPROCESS` linked list, it won’t show up in the Task Manager and neither will it in the pslist.

“scan” plugins, on the other hand, will take an approach similar to carving the memory for things that might make sense when dereferenced as specific structures. `psscan` for instance will read the memory and try to make`_EPROCESS` objects out of it (it uses pool-tag scanning, which is searching for 4-byte strings that indicate the presence of a structure of interest). The advantage is that it can dig up processes that have exited, and even if malware tampers with the `_EPROCESS` linked list, the plugin will still find the structure lying around in memory (since it still needs to exist for the process to run). The downfall is that “scan” plugins are a bit slower than “list” plugins, and can sometimes yield false positives (a process that exited too long ago and had parts of its structure overwritten by other operations).

From: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS Profiles

### Volatility3

As explained inside the readme you need to put the **symbol table of the OS** you want to support inside _volatility3/volatility/symbols_.\
Symbol table packs for the various operating systems are available for **download** at:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

You can get the list of supported profiles doing:

```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```

If you want to use a **new profile you have downloaded** (for example a linux one) you need to create somewhere the following folder structure: _plugins/overlays/linux_ and put inside this folder the zip file containing the profile. Then, get the number of the profiles using:

```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```

You can **download Linux and Mac profiles** from [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

In the previous chunk you can see that the profile is called `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, and you can use it to execute something like:

```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```

#### Discover Profile

```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```

#### **Differences between imageinfo and kdbgscan**

[**From here**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): As opposed to imageinfo which simply provides profile suggestions, **kdbgscan** is designed to positively identify the correct profile and the correct KDBG address (if there happen to be multiple). This plugin scans for the KDBGHeader signatures linked to Volatility profiles and applies sanity checks to reduce false positives. The verbosity of the output and the number of sanity checks that can be performed depends on whether Volatility can find a DTB, so if you already know the correct profile (or if you have a profile suggestion from imageinfo), then make sure you use it from .

Always take a look at the **number of processes that kdbgscan has found**. Sometimes imageinfo and kdbgscan can find **more than one** suitable **profile** but only the **valid one will have some process related** (This is because to extract processes the correct KDBG address is needed)

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

The **kernel debugger block**, referred to as **KDBG** by Volatility, is crucial for forensic tasks performed by Volatility and various debuggers. Identified as `KdDebuggerDataBlock` and of the type `_KDDEBUGGER_DATA64`, it contains essential references like `PsActiveProcessHead`. This specific reference points to the head of the process list, enabling the listing of all processes, which is fundamental for thorough memory analysis.

## OS Information

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

The plugin `banners.Banners` can be used in **vol3 to try to find linux banners** in the dump.

## Hashes/Passwords

Extract SAM hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) and [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

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

The memory dump of a process will **extract everything** of the current status of the process. The **procdump** module will only **extract** the **code**.

```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```

## Processes

### List processes

Try to find **suspicious** processes (by name) or **unexpected** child **processes** (for example a cmd.exe as a child of iexplorer.exe).\
It could be interesting to **compare** the result of pslist with the one of psscan to identify hidden processes.

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

Anything suspicious was executed?

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

Commands executed in `cmd.exe` are managed by **`conhost.exe`** (or `csrss.exe` on systems before Windows 7). This means that if **`cmd.exe`** is terminated by an attacker before a memory dump is obtained, it's still possible to recover the session's command history from the memory of **`conhost.exe`**. To do this, if unusual activity is detected within the console's modules, the memory of the associated **`conhost.exe`** process should be dumped. Then, by searching for **strings** within this dump, command lines used in the session can potentially be extracted.

### Environment

Get the env variables of each running process. There could be some interesting values.

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

Check for privileges tokens in unexpected services.\
It could be interesting to list the processes using some privileged token.

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

Check each SSID owned by a process.\
It could be interesting to list the processes using a privileges SID (and the processes using some service SID).

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

Useful to know to which other files, keys, threads, processes... a **process has a handle** for (has opened)

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

### Strings per processes

Volatility allows us to check which process a string belongs to.

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

It also allows to search for strings inside a process using the yarascan module:

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

**Windows** keeps track of programs you run using a feature in the registry called **UserAssist keys**. These keys record how many times each program is executed and when it was last run.

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


## Services

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

## Network

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

### Get a value

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

## Filesystem

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

### Master File Table

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

The **NTFS file system** uses a critical component known as the _master file table_ (MFT). This table includes at least one entry for every file on a volume, covering the MFT itself too. Vital details about each file, such as **size, timestamps, permissions, and actual data**, are encapsulated within the MFT entries or in areas external to the MFT but referenced by these entries. More details can be found in the [official documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

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

### Scanning with yara

Use this script to download and merge all the yara malware rules from github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Create the _**rules**_ directory and execute it. This will create a file called _**malware_rules.yar**_ which contains all the yara rules for malware.

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

### External plugins

If you want to use external plugins make sure that the folders related to the plugins are the first parameter used.

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

It's possible to **read from memory the bash history.** You could also dump the _.bash_history_ file, but it was disabled you will be glad you can use this volatility module

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

### TimeLine

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

### Drivers

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

### Get clipboard

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```

### Get IE history

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```

### Get notepad text

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```

### Screenshot

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```

### Master Boot Record (MBR)

```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```

The **Master Boot Record (MBR)** plays a crucial role in managing the logical partitions of a storage medium, which are structured with different [file systems](https://en.wikipedia.org/wiki/File_system). It not only holds partition layout information but also contains executable code acting as a boot loader. This boot loader either directly initiates the OS's second-stage loading process (see [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) or works in harmony with the [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) of each partition. For in-depth knowledge, refer to the [MBR Wikipedia page](https://en.wikipedia.org/wiki/Master_boot_record).

## References

- [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
- [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

{{#include ../../../banners/hacktricks-training.md}}
