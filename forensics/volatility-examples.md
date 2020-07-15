# Volatility - Examples

If you want something as **fast** as possible: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)

```text
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # Will use most important plugins (could use a lot of space depending on the size of the memory)
```

[Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

## A note on “list” vs. “scan” plugins

Volatility has two main approaches to plugins, which are sometimes reflected in their names. “list” plugins will try to navigate through Windows Kernel structures to retrieve information like processes \(locate and walk the linked list of `_EPROCESS` structures in memory\), OS handles \(locating and listing the handle table, dereferencing any pointers found, etc\). They more or less behave like the Windows API would if requested to, for example, list processes.

That makes “list” plugins pretty fast, but just as vulnerable as the Windows API to manipulation by malware. For instance, if malware uses DKOM to unlink a process from the `_EPROCESS` linked list, it won’t show up in the Task Manager and neither will it in the pslist.

“scan” plugins, on the other hand, will take an approach similar to carving the memory for things that might make sense when dereferenced as specific structures. `psscan` for instance will read the memory and try to make out `_EPROCESS` objects out of it \(it uses pool-tag scanning, which is basically searching for 4-byte strings that indicate the presence of a structure of interest\). The advantage is that it can dig up processes that have exited, and even if malware tampers with the `_EPROCESS` linked list, the plugin will still find the structure lying around in memory \(since it still needs to exist for the process to run\). The downfall is that “scan” plugins are a bit slower than “list” plugins, and can sometimes yield false-positives \(a process that exited too long ago and had parts of its structure overwritten by other operations\).

From: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Get profile

```text
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```

### **Differences between imageinfo and kdbgscan**

As opposed to imageinfo which simply provides profile suggestions, **kdbgscan** is designed to positively identify the correct profile and the correct KDBG address \(if there happen to be multiple\). This plugin scans for the KDBGHeader signatures linked to Volatility profiles and applies sanity checks to reduce false positives. The verbosity of the output and number of sanity checks that can be performed depends on whether Volatility can find a DTB, so if you already know the correct profile \(or if you have a profile suggestion from imageinfo\), then make sure you use it \(from [here](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)\).

Always take a look in the **number of procceses that kdbgscan has found**. Sometimes imageinfo and kdbgscan can find **more than one** suitable **profile** but only the **valid one will have some process related** \(This is because in order to extract processes the correct KDBG address is needed\)

```text
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```text
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```

### KDBG

The **kernel debugger block** \(named KdDebuggerDataBlock of the type \_KDDEBUGGER\_DATA64, or **KDBG** by volatility\) is important for many things that Volatility and debuggers do. For example, it has a reference to the PsActiveProcessHead which is the list head of all processes required for process listing.

## Hashes/Passwords

Extract password hashes from memory

```text
volatility --profile=Win7SP1x86_23418 hashdump -f ch2.dmp   #Local hashes
volatility --profile=Win7SP1x86_23418 cachedump -f ch2.dmp
volatility --profile=Win7SP1x86_23418 lsadump -f ch2.dmp    # LSA secrets
```

## Memory Dump

The memory dump of a process will **extract everything** of the current status of the process. The **procdump** module will only **extract** the **code**.

```text
volatility -f ch2.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```

## Processes

### List processes

Try to find **suspicious** processes \(by name\) or **unexpected** child **processes** \(for example a cmd.exe as a child of iexplorer.exe\).

```text
volatility --profile=PROFILE pstree -f DUMP # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f DUMP # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f DUMP # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f DUMP # Get hidden process list
```

### Dump proc

```text
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f ch2.dmp
```

### Command line

Something suspicious was executed?

```text
volatility --profile=PROFILE cmdline -f DUMP #Display process command-line arguments
volatility --profile=PROFILE consoles -f DUMP #command history by scanning for _CONSOLE_INFORMATION
```

Commands entered into cmd.exe are processed by **conhost.exe** \(csrss.exe prior to Windows 7\). So even if an attacker managed to **kill the cmd.exe** **prior** to us obtaining a memory **dump**, there is still a good chance of **recovering history** of the command line session from **conhost.exe’s memory**. If you find **something weird**\(using the consoles modules\), try to **dump** the **memory** of the **conhost.exe associated** process and **search** for **strings** inside it to extract the command lines.

### Environment

```text
volatility --profile=PROFILE envars -f DUMP #Display process environment variables
```

### Privileges

Unexpected and exploitable privileges in a process?

```text
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep Enabled | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege" 
```

### SIDs

Processes running with admin privileges?

```text
#Get the SID of a process
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get processes with admin privileges
volatility --profile=Win7SP1x86_23418 getsids  -f ch2.dmp | grep -i admin
```

### Handles

Useful to know to which other files, keys, threads, processes... a **process has a handle** for \(has opened\)

```text
volatility --profile=Win7SP1x86_23418 handles --pid=3152 -f ch2.dmp
```

### DLLs

```text
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f ch2.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f ch2.dmp #Dump dlls of a proc
```

## Services

```text
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan-f ch2.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f ch2.dmp
```

## Network

```text
volatility --profile=Win7SP1x86_23418 netscan -f ch2.dmp
volatility --profile=Win7SP1x86_23418 connections -f ch2.dmp #XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f ch2.dmp #TCP connections 
volatility --profile=Win7SP1x86_23418 sockscan -f ch2.dmp #Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f ch2.dmp #Scanner for tcp socket objects
```

## Hive

### Print available hives

```text
volatility --profile=Win7SP1x86_23418 hivelist -f ch2.dmp
```

### Get a value

```text
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f ch2.dmp
# Get Run binaries registry value
volatility -f ch2.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```

### Dump

```text
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f ch2.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f ch2.dmp
```

## Files

### Scan/dump

```text
volatility --profile=Win7SP1x86_23418 filescan -f ch2.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-files=. -f ch2.dmp #Dump the files
```

### SSL Keys/Certs

Interesting options for this modules are: _--pid, --name, --ssl_

```text
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f ch2.dmp
```

## Malware

```text
volatility --profile=Win7SP1x86_23418 malfind -f ch2.dmp
volatility --profile=Win7SP1x86_23418 apihooks -f ch2.dmp
volatility --profile=Win7SP1x86_23418 driverirp -f ch2.dmp
```

### Scanning with yara

Use this script to download and merge all the yara malware rules from github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)  
Create the _**rules**_ directory and execute it. This will create a file called _**malware\_rules.yar**_ which contains all the yara rules for malware.

```text
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```

## External Plugins

When you use an external plugin **the first parameter** that you have to set is `--plugins`

### Autoruns

Download it from [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)

```text
 volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f dump.img autoruns
```

## MISC

### Get clipboard

```text
volatility --profile=Win7SP1x86_23418 clipboard -f ch2.dmp
```

### Get IE history

```text
volatility --profile=Win7SP1x86_23418 iehistory -f ch2.dmp
```

### Get notepad text

```text
volatility --profile=Win7SP1x86_23418 notepad -f ch2.dmp
```

### Screenshot

```text
volatility --profile=Win7SP1x86_23418 screenshot -f ch2.dmp
```

### Mutantscan

```text
volatility --profile=Win7SP1x86_23418 mutantscan -f ch2.dmp
```

### Master Boot Record \(MBR\)

```text
volatility --profile=Win7SP1x86_23418 mbrparser -f ch2.dmp
```

The MBR holds the information on how the logical partitions, containing [file systems](https://en.wikipedia.org/wiki/File_system), are organized on that medium. The MBR also contains executable code to function as a loader for the installed operating system—usually by passing control over to the loader's [second stage](https://en.wikipedia.org/wiki/Second-stage_boot_loader), or in conjunction with each partition's [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) \(VBR\). This MBR code is usually referred to as a [boot loader](https://en.wikipedia.org/wiki/Boot_loader). From [here](https://en.wikipedia.org/wiki/Master_boot_record).

### Master File Table

```text
volatility --profile=Win7SP1x86_23418 mftparser -f ch2.dmp
```

 The NTFS file system contains a file called the _master file table_, or MFT. There is at least one entry in the MFT for every file on an NTFS file system volume, including the MFT itself. All information about a file, including its size, time and date stamps, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries. From [here](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

