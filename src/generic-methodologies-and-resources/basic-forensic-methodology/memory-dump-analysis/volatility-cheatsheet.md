# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

​


Wenn Sie ein Tool benötigen, das die Speicheranalyse mit verschiedenen Scan-Ebenen automatisiert und mehrere Volatility3-Plugins parallel ausführt, können Sie autoVolatility3 verwenden: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Wenn Sie etwas **schnelles und verrücktes** wollen, das mehrere Volatility-Plugins parallel ausführt, können Sie verwenden: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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

{{#tab name="Methode 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Volatility-Befehle

Greifen Sie auf die offizielle Dokumentation in [Volatility-Befehlsreferenz](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) zu.

### Eine Anmerkung zu „list“ vs. „scan“ Plugins

Volatility hat zwei Hauptansätze für Plugins, die sich manchmal in ihren Namen widerspiegeln. „list“-Plugins versuchen, durch Windows-Kernel-Strukturen zu navigieren, um Informationen wie Prozesse abzurufen (lokalisieren und die verkettete Liste der `_EPROCESS`-Strukturen im Speicher durchlaufen), OS-Handles (lokalisieren und die Handle-Tabelle auflisten, alle gefundenen Zeiger dereferenzieren usw.). Sie verhalten sich mehr oder weniger so, wie die Windows-API es tun würde, wenn sie beispielsweise aufgefordert wird, Prozesse aufzulisten.

Das macht „list“-Plugins ziemlich schnell, aber ebenso anfällig für Manipulationen durch Malware wie die Windows-API. Wenn beispielsweise Malware DKOM verwendet, um einen Prozess von der `_EPROCESS`-verketteten Liste zu trennen, wird er im Task-Manager nicht angezeigt und auch nicht in der pslist.

„scan“-Plugins hingegen verfolgen einen Ansatz, der dem Carving des Speichers ähnelt, um Dinge zu finden, die sinnvoll erscheinen, wenn sie als spezifische Strukturen dereferenziert werden. `psscan` wird beispielsweise den Speicher lesen und versuchen, `_EPROCESS`-Objekte daraus zu erstellen (es verwendet Pool-Tag-Scanning, das nach 4-Byte-Strings sucht, die auf das Vorhandensein einer interessanten Struktur hinweisen). Der Vorteil ist, dass es Prozesse finden kann, die beendet wurden, und selbst wenn Malware mit der `_EPROCESS`-verketteten Liste manipuliert, wird das Plugin die Struktur, die im Speicher herumliegt, immer noch finden (da sie weiterhin existieren muss, damit der Prozess ausgeführt werden kann). Der Nachteil ist, dass „scan“-Plugins etwas langsamer sind als „list“-Plugins und manchmal falsche Positivmeldungen liefern können (ein Prozess, der zu lange beendet wurde und Teile seiner Struktur von anderen Operationen überschrieben wurden).

Von: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS-Profile

### Volatility3

Wie im Readme erklärt, müssen Sie die **Symboltabelle des OS**, das Sie unterstützen möchten, in _volatility3/volatility/symbols_ ablegen.\
Symboltabellenpakete für die verschiedenen Betriebssysteme sind **zum Download** verfügbar unter:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Externes Profil

Sie können die Liste der unterstützten Profile abrufen, indem Sie:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Wenn Sie ein **neues Profil, das Sie heruntergeladen haben** (zum Beispiel ein Linux-Profil) verwenden möchten, müssen Sie an einem Ort die folgende Ordnerstruktur erstellen: _plugins/overlays/linux_ und die ZIP-Datei, die das Profil enthält, in diesen Ordner legen. Holen Sie sich dann die Nummer der Profile mit:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Sie können **Linux- und Mac-Profile** von [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) herunterladen.

Im vorherigen Abschnitt sehen Sie, dass das Profil `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` genannt wird, und Sie können es verwenden, um etwas wie Folgendes auszuführen:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Profil entdecken
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Unterschiede zwischen imageinfo und kdbgscan**

[**Von hier**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Im Gegensatz zu imageinfo, das einfach Profilvorschläge bietet, ist **kdbgscan** darauf ausgelegt, das richtige Profil und die richtige KDBG-Adresse (falls mehrere vorhanden sind) positiv zu identifizieren. Dieses Plugin scannt nach den KDBGHeader-Signaturen, die mit Volatility-Profilen verknüpft sind, und führt Plausibilitätsprüfungen durch, um Fehlalarme zu reduzieren. Die Ausführlichkeit der Ausgabe und die Anzahl der durchgeführten Plausibilitätsprüfungen hängen davon ab, ob Volatility einen DTB finden kann. Wenn Sie also bereits das richtige Profil kennen (oder wenn Sie einen Profilvorschlag von imageinfo haben), stellen Sie sicher, dass Sie es verwenden.

Achten Sie immer auf die **Anzahl der Prozesse, die kdbgscan gefunden hat**. Manchmal können imageinfo und kdbgscan **mehr als ein** geeignetes **Profil** finden, aber nur das **gültige wird einige prozessbezogene** Informationen haben (Dies liegt daran, dass die korrekte KDBG-Adresse benötigt wird, um Prozesse zu extrahieren).
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

Der **Kernel-Debugger-Block**, der von Volatility als **KDBG** bezeichnet wird, ist entscheidend für forensische Aufgaben, die von Volatility und verschiedenen Debuggern durchgeführt werden. Identifiziert als `KdDebuggerDataBlock` und vom Typ `_KDDEBUGGER_DATA64`, enthält er wesentliche Referenzen wie `PsActiveProcessHead`. Diese spezifische Referenz verweist auf den Kopf der Prozessliste, was die Auflistung aller Prozesse ermöglicht, die für eine gründliche Analyse des Speichers grundlegend ist.

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Das Plugin `banners.Banners` kann in **vol3 verwendet werden, um zu versuchen, Linux-Banner** im Dump zu finden.

## Hashes/Passwörter

Extrahiere SAM-Hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) und [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

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

## Speicherabbild

Das Speicherabbild eines Prozesses wird **alles** aus dem aktuellen Status des Prozesses **extrahieren**. Das **procdump**-Modul wird nur den **Code** **extrahieren**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Prozesse

### Prozesse auflisten

Versuchen Sie, **verdächtige** Prozesse (nach Namen) oder **unerwartete** Kind **Prozesse** (zum Beispiel ein cmd.exe als Kind von iexplorer.exe) zu finden.\
Es könnte interessant sein, das Ergebnis von pslist mit dem von psscan zu vergleichen, um versteckte Prozesse zu identifizieren.

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

### Befehlszeile

Wurde etwas Verdächtiges ausgeführt?

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

Befehle, die in `cmd.exe` ausgeführt werden, werden von **`conhost.exe`** (oder `csrss.exe` auf Systemen vor Windows 7) verwaltet. Das bedeutet, dass, wenn **`cmd.exe`** von einem Angreifer beendet wird, bevor ein Memory-Dump erstellt wird, es dennoch möglich ist, den Befehlsverlauf der Sitzung aus dem Speicher von **`conhost.exe`** wiederherzustellen. Um dies zu tun, sollte der Speicher des zugehörigen **`conhost.exe`** Prozesses gedumpt werden, wenn ungewöhnliche Aktivitäten innerhalb der Module der Konsole festgestellt werden. Anschließend können durch die Suche nach **strings** innerhalb dieses Dumps möglicherweise die in der Sitzung verwendeten Befehlszeilen extrahiert werden.

### Umgebung

Holen Sie sich die Umgebungsvariablen jedes laufenden Prozesses. Es könnten einige interessante Werte vorhanden sein.

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

### Tokenprivilegien

Überprüfen Sie die Privilegien-Token in unerwarteten Diensten.\
Es könnte interessant sein, die Prozesse aufzulisten, die ein privilegiertes Token verwenden.

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

Überprüfen Sie jede SSID, die von einem Prozess besessen wird.\
Es könnte interessant sein, die Prozesse aufzulisten, die eine Privilegien-SID verwenden (und die Prozesse, die eine Dienst-SID verwenden).

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

Nützlich zu wissen, auf welche anderen Dateien, Schlüssel, Threads, Prozesse... ein **Prozess einen Handle** hat (geöffnet hat)

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

### Strings pro Prozesse

Volatility ermöglicht es uns zu überprüfen, zu welchem Prozess ein String gehört.

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

Es ermöglicht auch die Suche nach Strings innerhalb eines Prozesses mit dem yarascan-Modul:

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

**Windows** verfolgt die Programme, die Sie ausführen, mithilfe einer Funktion in der Registrierung, die als **UserAssist-Schlüssel** bezeichnet wird. Diese Schlüssel zeichnen auf, wie oft jedes Programm ausgeführt wird und wann es zuletzt gestartet wurde.

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


## Dienste

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

## Netzwerk

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

### Verfügbare Hives drucken

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

### Einen Wert erhalten
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
## Dateisystem

### Einhängen

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

### Scan/Dump

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

Das **NTFS-Dateisystem** verwendet eine kritische Komponente, die als _Master File Table_ (MFT) bekannt ist. Diese Tabelle enthält mindestens einen Eintrag für jede Datei auf einem Volume, einschließlich der MFT selbst. Wichtige Details zu jeder Datei, wie **Größe, Zeitstempel, Berechtigungen und tatsächliche Daten**, sind in den MFT-Einträgen oder in Bereichen außerhalb der MFT, die von diesen Einträgen referenziert werden, enthalten. Weitere Details finden Sie in der [offiziellen Dokumentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL-Schlüssel/Zertifikate

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

### Scannen mit yara

Verwenden Sie dieses Skript, um alle yara-Malware-Regeln von github herunterzuladen und zusammenzuführen: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Erstellen Sie das _**rules**_ Verzeichnis und führen Sie es aus. Dies erstellt eine Datei namens _**malware_rules.yar**_, die alle yara-Regeln für Malware enthält.

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

### Externe Plugins

Wenn Sie externe Plugins verwenden möchten, stellen Sie sicher, dass die mit den Plugins verbundenen Ordner das erste verwendete Parameter sind.

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

Laden Sie es von [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) herunter.
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

Es ist möglich, **aus dem Speicher die Bash-Historie zu lesen.** Sie könnten auch die _.bash_history_-Datei dumpen, aber sie wurde deaktiviert, Sie werden froh sein, dass Sie dieses Volatility-Modul verwenden können.

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

### Zeitlinie

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

### Treiber

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

### Zwischenablage abrufen
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE-Verlauf abrufen
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Notepad-Text abrufen
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
Der **Master Boot Record (MBR)** spielt eine entscheidende Rolle bei der Verwaltung der logischen Partitionen eines Speichermediums, die mit verschiedenen [Dateisystemen](https://en.wikipedia.org/wiki/File_system) strukturiert sind. Er enthält nicht nur Informationen über das Partitionierungslayout, sondern auch ausführbaren Code, der als Bootloader fungiert. Dieser Bootloader initiiert entweder direkt den zweiten Ladeprozess des Betriebssystems (siehe [zweiter Bootloader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) oder arbeitet harmonisch mit dem [Volume Boot Record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) jeder Partition zusammen. Für vertiefte Kenntnisse siehe die [MBR Wikipedia-Seite](https://en.wikipedia.org/wiki/Master_boot_record).

## Referenzen

- [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
- [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

{{#include ../../../banners/hacktricks-training.md}}
