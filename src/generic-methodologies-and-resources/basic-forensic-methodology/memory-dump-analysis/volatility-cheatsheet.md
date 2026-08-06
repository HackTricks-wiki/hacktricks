# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

Wenn du ein Tool benötigst, das die memory analysis mit verschiedenen Scan-Ebenen automatisiert und mehrere Volatility3 plugins parallel ausführt, kannst du autoVolatility3 verwenden:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Wenn du etwas **Schnelles und Verrücktes** möchtest, das mehrere Volatility-Plugins parallel startet, kannst du Folgendes verwenden: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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

## Volatility-Befehle

Die offizielle Dokumentation finden Sie in der [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan).

### Ein Hinweis zu „list“- und „scan“-Plugins

Volatility verfolgt bei Plugins zwei Hauptansätze, die sich teilweise in deren Namen widerspiegeln. „list“-Plugins versuchen, durch Windows-Kernelstrukturen zu navigieren, um Informationen wie Prozesse abzurufen (die verknüpfte Liste von `_EPROCESS`-Strukturen im Speicher suchen und durchlaufen), OS-Handles aufzulisten (die Handle-Tabelle suchen und auflisten, alle gefundenen Pointer dereferenzieren usw.). Sie verhalten sich mehr oder weniger so wie die Windows API, wenn diese beispielsweise zum Auflisten von Prozessen aufgefordert wird.

Dadurch sind „list“-Plugins ziemlich schnell, aber ebenso wie die Windows API anfällig für Manipulationen durch Malware. Wenn Malware beispielsweise DKOM verwendet, um einen Prozess aus der verknüpften `_EPROCESS`-Liste zu entfernen, wird er weder im Task-Manager noch in `pslist` angezeigt.

„scan“-Plugins verfolgen dagegen einen Ansatz, der dem Carving des Speichers nach Dingen ähnelt, die bei der Dereferenzierung als bestimmte Strukturen sinnvoll erscheinen könnten. `psscan` liest beispielsweise den Speicher und versucht, daraus `_EPROCESS`-Objekte zu erstellen (es verwendet Pool-Tag-Scanning, bei dem nach 4-Byte-Strings gesucht wird, die auf das Vorhandensein einer relevanten Struktur hinweisen). Der Vorteil besteht darin, dass damit bereits beendete Prozesse gefunden werden können. Selbst wenn Malware die verknüpfte `_EPROCESS`-Liste manipuliert, findet das Plugin die im Speicher verbliebene Struktur weiterhin (da sie für die Ausführung des Prozesses noch vorhanden sein muss). Der Nachteil ist, dass „scan“-Plugins etwas langsamer als „list“-Plugins sind und manchmal False Positives liefern können (ein Prozess, der bereits zu lange beendet wurde und dessen Struktur teilweise durch andere Vorgänge überschrieben wurde).

Von: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## OS-Profile

### Volatility3

Wie in der README beschrieben, müssen Sie die **Symboltabelle des zu unterstützenden OS** in _volatility3/volatility/symbols_ ablegen.\
Symboltabellenpakete für die verschiedenen Betriebssysteme stehen zum **Download** bereit:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Externes Profil

Sie können die Liste der unterstützten Profile mit folgendem Befehl abrufen:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Wenn du ein **neues Profil verwenden möchtest, das du heruntergeladen hast** (zum Beispiel ein Linux-Profil), musst du irgendwo die folgende Ordnerstruktur erstellen: _plugins/overlays/linux_ und die ZIP-Datei mit dem Profil in diesen Ordner legen. Ermittle anschließend die Anzahl der Profile mit:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Du kannst **Linux- und Mac-Profile** unter [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) herunterladen.

Im vorherigen Abschnitt siehst du, dass das Profil `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` heißt. Du kannst es verwenden, um etwas wie Folgendes auszuführen:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Profil ermitteln
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Unterschiede zwischen imageinfo und kdbgscan**

[**Von hier**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Im Gegensatz zu imageinfo, das lediglich Vorschläge für Profile liefert, wurde **kdbgscan** entwickelt, um das korrekte Profil und die korrekte KDBG-Adresse (falls mehrere vorhanden sind) eindeutig zu identifizieren. Dieses Plugin sucht nach den mit Volatility-Profilen verknüpften KDBGHeader-Signaturen und führt Plausibilitätsprüfungen durch, um falsch positive Ergebnisse zu reduzieren. Die Ausführlichkeit der Ausgabe und die Anzahl der durchführbaren Plausibilitätsprüfungen hängen davon ab, ob Volatility einen DTB finden kann. Wenn du das korrekte Profil bereits kennst (oder einen Profilvorschlag von imageinfo hast), solltest du es daher ab .<sup>[[1]](#references)</sup> verwenden.

Achte immer auf die **Anzahl der Prozesse, die kdbgscan gefunden hat**. Manchmal finden imageinfo und kdbgscan **mehr als ein** geeignetes **Profil**, aber nur das **gültige Profil weist prozessbezogene Einträge auf** (der Grund dafür ist, dass zum Extrahieren von Prozessen die korrekte KDBG-Adresse benötigt wird)<sup>[[1]](#references)</sup>
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

Der **Kernel-Debugger-Block**, von Volatility als **KDBG** bezeichnet, ist für forensische Aufgaben mit Volatility und verschiedenen Debuggern von entscheidender Bedeutung. Er wird als `KdDebuggerDataBlock` identifiziert und hat den Typ `_KDDEBUGGER_DATA64`. Er enthält wichtige Verweise wie `PsActiveProcessHead`. Dieser spezifische Verweis zeigt auf den Anfang der Prozessliste und ermöglicht dadurch die Auflistung aller Prozesse, was für eine gründliche Speicheranalyse grundlegend ist.<sup>[[2]](#references)</sup>

## Betriebssysteminformationen
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Das Plugin `banners.Banners` kann in **vol3 verwendet werden, um linux banners im Dump zu finden.

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

Das Speicherabbild eines Prozesses wird **alles** aus dem aktuellen Zustand des Prozesses **extrahieren**. Das **procdump**-Modul wird nur den **Code** **extrahieren**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Prozesse

### Prozesse auflisten

Versuche, **verdächtige** Prozesse (anhand des Namens) oder **unerwartete** untergeordnete **Prozesse** zu finden (zum Beispiel eine cmd.exe als untergeordneten Prozess von iexplorer.exe).\
Es könnte interessant sein, das Ergebnis von pslist mit dem von psscan zu **vergleichen**, um versteckte Prozesse zu identifizieren.

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

### Prozess dumpen

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

### Kommandozeile

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

In `cmd.exe` ausgeführte Befehle werden von **`conhost.exe`** verwaltet (oder von **`csrss.exe`** auf Systemen vor Windows 7). Das bedeutet, dass der Befehlsverlauf der Sitzung weiterhin aus dem Speicher von **`conhost.exe`** wiederhergestellt werden kann, wenn **`cmd.exe`** von einem Angreifer beendet wird, bevor ein memory dump erstellt wurde. Wenn ungewöhnliche Aktivitäten innerhalb der Module der Konsole festgestellt werden, sollte der Speicher des zugehörigen **`conhost.exe`**-Prozesses gedumpt werden. Anschließend können durch die Suche nach **strings** innerhalb dieses Dumps möglicherweise die in der Sitzung verwendeten Befehlszeilen extrahiert werden.

### Umgebung

Rufe die env-Variablen jedes laufenden Prozesses ab. Es könnte einige interessante Werte geben.

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

### Token-Berechtigungen

Prüfe auf privilegierte Tokens in unerwarteten Diensten.\
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

Überprüfe jede SSID, die einem Prozess gehört.\
Es könnte interessant sein, die Prozesse aufzulisten, die eine privilegierte SID verwenden (sowie die Prozesse, die eine service SID verwenden).

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

Nützlich, um zu wissen, für welche anderen Dateien, Schlüssel, Threads, Prozesse ... ein **Prozess ein Handle besitzt** (geöffnet hat).

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

### Strings pro Prozess

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

Es ermöglicht außerdem, mithilfe des yarascan-Moduls nach Strings innerhalb eines Prozesses zu suchen:

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

**Windows** verfolgt die von Ihnen ausgeführten Programme mithilfe einer in der Registry als **UserAssist keys** bezeichneten Funktion. Diese Schlüssel speichern, wie oft jedes Programm ausgeführt wurde und wann es zuletzt ausgeführt wurde.<sup>[[3]](#references)</sup>

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

## Registry-Hive

### Verfügbare Hives anzeigen

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

### Einen Wert abrufen

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
## Dateisystem

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

### Scannen/Dump erstellen

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

Das **NTFS-Dateisystem** verwendet eine wichtige Komponente, die als _master file table_ (MFT) bekannt ist. Diese Tabelle enthält mindestens einen Eintrag für jede Datei auf einem Volume, einschließlich der MFT selbst. Wichtige Details zu jeder Datei, wie **Größe, Zeitstempel, Berechtigungen und tatsächliche Daten**, sind in den MFT-Einträgen oder in Bereichen außerhalb der MFT enthalten, auf die diese Einträge verweisen. Weitere Details finden sich in der [offiziellen Dokumentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

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

### Scanning mit yara

Verwende dieses Script, um alle yara-Malware-Regeln von github herunterzuladen und zusammenzuführen: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Erstelle das Verzeichnis _**rules**_ und führe das Script aus. Dadurch wird eine Datei namens _**malware_rules.yar**_ erstellt, die alle yara-Regeln für Malware enthält.

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

## VERSCHIEDENES

### Externe Plugins

Wenn du externe Plugins verwenden möchtest, stelle sicher, dass die zu den Plugins gehörenden Ordner als erster Parameter verwendet werden.

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

Lade es von [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) herunter.
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

### Symbolische Links

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

Es ist möglich, die **Bash-Historie aus dem Speicher zu lesen.** Du könntest auch die Datei _.bash_history_ ausgeben, aber falls dies deaktiviert wurde, wirst du froh sein, dieses Volatility-Modul verwenden zu können.

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
### IE-Verlauf auslesen
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
Der **Master Boot Record (MBR)** spielt eine entscheidende Rolle bei der Verwaltung der logischen Partitionen eines Speichermediums, die mit unterschiedlichen [Dateisystemen](https://en.wikipedia.org/wiki/File_system) strukturiert sind. Er enthält nicht nur Informationen zum Partitionslayout, sondern auch ausführbaren Code, der als Bootloader dient. Dieser Bootloader startet entweder direkt den Ladevorgang der zweiten Stufe des OS (siehe [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) oder arbeitet mit dem [Volume Boot Record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) jeder Partition zusammen. Ausführliche Informationen finden Sie auf der [MBR-Wikipedia-Seite](https://en.wikipedia.org/wiki/Master_boot_record).<sup>[[5]](#references)</sup>

## Referenzen

- [1] [Volatility, mein eigener Cheatsheet (Teil 1): Image Identification](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Den Kernel Debugger Block finden](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (lokale Dateisysteme) – Win32-Apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI-basierter PC, Protective MBR: Was ist das? – Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: Volatility-Plugins zur Malware-Analyse](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
