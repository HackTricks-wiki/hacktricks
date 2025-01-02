# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

Процеси можуть бути відкриті на хостах, де відомі ім'я користувача та або пароль, або хеш, за допомогою WMI. Команди виконуються за допомогою WMI через Wmiexec, що забезпечує напівінтерактивний досвід оболонки.

**dcomexec.py:** Використовуючи різні кінцеві точки DCOM, цей скрипт пропонує напівінтерактивну оболонку, подібну до wmiexec.py, спеціально використовуючи об'єкт ShellBrowserWindow DCOM. В даний час підтримує об'єкти MMC20. Application, Shell Windows та Shell Browser Window. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Основи WMI

### Простір імен

Структурований у ієрархії, подібній до каталогу, верхній контейнер WMI - це \root, під яким організовані додаткові каталоги, які називаються просторами імен.
Команди для переліку просторів імен:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Класи в межах простору імен можна перерахувати за допомогою:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Класи**

Знання назви класу WMI, такого як win32_process, та простору імен, в якому він знаходиться, є критично важливим для будь-якої операції WMI.  
Команди для переліку класів, що починаються з `win32`:
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

Методи, які є однією або кількома виконуваними функціями класів WMI, можуть бути виконані.
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
## WMI Перерахунок

### Статус служби WMI

Команди для перевірки, чи працює служба WMI:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Інформація про систему та процеси

Збір інформації про систему та процеси за допомогою WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Для атакуючих WMI є потужним інструментом для перерахунку чутливих даних про системи або домени.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Віддалене запитування WMI для отримання конкретної інформації, такої як локальні адміністратори або користувачі, що увійшли в систему, є можливим за умови ретельного складання команд.

### **Ручне віддалене запитування WMI**

Сховане виявлення локальних адміністраторів на віддаленій машині та користувачів, що увійшли в систему, можна досягти за допомогою специфічних запитів WMI. `wmic` також підтримує читання з текстового файлу для виконання команд на кількох вузлах одночасно.

Для віддаленого виконання процесу через WMI, наприклад, для розгортання агента Empire, використовується наступна структура команди, успішне виконання якої вказується значенням повернення "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Цей процес ілюструє можливості WMI для віддаленого виконання та перерахунку системи, підкреслюючи його корисність як для адміністрування системи, так і для тестування на проникнення.

## References

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
