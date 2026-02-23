# UIAccess を利用した Admin Protection のバイパス

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows AppInfo は `RAiLaunchAdminProcess` を公開して UIAccess プロセスを起動できる（アクセシビリティ向け）。UIAccess は User Interface Privilege Isolation (UIPI) のメッセージフィルタリングの多くをバイパスするため、アクセシビリティ用ソフトがより高い IL の UI を操作できるようにする。
- UIAccess を直接有効化するには `NtSetInformationToken(TokenUIAccess)` と **SeTcbPrivilege** が必要なので、低権限の呼び出し元はサービスに依存する。サービスは UIAccess を設定する前にターゲットバイナリに対して 3 つのチェックを行う:
  - 埋め込みマニフェストに `uiAccess="true"` が含まれている。
  - ローカルマシンのルートストアで信頼された任意の証明書で署名されている（EKU/Microsoft 要件はない）。
  - システムドライブ上の管理者専用パスに配置されている（例: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`、特定の書き込み可能なサブパスは除く）。
- `RAiLaunchAdminProcess` は UIAccess 起動に対して同意プロンプトを表示しない（さもないとアクセシビリティツールがプロンプトを操作できない）。

## Token shaping and integrity levels
- チェックが成功すると、AppInfo は **呼び出し元トークンをコピー** し、UIAccess を有効化して Integrity Level (IL) を引き上げる:
  - Limited admin user（ユーザーは `Administrators` に属するがフィルタリングされた状態で実行） ➜ **High IL**。
  - Non-admin user ➜ IL が **+16 レベル** 増加し、**High** 上限まで上がる（System IL は決して割り当てられない）。
- 呼び出し元トークンが既に UIAccess を持っている場合、IL は変更されない。
- ラチェット・トリック: UIAccess プロセスは自身で UIAccess を無効化して `RAiLaunchAdminProcess` で再起動し、さらに +16 IL を得ることができる。Medium➜High には 255 回の再起動が必要（騒がしいが可能）。

## なぜ UIAccess が Admin Protection の回避を可能にするか
- UIAccess は低 IL のプロセスが高 IL のウィンドウにウィンドウメッセージを送れるようにする（UIPI フィルタをバイパス）。同一 IL の場合、`SetWindowsHookEx` のような古典的な UI プリミティブは任意のウィンドウを所有するプロセス（COM が使う message-only window を含む）へのコード注入／DLL ロードを許す。
- Admin Protection は UIAccess プロセスを限定ユーザーの識別で、しかし **High IL** で静かに起動する。High IL の UIAccess プロセス内で任意のコードが実行されると、攻撃者はデスクトップ上の他の High IL プロセス（別ユーザーのものを含む）に注入でき、意図された分離を破る。

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo は与えられたパスを `GetFinalPathNameByHandle` で解決し、その後ハードコードされたルート／除外に対して **文字列の allow/deny チェック** を適用する。単純な検証に由来する複数のバイパスクラスが存在する:
- **Directory named streams**: 除外された書き込み可能ディレクトリ（例: `C:\Windows\tracing`）は、ディレクトリ自体の名前付きストリームを使ってバイパスできる。例: `C:\Windows\tracing:file.exe`。文字列チェックは `C:\Windows\` を見て、除外サブパスを見落とす。
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` は **`.exe` 拡張子を要求しない**。許可されたルートの下にある任意の書き込み可能ファイルを実行可能ペイロードで上書きするか、署名済みで `uiAccess="true"` の EXE を書き込み可能なサブディレクトリ（例: 更新の残骸である `Tasks_Migrated` 等）にコピーすると、secure-path チェックを通過する。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admin が署名済みの MSIX パッケージを `WindowsApps` にインストールできたため（当該パスが除外されていなかった）、MSIX に UIAccess バイナリを入れて `RAiLaunchAdminProcess` で起動するとプロンプト無しで High-IL UIAccess プロセスが得られた。Microsoft はこのパスを除外することで対処した；`uiAccess` 制限付きの MSIX capability 自体は既に管理者インストールを要求する。

## Attack workflow (High IL without a prompt)
1. 署名済みの UIAccess バイナリ（マニフェストに `uiAccess="true"`）を用意／作成する。
2. AppInfo の allowlist が受け入れる場所に配置する（または上記のパス検証のエッジケース／書き込み可能アーティファクトを悪用する）。
3. `RAiLaunchAdminProcess` を呼んで、UIAccess + 引き上げられた IL で **サイレントに** 起動させる。
4. その High-IL の足場から、ウィンドウフック／DLL 注入や同一 IL の他のプリミティブを使ってデスクトップ上の別の High-IL プロセスを標的にし、管理者コンテキストを完全に乗っ取る。

## Enumerating candidate writable paths
選択したトークンの視点から名目上は secure roots 内の書き込み可能／上書き可能オブジェクトを発見するために、PowerShell ヘルパーを実行する。
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator にしてより広い可視性を得る。`-ProcessId` をその token のアクセスを反映するために low-priv process に設定する。
- RAiLaunchAdminProcess で候補を使用する前に、既知の禁止されたサブディレクトリを手動で除外するようフィルタリングする。

## 参考資料
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
