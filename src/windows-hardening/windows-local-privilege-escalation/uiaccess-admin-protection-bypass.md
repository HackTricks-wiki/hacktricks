# UIAccess を介した Admin Protection のバイパス

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows AppInfo は `RAiLaunchAdminProcess` を公開して UIAccess プロセスを起動できる（アクセシビリティ用途）。UIAccess はほとんどの User Interface Privilege Isolation (UIPI) メッセージフィルタリングをバイパスし、アクセシビリティソフトがより高い IL の UI を操作できるようにする。
- UIAccess を直接有効化するには `NtSetInformationToken(TokenUIAccess)` を **SeTcbPrivilege** で呼ぶ必要があるため、低権限の呼び出し元はこのサービスに依存する。サービスは UIAccess を設定する前にターゲットバイナリに対して 3 つのチェックを行う:
  - 埋め込まれたマニフェストが `uiAccess="true"` を含むこと。
  - Local Machine のルートストアで信頼されている任意の証明書で署名されていること（EKU/Microsoft の要件はない）。
  - システムドライブ上の管理者専用パスに配置されていること（例: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`、特定の書き込み可能なサブパスは除外）。
- `RAiLaunchAdminProcess` は UIAccess 起動時に同意プロンプトを表示しない（さもなければアクセシビリティツールがプロンプトを操作できない）。

## トークン形成と整合性レベル
- チェックに成功すると、AppInfo は **呼び出し元トークンをコピーし**、UIAccess を有効にし、整合性レベル (IL) を引き上げる:
  - 限定的な管理者ユーザー（ユーザーが Administrators に属するがフィルタリングされた状態） ➜ **High IL**。
  - 非管理者ユーザー ➜ IL は **+16 レベル**ずつ増加し、最大で **High** に到達する（System IL は付与されない）。
- 呼び出し元トークンがすでに UIAccess を持っている場合、IL は変更されない。
- “Ratchet” トリック: UIAccess プロセスは自身の UIAccess を無効化し、`RAiLaunchAdminProcess` で再起動してさらに +16 IL を得ることができる。Medium➜High には 255 回の再起動が必要（騒がしいが動作する）。

## なぜ UIAccess が Admin Protection の回避を可能にするのか
- UIAccess により低 IL のプロセスが高 IL のウィンドウへウィンドウメッセージを送信できる（UIPI フィルタをバイパス）。同一 IL の場合、`SetWindowsHookEx` のような古典的な UI プリミティブはウィンドウを所有する任意のプロセス（COM が使う message-only windows を含む）へのコード注入/DLL ロードを許すことがある。
- Admin Protection は UIAccess プロセスを限定ユーザーのアイデンティティで、しかし **High IL** でサイレントに起動する。High-IL の UIAccess プロセス内で任意のコードが実行されると、攻撃者はデスクトップ上の他の High-IL プロセス（異なるユーザーに属するものを含む）へ注入でき、意図された分離を破壊できる。

## HWND→プロセスハンドル プリミティブ (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ では API が Win32k (`NtUserGetWindowProcessHandle`) に移動し、呼び出し元指定の `DesiredAccess` を使ってプロセスハンドルを開けるようになった。カーネル経路は `ObOpenObjectByPointer(..., KernelMode, ...)` を使っており、通常のユーザーモードアクセスチェックを回避する。
- 実務上の前提条件: ターゲットウィンドウは同一デスクトップ上にあり、UIPI チェックをパスする必要がある。歴史的には UIAccess を持つ呼び出し元が UIPI の失敗をバイパスしてカーネルモードハンドルを取得できた（CVE-2023-41772 として修正）。
- 影響: ウィンドウハンドルが強力なプロセスハンドル（一般的に `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`）を取得するための「ケイパビリティ」になり、呼び出し元が通常は開けないアクセス権を得られる。これによりクロスサンドボックスアクセスが可能になり、ターゲットが任意のウィンドウ（message-only windows を含む）を公開していれば Protected Process / PPL 境界が破られる可能性がある。
- 実用的な悪用フロー: HWND を列挙または特定（例: `EnumWindows` / `FindWindowEx`）、所有 PID を解決 (`GetWindowThreadProcessId`)、`GetProcessHandleFromHwnd` を呼び出し、返されたハンドルでメモリ読み書きやコードハイジャックを行う。
- 修正後の挙動: UIAccess は UIPI 失敗時にカーネルモードでのオープンを付与しなくなり、許可されるアクセス権はレガシーなフックセットに制限された。Windows 11 24H2 ではプロセス保護チェックや機能フラグ付きの安全な経路が追加されている。UIPI をシステム全体で無効化する（`EnforceUIPI=0`）とこれらの保護は弱体化する。

## セキュアディレクトリ検証の弱点 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo は与えられたパスを `GetFinalPathNameByHandle` で解決し、その後ハードコードされたルート/除外に対して **文字列の許可/拒否チェック** を適用する。単純な検証に起因する回避クラスが複数存在する:
- **Directory named streams**: 除外された書き込み可能ディレクトリ（例: `C:\Windows\tracing`）は、ディレクトリ自体の名前付きストリームを使って回避できる（例: `C:\Windows\tracing:file.exe`）。文字列チェックは `C:\Windows\` を検出して除外サブパスを見落とす。
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` は **`.exe` 拡張子を必須としない**。許可されたルート下の任意の書き込み可能なファイルを実行ファイルペイロードで上書きするか、署名済みの `uiAccess="true"` EXE を書き込み可能なサブディレクトリ（例: 残存する update のような `Tasks_Migrated`）にコピーするとセキュアパスチェックを通過する。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: 非管理者が `WindowsApps` に署名済み MSIX パッケージをインストールでき、その中に UIAccess バイナリを含めて `RAiLaunchAdminProcess` で起動するとプロンプトなしで High-IL UIAccess プロセスが得られた。Microsoft はこのパスを除外することで緩和した；また `uiAccess` 制限された MSIX capability 自体は既に管理者インストールを要求する。

## 攻撃ワークフロー（プロンプトなしで High IL を得る）
1. 署名済みの UIAccess バイナリを入手/作成する（マニフェストに `uiAccess="true"`）。
2. AppInfo の許容リストが受け入れる場所に配置する（または上記のパス検証のエッジケース/書き込み可能なアーティファクトを悪用する）。
3. `RAiLaunchAdminProcess` を呼び出して、UIAccess + 増加した IL でそれを **サイレントに** 起動する。
4. その High-IL 足場から、同一 IL のプリミティブ（ウィンドウフック/DLL 注入など）を使ってデスクトップ上の別の High-IL プロセスを狙い、管理者コンテキストを完全に奪取する。

## 候補となる書き込み可能パスの列挙
選択したトークンの視点から名目上セキュアなルート内の書き込み/上書き可能なオブジェクトを発見するために PowerShell ヘルパーを実行する:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 管理者として実行すると可視性が広がります。`-ProcessId` を low-priv process に設定して、そのトークンのアクセスをミラーしてください。
- `RAiLaunchAdminProcess` を使用する前に、既知の許可されていないサブディレクトリを手動でフィルタして除外してください。

## 参考資料
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
