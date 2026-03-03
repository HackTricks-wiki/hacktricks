# UIAccess を介した Admin Protection のバイパス

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows の AppInfo は、UIAccess プロセスを起動するための `RAiLaunchAdminProcess` を公開している（アクセシビリティ向け）。UIAccess はほとんどの User Interface Privilege Isolation (UIPI) のメッセージフィルタリングをバイパスするため、アクセシビリティソフトウェアがより高い IL の UI を操作できるようにする。
- UIAccess を直接有効にするには `NtSetInformationToken(TokenUIAccess)` を **SeTcbPrivilege** とともに呼ぶ必要があるため、権限の低い呼び出し元はサービスに依存する。サービスは UIAccess を設定する前にターゲットバイナリに対して以下の 3 つのチェックを行う:
  - 埋め込みマニフェストに `uiAccess="true"` が含まれていること。
  - Local Machine のルートストアで信頼されている任意の証明書で署名されていること（EKU/Microsoft による要求はなし）。
  - システムドライブ上の管理者専用パスに配置されていること（例: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`、ただし特定の書き込み可能なサブパスは除外）。
- `RAiLaunchAdminProcess` は UIAccess 起動時に同意プロンプトを表示しない（そうでなければアクセシビリティツールがプロンプトを操作できない）。

## トークン整形と整合性レベル
- チェックが成功すると、AppInfo は呼び出し元トークンを**コピー**し、UIAccess を有効化し、Integrity Level (IL) を引き上げる:
  - Limited admin user（Administrators に所属しているがフィルタリングされた状態で実行されているユーザー） ➜ **High IL**。
  - Non-admin user ➜ IL が **+16 レベル**だけ増加し、**High** 上限まで（System IL は決して付与されない）。
- 呼び出し元トークンが既に UIAccess を持っている場合、IL は変更されない。
- “Ratchet” トリック: UIAccess プロセスは自身の UIAccess を無効化して `RAiLaunchAdminProcess` で再起動し、さらに +16 IL を得ることができる。Medium➜High へは 255 回の再起動が必要（騒がしいが動作する）。

## なぜ UIAccess が Admin Protection 回避を可能にするか
- UIAccess により、より低い IL のプロセスがより高い IL のウィンドウへウィンドウメッセージを送信できる（UIPI フィルタをバイパス）。同一 IL の場合、`SetWindowsHookEx` のような古典的な UI プリミティブは、ウィンドウを所有する任意のプロセス（COM が使用する **message-only windows** を含む）へのコードインジェクション／DLL ロードを許可することがある。
- Admin Protection は UIAccess プロセスを **limited user のアイデンティティ** で、しかし **High IL** でサイレントに起動する。High-IL の UIAccess プロセス内で任意のコードが実行されると、攻撃者はデスクトップ上の他の High-IL プロセス（異なるユーザーに属するものを含む）へインジェクトでき、意図された分離が破られる。

## HWND→プロセスハンドルのプリミティブ（`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`）
- Windows 10 1803+ ではこの API は Win32k に移動し（`NtUserGetWindowProcessHandle`）、呼び出し元が指定する `DesiredAccess` を使ってプロセスハンドルを開けるようになった。カーネル側の経路は `ObOpenObjectByPointer(..., KernelMode, ...)` を使い、通常のユーザーモードアクセスチェックをバイパスする。
- 実務上の前提条件: 対象ウィンドウは同一デスクトップ上にあり、UIPI チェックが通る必要がある。歴史的には、UIAccess を持つ呼び出し元は UIPI 失敗をバイパスしてカーネルモードのハンドルを取得できた（CVE-2023-41772 で修正）。
- 影響: ウィンドウハンドルは強力なプロセスハンドル（一般的には `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`）を取得するための能力となりうる。通常は開けないはずのアクセス権でプロセスにアクセスでき、クロスサンドボックスアクセスや、対象がウィンドウ（message-only を含む）を公開している場合は Protected Process / PPL の境界を破ることができる。
- 実際の悪用フロー: HWND を列挙または発見（例: `EnumWindows`/`FindWindowEx`）、所有 PID を解決（`GetWindowThreadProcessId`）、`GetProcessHandleFromHwnd` を呼び出し、返されたハンドルを使ってメモリの読み書きやコードハイジャックプリミティブを実行する。
- 修正後の挙動: UIAccess は UIPI 失敗時にカーネルモードでのオープンを与えなくなり、許可されるアクセス権はレガシーなフックセットに制限される。Windows 11 24H2 はプロセス保護チェックを追加し、機能フラグでより安全な経路を導入した。UIPI をシステム全体で無効化する（`EnforceUIPI=0`）とこれらの保護が弱まる。

## セキュアディレクトリ検証の弱点 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo は渡されたパスを `GetFinalPathNameByHandle` で解決し、その後ハードコードされたルート／除外に対して **文字列ベースの許可／拒否チェック** を行う。単純な検証に起因する複数のバイパス類がある:
- **Directory named streams**: 除外対象ではない（書き込み可能な）ディレクトリ（例: `C:\Windows\tracing`）は、ディレクトリ自体の名前付けストリームを使ってバイパスできる。例: `C:\Windows\tracing:file.exe`。文字列チェックは `C:\Windows\` を見て除外サブパスを見落とす。
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` は **`.exe` 拡張子を必須としない**。許可されたルート下の任意の書き換え可能なファイルを実行可能ペイロードで上書きするか、署名された `uiAccess="true"` の EXE を書き込み可能なサブディレクトリ（例: 更新の残骸として存在する `Tasks_Migrated` など）にコピーしても、secure-path チェックを通過する。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: ノン管理者が署名された MSIX パッケージを `WindowsApps` にインストールでき、それが除外対象でなかったためにバイパスできた。MSIX に UIAccess バイナリを含めて `RAiLaunchAdminProcess` で起動すると、プロンプトなしで High-IL の UIAccess プロセスが得られた。Microsoft はこのパスを除外することで緩和した；また `uiAccess` に制限された MSIX の機能自体が管理者インストールを要求するようになっている。

## 攻撃ワークフロー（プロンプトなしで High IL を獲得）
1. 署名された UIAccess バイナリを入手／作成する（マニフェストに `uiAccess="true"`）。
2. AppInfo の許可リストが受け入れる場所に配置する（あるいは上記のパス検証のエッジケース／書き込み可能なアーティファクトを悪用する）。
3. `RAiLaunchAdminProcess` を呼び出して、UIAccess と引き上げられた IL でそれを **サイレントに** 起動する。
4. その High-IL の足場から、他のデスクトップ上の High-IL プロセスを `SetWindowsHookEx` 等のウィンドウフック／DLL インジェクションや同一 IL の他のプリミティブで標的にし、管理者コンテキストを完全に侵害する。

## 候補となる書き込み可能パスの列挙
選択したトークンの視点から、名目上セキュアなルート内部にある書き込み可能／上書き可能なオブジェクトを発見するために PowerShell ヘルパーを実行する:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- より広い可視性のために Run as Administrator を実行してください。トークンのアクセスを反映させるため、`-ProcessId` を low-priv process のプロセスに設定します。
- `RAiLaunchAdminProcess` で候補を使用する前に、既知の許可されていないサブディレクトリを手動で除外してフィルタリングしてください。

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
