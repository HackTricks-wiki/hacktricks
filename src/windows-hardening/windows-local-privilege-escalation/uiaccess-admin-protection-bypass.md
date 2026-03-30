# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows の AppInfo は `RAiLaunchAdminProcess` を公開しており、UIAccess プロセスを起動できる（アクセシビリティ向けに意図）。UIAccess は User Interface Privilege Isolation (UIPI) のメッセージフィルタリングの多くを回避できるため、アクセシビリティソフトがより高い IL の UI を操作できる。
- UIAccess を直接有効化するには `NtSetInformationToken(TokenUIAccess)` と **SeTcbPrivilege** が必要なため、低権限の呼び出し元はサービスに依存する。サービスは UIAccess を設定する前にターゲットバイナリに対して3つのチェックを行う:
  - 埋め込みマニフェストに `uiAccess="true"` が含まれていること。
  - Local Machine ルートストアで信頼された任意の証明書で署名されていること（EKU/Microsoft 要件はない）。
  - システムドライブ上の管理者専用パスに配置されていること（例: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`、特定の書き込み可能なサブパスは除外）。
- `RAiLaunchAdminProcess` は UIAccess 起動時に同意プロンプトを出さない（出してしまってはアクセシビリティツールがプロンプトを操作できなくなるため）。

## Token shaping and integrity levels
- チェックが成功すると、AppInfo は **呼び出し元トークンをコピー** し、UIAccess を有効化し、Integrity Level (IL) を引き上げる:
  - Limited admin user（ユーザーは Administrators に属しているがフィルタリングされた状態で実行） ➜ **High IL**。
  - Non-admin user ➜ IL を **+16 レベル**だけ増加させ、最大で **High** に到達（System IL は決して割り当てられない）。
- 呼び出し元トークンに既に UIAccess がある場合は IL は変更されない。
- 「ラチェット」トリック: UIAccess プロセスは自身で UIAccess を無効にし、`RAiLaunchAdminProcess` で再起動してさらに +16 IL を得ることができる。Medium➜High へは 255 回の再起動が必要（ノイズは大きいが可能）。

## Why UIAccess enables an Admin Protection escape
- UIAccess により、低 IL のプロセスが高 IL のウィンドウにウィンドウメッセージを送れる（UIPI フィルタをバイパス）。同一 IL では、`SetWindowsHookEx` のような古典的な UI プリミティブが任意のウィンドウを所有するプロセスへコード注入／DLL ロードを許す（COM が使う場合を含むメッセージ専用ウィンドウも対象）。
- Admin Protection は UIAccess プロセスを **限定ユーザーのアイデンティティ** の下で、しかし **High IL** でサイレントに起動する。High-IL の UIAccess プロセス内で任意コードが実行されると、攻撃者はデスクトップ上の他の High-IL プロセス（別ユーザーのものを含む）へ注入でき、意図された分離が破られる。

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ では API は Win32k (`NtUserGetWindowProcessHandle`) に移動し、呼び出し元が指定した `DesiredAccess` を使ってプロセスハンドルを開けるようになった。カーネル経路は `ObOpenObjectByPointer(..., KernelMode, ...)` を使用し、通常のユーザーモードのアクセスチェックをバイパスする。
- 実際の前提条件: ターゲットウィンドウは同一デスクトップ上にあり、UIPI チェックが通る必要がある。歴史的には、UIAccess を持つ呼び出し元は UIPI 失敗をバイパスしてカーネルモードハンドルを取得できた（CVE-2023-41772 として修正）。
- 影響: ウィンドウハンドルが強力なプロセスハンドル（一般的には `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` など）を取得するための「能力」になる。これによりクロスサンドボックスのアクセスが可能となり、対象がウィンドウ（メッセージ専用ウィンドウを含む）を公開していれば Protected Process / PPL の境界を破ることができる。
- 実用的な悪用フロー: HWND を列挙または特定（例: `EnumWindows`/`FindWindowEx`）、所有 PID を解決（`GetWindowThreadProcessId`）、`GetProcessHandleFromHwnd` を呼び出し、返されたハンドルを使ってメモリ読み書きやコードハイジャックのプリミティブを実行する。
- 修正後の挙動: UIAccess は UIPI 失敗時にカーネルモードでのオープンを付与せず、許可されるアクセス権はレガシーフックセットに制限される。Windows 11 24H2 はプロセス保護チェックと機能フラグによる安全な経路を追加している。システム全体で UIPI を無効化する（`EnforceUIPI=0`）とこれらの保護が弱まる。

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo は渡されたパスを `GetFinalPathNameByHandle` で解決し、その後にハードコードされたルート／除外パスに対して **文字列の allow/deny チェック** を適用する。この単純な検証から複数のバイパスクラスが生じる:
- **Directory named streams**: 除外された書き込み可能なディレクトリ（例: `C:\Windows\tracing`）は、そのディレクトリ自体の名前付きストリームを使ってバイパスできる（例: `C:\Windows\tracing:file.exe`）。文字列チェックは `C:\Windows\` を検出し、除外サブパスを見落とす。
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` は `.exe` 拡張子を必須としない。許可されたルート配下の書き換え可能なファイルを実行可能ペイロードで上書きするか、サイン済みで `uiAccess="true"` の EXE を任意の書き込み可能なサブディレクトリ（例: 存在する場合の更新の残り物 `Tasks_Migrated`）にコピーすると、secure-path チェックを通過できる。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: 非管理者が署名済み MSIX パッケージをインストールして `WindowsApps` に置けた時期があり、そこに UIAccess バイナリをパッケージ化して `RAiLaunchAdminProcess` で起動すると、プロンプト無しで High-IL UIAccess プロセスが得られた。Microsoft はこのパスを除外することで緩和した; また `uiAccess` 制限のある MSIX capability 自体が管理者インストールを要求するようになっている。

## Attack workflow (High IL without a prompt)
1. 署名された UIAccess バイナリを入手／作成する（マニフェストに `uiAccess="true"`）。
2. AppInfo の allowlist が許容する場所に配置する（または上記のパス検証のエッジケース／書き込み可能アーティファクトを悪用する）。
3. `RAiLaunchAdminProcess` を呼んで、UIAccess + 引き上げられた IL で**サイレントに**起動させる。
4. その High-IL の足場から、他のデスクトップ上の High-IL プロセスを `window hooks`/DLL 注入や同一 IL の他プリミティブで狙い、管理者コンテキストを完全に乗っ取る。

## Enumerating candidate writable paths
選択したトークンの視点から、名目上はセキュアなルート内にある書き込み／上書き可能なオブジェクトを発見するために PowerShell ヘルパーを実行する:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 広範な可視性を得るために管理者として実行してください。`-ProcessId` を low-priv プロセスに設定して、そのトークンのアクセスを反映させます。
- 候補を `RAiLaunchAdminProcess` で使用する前に、既知の許可されていないサブディレクトリを手動でフィルタして除外してください。

## 関連

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 参考
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
