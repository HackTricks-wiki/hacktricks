# Kernel-Mode File Access Check Bypasses

{{#include ../../banners/hacktricks-training.md}}

## 脆弱な driver のパターン

driver は caller を impersonate するだけでは、caller のセキュリティ境界を維持できません。Kernel mode からのオブジェクトの open は通常、アクセスチェックをバイパスします。`OBJ_KERNEL_HANDLE` は、作成されたハンドルを kernel mode からのみアクセス可能にするだけです。driver が user mode に代わってオブジェクトを open または操作する場合は、`OBJ_FORCE_ACCESS_CHECK` も使用して、Object Manager が有効なトークンに対して要求されたアクセスを評価するようにする必要があります。<sup>[[3]](#references)[[4]](#references)</sup>

次の流れに該当するファイル処理 IOCTL と create callback を監査してください。<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode が path、source handle、desired access、または operation type を指定する。
2. driver が caller を impersonate するが、`OBJ_FORCE_ACCESS_CHECK` を指定せずに `IoCreateFileEx`、`ZwCreateFile`、または同様の routine を呼び出す。
3. kernel 専用のファイルまたはディレクトリの handle が、handle ごとの状態に保存される。
4. 後続の操作で、最初の open 時に要求された access mask など、攻撃者の影響を受ける状態に基づいて impersonate するかどうかが決まる。
5. 特権付きの分岐が、`BypassAccessCheck` information class を使って rename または link を実行する。

これは**confused-deputy file primitive**であり、必ずしもメモリ破損を伴うわけではありません。特に危険な状態の逆転は、「write を要求した場合は impersonate し、write を要求しない場合は特権状態を維持する」というものです。この設計では、意図的に read access のみを要求することで、より強力な経路を利用できる場合があります。<sup>[[3]](#references)</sup>

## vSMB の例: 特権付き root と特権付き rename

`storvsp.sys` は Virtual Server Message Block (vSMB) を実装します。**Virtual Machine Platform** 機能が有効な場合、user mode から `\\.\STORVSP` を通じて `\Device\STORVSP` にアクセスできます。vSMB filesystem path の形式は `\\.\STORVSP\VSMB\??\C:\path` です。CVE-2025-59517 と CVE-2025-64673 では、一貫しない 2 つのアクセス制御判断によって、この interface がローカル権限昇格につながり得ることが示されました。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

ソース内の関数と CVE の対応付けは、Microsoft のソースではなく、パッチ適用済みバイナリの reverse engineering に基づいています。研究者は、2 つの識別子が反対の関数に対応している可能性があると警告しています。<sup>[[3]](#references)</sup>

### 1. 保護されたディレクトリを root とする read-only share を作成する

脆弱な create path では、要求された権限が `HasReadAccess`、`HasWriteAccess`、`HasAppendAccess` などの永続的なフラグに記録されていました。その後、`OBJ_KERNEL_HANDLE` は指定していましたが、`OBJ_FORCE_ACCESS_CHECK` は指定せずに backing path を open していました。そのため、impersonation を試みても、ファイルの open 時に caller の NTFS 権限は尊重されませんでした。<sup>[[3]](#references)[[4]](#references)</sup>

`FILE_READ_DATA` のみを要求します。これにより `HasWriteAccess` はクリアされたまま、内部 root が保護されたディレクトリである share を取得できます。<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

重要なアーティファクトは、ユーザーモードの System32 ディレクトリハンドルではありません。これは、特権付きカーネルルートハンドルを含むドライバー状態に関連付けられた vSMB デバイスハンドルです。<sup>[[3]](#references)</sup>

### 2. 状態の不一致を利用して保護されたファイルを置き換える

IOCTL `0x240330` は、ソースファイルハンドル、情報クラス、可変長の情報バッファを受け取ります。<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

脆弱な handler は `FileRenameInformation`、`FileLinkInformation`、`FileRenameInformationEx` を受け付けていました。通常の rename path では、親 path と最後のコンポーネントを分離し、保存済みの root handle を基準に親を開いていました。この open でも `OBJ_FORCE_ACCESS_CHECK` を指定せず、`OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` を使用していました。rename 構造体内の、攻撃者が指定した `RootDirectory` がゼロ以外の場合は拒否されるため、driver が特権付きのディレクトリ handle を指定していました。<sup>[[3]](#references)</sup>

悪用可能な branch は、stage 1 で write access を**要求しない**ことで選択されました。<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: 保存済みの root security context を impersonate する。
- `HasWriteAccess == 0`: impersonation をスキップし、`FileRenameInformation` または `FileRenameInformationEx` を対応する `BypassAccessCheck` variant に変換する。

handler は、攻撃者が指定した source handle を `PsInitialSystemProcess` に複製し、それを file object として参照してから、特権付きの target-directory handle を rename 構造体に設定し、`ZwSetInformationFile` を呼び出していました。`ReplaceIfExists = TRUE` の場合、呼び出し元が制御するファイルで、保護された root 配下の既存ファイルを置き換えることができました。<sup>[[3]](#references)</sup>

同様の handler をレビューする際は、すべての branch について、**handle の由来と security context の両方**を追跡してください。input validation、integer-overflow checks、`IO_STOP_ON_SYMLINK`、受け付ける information class の制限だけでは、特権付き root handle と access-check-bypass operation の組み合わせを補えません。<sup>[[3]](#references)</sup>

## 保護されたファイルへの書き込みから SYSTEM 実行へ

特権プロセスが置き換えられた module を後でロードすると、保護されたファイルの置き換え機能が code execution につながります。実証された chain では、置き換え先は `C:\Windows\System32\wuapi.dll` でした。interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` の local-server COM class `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` を activate して `IWaaSRemediation::LaunchDetectionOnly()` を呼び出すと、SYSTEM process がその DLL をロードしました。<sup>[[3]](#references)</sup>

この COM call は**activation trigger**であり、[COM registry hijacking](com-hijacking.md) ではありません。ファイル操作機能が仕込んだ module を配置し、特権 loader が実行します。他の保護ファイル書き込み chain では、target を選ぶ前に、対象となる image、DLL path、signature policy、bitness、exported function、信頼できる trigger を特定してください。一般的な loader 分析の手順については、[任意のファイル書き込みを DLL hijacking につなげる](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)を参照してください。<sup>[[3]](#references)</sup>

### Session 0 の token を対話型デスクトップに移す

service がロードした payload は、通常 Session 0 で実行されます。対話型 process を作成するには、`WTSGetActiveConsoleSessionId` でアクティブな console session を取得し、必要な token privilege を有効にして、現在の SYSTEM token を primary token として複製し、その `TokenSessionId` をアクティブな session に設定します。その後、`CreateProcessAsUserW` でその token を使用し、`STARTUPINFO.lpDesktop = L"winsta0\\default"` を指定します。<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` は、このシナリオでトークンのセッション ID を設定するために必要です。また、対話型ウィンドウステーションとデスクトップがトークンにアクセスを許可している必要があります。より広範なトークンコピーのワークフローについては、[Session 0 からのトークン複製](sedebug-+-seimpersonate-copy-token.md)を参照してください。<sup>[[3]](#references)[[5]](#references)</sup>

## パッチ適用とレビューのガイダンス

Microsoft の 2025 年 12 月の更新プログラムにより、実証された一連の攻撃手順は修正されました。リバースエンジニアリングの結果、パッチ適用後の vSMB 作成パスでは、`FILE_WRITE_DATA` を指定せずに共有ルートを要求する信頼されていない呼び出し元が拒否されることが判明しました。関連する操作にも強制的なアクセスチェックが追加されました。これにより、権限のない呼び出し元が特権付きルートを取得する前に、状態の反転が阻止されます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

ドライバーコードでは、以下のルールを適用してください。<sup>[[3]](#references)[[4]](#references)</sup>

- ユーザーモードの要求に代わってオブジェクトを開く場合は、必ず `OBJ_FORCE_ACCESS_CHECK` を追加してください。`OBJ_KERNEL_HANDLE` を認可制御として扱わないでください。<sup>[[4]](#references)</sup>
- 要求元のモードと有効な主体コンテキストを取得して検証してください。要求された権限によって、より特権的な実行分岐が選択されることのないようにしてください。
- 正しいオブジェクト型、アクセスマスク、および `UserMode` を使って、ユーザーハンドルを検証してください。ハンドルをシステムプロセスに複製しても、要求された操作の権限は検証されません。
- 対象の解決は信頼されたハンドルを基準に行ってください。ただし、その信頼されたハンドル自体が、要求元に対する強制アクセスチェックを経て開かれていることを確認してください。
- ユーザー主導の操作では、`File*BypassAccessCheck` クラスを避けてください。内部コードで本当に必要な場合は、ユーザーが制御するアクセスフラグとは独立した認可判断で、そのパスを制限してください。
- 影響を受けるシステムにパッチを適用してください。Virtual Machine Platform が `storvsp.sys` を読み込む場合、この脆弱な領域が関係します。<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - 仮想共有から物理シェルへ：Windows の一貫性のないアクセス制御を利用した LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - オブジェクトハンドル](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW 関数](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
