# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony service (TapiSrv, `tapisrv.dll`) が **TAPI server** として構成されている場合、認証済みの SMB クライアントに対して **`\\pipe\\tapsrv` named pipe 上で `tapsrv` MSRPC インターフェース** を公開します。リモートクライアント向けの非同期イベント配信にある設計上のバグにより、攻撃者は mailslot ハンドルを任意の既存ファイルに対する **制御可能な 4 バイト書き込み（`NETWORK SERVICE` によって書き込み可能なファイル）** に変換できます。このプリミティブを連鎖させて Telephony の管理者リストを書き換え、管理者専用の任意 DLL ロードを悪用して `NETWORK SERVICE` としてコードを実行できます。

## Attack Surface
- **リモート公開は有効化時のみ**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` が共有を許可している（または `TapiMgmt.msc` / `tcmsetup /c <server>` で設定されている）必要があります。デフォルトでは `tapsrv` はローカル限定です。
- インターフェース: MS-TRP (`tapsrv`) が **SMB named pipe** 上で動作するため、攻撃者は有効な SMB 認証を必要とします。
- サービスアカウント: `NETWORK SERVICE`（手動開始、オンデマンド）。

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` が非同期イベント配信を初期化します。プルモードでは、サービスは次を実行します:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser` が mailslot パス（`\\*\MAILSLOT\...`）であることを検証せずに開くため、`NETWORK SERVICE` によって書き込み可能な任意の **既存のファイルシステムパス** が受け入れられます。
- すべての非同期イベント書き込みは開かれたハンドルに対して単一の **`DWORD` = `InitContext`**（後続の `Initialize` リクエストで攻撃者が制御）を書き込みます。これにより **write-what/write-where（4 バイト）** が得られます。

## Forcing Deterministic Writes
1. **ターゲットファイルを開く**: `ClientAttach` を `pszDomainUser = <existing writable path>`（例: `C:\Windows\TAPI\tsec.ini`）で呼び出す。
2. 書き込みたい各 `DWORD` について、`ClientRequest` に対して次の RPC シーケンスを実行する:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` を設定し、`pszModuleName = DIALER.EXE`（または per-user 優先リストの上位の別モジュール）を指定。
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1`（ラインアプリを登録し、最高優先受信者を再計算）。
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` を強制し、非同期イベントを生成。
- `GetAsyncEvents` (`Req_Func 0`): キューから取り出して書き込みを完了。
- `LRegisterRequestRecipient` を再度 `bEnable = 0` で呼び出して登録解除。
- `Shutdown` (`Req_Func 86`) でラインアプリを終了。
- 優先度制御: “highest priority” の受信者は `pszModuleName` を `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` と比較して選ばれます（クライアントとしてインパーソネイト中に読み取り）。必要なら `LSetAppPriority` (`Req_Func 69`) を使ってモジュール名を挿入します。
- ファイルは `OPEN_EXISTING` が使われるため **既に存在している必要があります**。`NETWORK SERVICE` が書き込み可能でよくある候補: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **自分に Telephony “admin” を付与**: `C:\Windows\TAPI\tsec.ini` をターゲットにして、上記の 4 バイト書き込みで `[TapiAdministrators]\r\n<DOMAIN\\user>=1` を追記します。サービスが INI を再読み込みしてあなたのアカウントに対して `ptClient->dwFlags |= 9` を設定するように、新しいセッション（`ClientAttach`）を開始します。
2. **管理者専用の DLL ロード**: `GetUIDllName` を `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` で送信し、`dwProviderFilenameOffset` 経由でパスを渡します。管理者の場合、サービスは `LoadLibrary(path)` を行い、エクスポート `TSPI_providerUIIdentify` を呼び出します:
- UNC パスで実在する Windows SMB 共有を指定して機能します；一部の攻撃者 SMB サーバは `ERROR_SMB_GUEST_LOGON_BLOCKED` を返すことがあります。
- 代替手段: 同じ 4 バイト書き込みプリミティブを使ってローカルに DLL を徐々に書き込み、それをロードする。
3. **ペイロード**: エクスポートは `NETWORK SERVICE` 権限で実行されます。最小の DLL であれば `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` を実行し、サービスが DLL をアンロードするように非ゼロ値（例: `0x1337`）を返して実行を確認できます。

## Hardening / Detection Notes
- 必要がない限り TAPI server mode を無効化し、リモートからの `\pipe\tapsrv` へのアクセスをブロックする。
- クライアントが供給するパスを開く前に mailslot 名前空間検証（`\\*\MAILSLOT\`）を強制する。
- `C:\Windows\TAPI\tsec.ini` の ACL を厳格化し、変更を監視する；デフォルト以外のパスをロードする `GetUIDllName` 呼び出しを検出してアラートを上げる。

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
