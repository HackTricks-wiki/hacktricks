# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony service（TapiSrv、`tapisrv.dll`）が **TAPI server** として構成されている場合、認証済み SMB clients に対して **`\pipe\tapsrv` named pipe 上の `tapsrv` MSRPC interface** を公開します。リモート client 向け非同期 event delivery の設計上のバグにより、攻撃者は mailslot handle を、`NETWORK SERVICE` が書き込み可能な **既存ファイルの任意の位置への制御可能な 4-byte write** に変換できます。この primitive を利用して Telephony admin list を上書きし、**admin-only arbitrary DLL load** を悪用することで、`NETWORK SERVICE` として code execution を実行できます。<sup>[[1]](#references)</sup>

## Attack Surface

- **有効化されている場合のみリモート公開**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` で sharing が許可されている必要があります（または `TapiMgmt.msc` / `tcmsetup /c <server>` で構成）。デフォルトでは `tapsrv` は local-only です。
- Interface: **SMB named pipe** 上の MS-TRP（`tapsrv`）。そのため攻撃者には有効な SMB auth が必要です。
- Service account: `NETWORK SERVICE`（manual start、on-demand）。<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` は async event delivery を初期化します。pull mode では、service は次を実行します:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser` が mailslot path（`\\*\MAILSLOT\...`）であることを検証しません。そのため、`NETWORK SERVICE` が書き込み可能な **既存の filesystem path** はすべて受け入れられます。
- 各 async event write は、開かれた handle に単一の **`DWORD` = `InitContext`**（後続の `Initialize` request で攻撃者が制御）を保存し、**write-what/write-where（4 bytes）** を実現します。<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Target file を開く**: `pszDomainUser = <existing writable path>`（例: `C:\Windows\TAPI\tsec.ini`）として `ClientAttach` を実行します。
2. 書き込む各 `DWORD` について、`ClientRequest` に対して次の RPC sequence を実行します:
- `Initialize`（`Req_Func 47`）: `InitContext = <4-byte value>`、`pszModuleName = DIALER.EXE`（または per-user priority list の上位にある別の entry）を設定します。
- `LRegisterRequestRecipient`（`Req_Func 61`）: `dwRequestMode = LINEREQUESTMODE_MAKECALL`、`bEnable = 1`（line app を登録し、highest priority recipient を再計算）。
- `TRequestMakeCall`（`Req_Func 121`）: `NotifyHighestPriorityRequestRecipient` を強制し、async event を生成します。
- `GetAsyncEvents`（`Req_Func 0`）: write を dequeue / complete します。
- 再度 `LRegisterRequestRecipient` を `bEnable = 0` で実行（unregister）。
- `Shutdown`（`Req_Func 86`）で line app を tear down します。
- Priority control: “highest priority” recipient は、`HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` と `pszModuleName` を比較して選択されます（client を impersonating して読み取られます）。必要に応じて、`LSetAppPriority`（`Req_Func 69`）で module name を追加します。
- file は `OPEN_EXISTING` が使用されるため、**あらかじめ存在している必要があります**。`NETWORK SERVICE` が書き込み可能な一般的な候補: `C:\Windows\System32\catroot2\dberr.txt`、`C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`、`...\MpSigStub.log`。<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **自分自身に Telephony “admin” 権限を付与**: `C:\Windows\TAPI\tsec.ini` を target にし、上記の 4-byte writes を使用して `[TapiAdministrators]\r\n<DOMAIN\\user>=1` を append します。新しい session（`ClientAttach`）を開始すると、service が INI を再読み込みし、アカウントに対して `ptClient->dwFlags |= 9` を設定します。
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` を指定して `GetUIDllName` を送信し、`dwProviderFilenameOffset` 経由で path を指定します。admin の場合、service は `LoadLibrary(path)` を実行してから export `TSPI_providerUIIdentify` を呼び出します:
- 実在する Windows SMB share への UNC paths で動作します。一部の攻撃者 SMB servers では `ERROR_SMB_GUEST_LOGON_BLOCKED` が発生します。
- Alternative: 同じ 4-byte write primitive を使用して local DLL を時間をかけて配置し、その後 load します。
3. **Payload**: export は `NETWORK SERVICE` として実行されます。最小限の DLL で `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` を実行し、non-zero value（例: `0x1337`）を返すと、service が DLL を unload するため、execution を確認できます。<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- 必要でない限り TAPI server mode を無効化し、`\pipe\tapsrv` への remote access を block します。
- client から提供された paths を開く前に、mailslot namespace validation（`\\*\MAILSLOT\`）を強制します。
- `C:\Windows\TAPI\tsec.ini` の ACLs を lock down し、変更を monitor します。default 以外の paths を load する `GetUIDllName` calls に alert を設定します。<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
