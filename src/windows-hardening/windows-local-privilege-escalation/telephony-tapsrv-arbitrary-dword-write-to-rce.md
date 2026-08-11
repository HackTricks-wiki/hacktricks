# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony service（TapiSrv、`tapisrv.dll`）を **TAPI server** として構成すると、認証済み SMB clients に対して、**`\pipe\tapsrv` named pipe 上の `tapsrv` MSRPC interface** を公開します。非同期イベント配信における CVE-2026-20931 により、攻撃者は想定上の mailslot handle を、`NETWORK SERVICE` が書き込み可能な**既存ファイルへの制御可能な 4-byte write** に変換できます。公開された chain では Telephony administrator list を上書きし、その後 administrator-only DLL load に到達して、`NETWORK SERVICE` として実行します。<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **有効化されている場合のみ remote exposure**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` によって sharing が許可されている必要があります（または `TapiMgmt.msc` / `tcmsetup /c <server>` で構成）。デフォルトでは `tapsrv` は local-only です。
- Interface: **SMB named pipe** 上の MS-TRP (`tapsrv`)。そのため攻撃者には有効な SMB auth が必要です。
- Service account: `NETWORK SERVICE`（manual start、on-demand）。<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` は async event delivery を初期化します。pull mode では、service は次を実行します。
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser` が mailslot path（`\\*\MAILSLOT\...`）であることを検証しません。`NETWORK SERVICE` が書き込み可能な**既存の filesystem path** はすべて受け入れられます。
- 各 async event write は、開かれた handle に単一の **`DWORD` = `InitContext`**（後続の `Initialize` request で攻撃者が制御）を格納し、**write-what/write-where (4 bytes)** を実現します。<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `pszDomainUser = <existing writable path>`（例: `C:\Windows\TAPI\tsec.ini`）として `ClientAttach` を実行します。
2. 書き込む各 `DWORD` について、`ClientRequest` に対して次の RPC sequence を実行します。
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>`、`pszModuleName = DIALER.EXE`（または per-user priority list の別の top entry）に設定します。
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`、`bEnable = 1`（line app を登録し、highest priority recipient を再計算）。
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` を強制し、async event を生成します。
- `GetAsyncEvents` (`Req_Func 0`): write を dequeue/completion します。
- `LRegisterRequestRecipient` を再度実行し、`bEnable = 0`（unregister）。
- `Shutdown` (`Req_Func 86`) で line app を tear down します。
- Priority control: “highest priority” recipient は、`pszModuleName` と `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` の内容を比較して選択されます（client を impersonating して読み取られます）。必要に応じて、`LSetAppPriority` (`Req_Func 69`) で module name を追加します。
- `OPEN_EXISTING` が使用されるため、file は**あらかじめ存在している必要があります**。`NETWORK SERVICE` が書き込み可能な一般的な候補: `C:\Windows\System32\catroot2\dberr.txt`、`C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`、`...\MpSigStub.log`。<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Telephony “admin” を自分に付与**: `C:\Windows\TAPI\tsec.ini` を対象にし、上記の 4-byte writes を使用して `[TapiAdministrators]\r\n<DOMAIN\\user>=1` を append します。新しい session（`ClientAttach`）を開始すると、service が INI を再読み込みし、アカウントに対して `ptClient->dwFlags |= 9` を設定します。
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` として `GetUIDllName` を送信し、`dwProviderFilenameOffset` 経由で path を指定します。admins の場合、service は `LoadLibrary(path)` を実行し、続いて export `TSPI_providerUIIdentify` を呼び出します。
- 実際の Windows SMB share への UNC paths で動作します。一部の attacker SMB servers は `ERROR_SMB_GUEST_LOGON_BLOCKED` で失敗します。
- Alternative: 同じ 4-byte write primitive を使って local DLL を時間をかけて drop し、その後 load します。
3. **Payload**: export は `NETWORK SERVICE` として実行されます。最小限の DLL は `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` を実行し、non-zero value（例: `0x1337`）を return できます。これにより service が DLL を unload し、execution を確認できます。<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- CVE-2026-20931 に対する Microsoft security update を install します。さらに、必要がない限り TAPI server mode を disable し、`\pipe\tapsrv` への remote access を block します。
- client-supplied paths を開く前に mailslot namespace validation（`\\*\MAILSLOT\`）を強制します。
- `C:\Windows\TAPI\tsec.ini` の ACLs を lock down し、変更を monitor します。non-default paths を load する `GetUIDllName` calls に対して alert を発生させます。<sup>[[1]](#references)</sup>

## References

- [1] [Windows Telephony Service における RCE の Exploiting（CVE-2026-20931）](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
