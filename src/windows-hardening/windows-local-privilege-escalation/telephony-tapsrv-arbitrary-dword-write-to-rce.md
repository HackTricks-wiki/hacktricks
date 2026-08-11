# Telephony tapsrv Arbitrary DWORD Write to RCE（TAPI Server Mode）

{{#include ../../banners/hacktricks-training.md}}

当 Windows Telephony 服务（TapiSrv，`tapisrv.dll`）配置为 **TAPI server** 时，会通过 **`\pipe\tapsrv` named pipe** 向经过身份验证的 SMB 客户端暴露 **`tapsrv` MSRPC interface**。异步事件传递中的 CVE-2026-20931 允许攻击者将一个声称为 mailslot 的句柄转换为**向 `NETWORK SERVICE` 可写的现有文件执行受控的 4 字节写入**。已公开的攻击链会覆盖 Telephony administrator 列表，随后触发仅管理员可执行的 DLL load，并以 `NETWORK SERVICE` 身份执行。<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **仅在启用时远程暴露**：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` 必须允许 sharing（或通过 `TapiMgmt.msc` / `tcmsetup /c <server>` 配置）。默认情况下，`tapsrv` 仅限本地访问。
- Interface：通过 **SMB named pipe** 提供的 MS-TRP（`tapsrv`），因此攻击者需要有效的 SMB 身份验证。
- Service account：`NETWORK SERVICE`（manual start，按需启动）。<sup>[[1]](#references)</sup>

## Primitive：Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` 初始化异步事件传递。在 pull mode 中，服务执行：
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
但不会验证 `pszDomainUser` 是否为 mailslot path（`\\*\MAILSLOT\...`）。任何由 `NETWORK SERVICE` 可写的**现有文件系统路径**都会被接受。
- 每次异步事件写入都会将单个 **`DWORD` = `InitContext`**（攻击者在后续 `Initialize` request 中控制）写入已打开的句柄，从而实现 **write-what/write-where（4 字节）**。<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**：使用 `pszDomainUser = <existing writable path>` 调用 `ClientAttach`（例如 `C:\Windows\TAPI\tsec.ini`）。
2. 对于每个要写入的 `DWORD`，针对 `ClientRequest` 执行以下 RPC sequence：
- `Initialize`（`Req_Func 47`）：设置 `InitContext = <4-byte value>`，并将 `pszModuleName = DIALER.EXE`（或 per-user priority list 中的其他顶部条目）。
- `LRegisterRequestRecipient`（`Req_Func 61`）：设置 `dwRequestMode = LINEREQUESTMODE_MAKECALL`、`bEnable = 1`（注册 line app，并重新计算最高优先级 recipient）。
- `TRequestMakeCall`（`Req_Func 121`）：强制执行 `NotifyHighestPriorityRequestRecipient`，生成异步事件。
- `GetAsyncEvents`（`Req_Func 0`）：出队并完成写入。
- 再次调用 `LRegisterRequestRecipient`，将 `bEnable = 0`（取消注册）。
- `Shutdown`（`Req_Func 86`）：拆除 line app。
- Priority control：通过将 `pszModuleName` 与 `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` 进行比较来选择“highest priority” recipient（读取时会 impersonate client）。如果需要，可通过 `LSetAppPriority`（`Req_Func 69`）插入你的 module name。
- 文件**必须已经存在**，因为使用了 `OPEN_EXISTING`。常见的 `NETWORK SERVICE` 可写候选文件包括：`C:\Windows\System32\catroot2\dberr.txt`、`C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`、`...\MpSigStub.log`。<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **授予自己 Telephony “admin” 权限**：将 `C:\Windows\TAPI\tsec.ini` 作为目标，并使用上述 4 字节写入追加 `[TapiAdministrators]\r\n<DOMAIN\\user>=1`。启动一个新的 session（`ClientAttach`），使服务重新读取 INI，并为你的账户设置 `ptClient->dwFlags |= 9`。
2. **Admin-only DLL load**：发送 `GetUIDllName`，设置 `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID`，并通过 `dwProviderFilenameOffset` 提供路径。对于 admins，服务会执行 `LoadLibrary(path)`，然后调用 export `TSPI_providerUIIdentify`：
- 可使用指向真实 Windows SMB share 的 UNC paths；某些 attacker SMB servers 会失败并返回 `ERROR_SMB_GUEST_LOGON_BLOCKED`。
- Alternative：使用相同的 4-byte write primitive，缓慢写入一个 local DLL，然后加载它。
3. **Payload**：该 export 会在 `NETWORK SERVICE` 身份下执行。最小 DLL 可以运行 `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt`，并返回非零值（例如 `0x1337`），使服务卸载 DLL，从而确认执行成功。<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- 安装针对 CVE-2026-20931 的 Microsoft security update。除非确有需要，否则应独立禁用 TAPI server mode，并阻止对 `\pipe\tapsrv` 的远程访问。
- 在打开客户端提供的路径前，强制执行 mailslot namespace validation（`\\*\MAILSLOT\`）。
- 收紧 `C:\Windows\TAPI\tsec.ini` 的 ACL，并监控其变更；对 `GetUIDllName` 加载非默认路径的调用生成 alert。<sup>[[1]](#references)</sup>

## References

- [1] [谁在线路上？利用 Windows Telephony Service 中的 RCE（CVE-2026-20931）](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
