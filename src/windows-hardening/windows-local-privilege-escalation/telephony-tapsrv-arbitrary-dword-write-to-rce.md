# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony 서비스(TapiSrv, `tapisrv.dll`)가 **TAPI server**로 구성되면 인증된 SMB 클라이언트에 **`\pipe\tapsrv` named pipe를 통한 `tapsrv` MSRPC interface**를 노출합니다. 비동기 이벤트 전달의 CVE-2026-20931을 이용하면 공격자는 메일슬롯 handle로 추정되는 값을 **`NETWORK SERVICE`가 쓰기 가능한 기존 파일에 대한 제어된 4바이트 쓰기**로 전환할 수 있습니다. 공개된 chain은 Telephony administrator 목록을 덮어쓴 다음, administrator 전용 DLL load에 도달하여 `NETWORK SERVICE` 권한으로 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **활성화된 경우에만 원격 노출**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing`가 sharing을 허용해야 합니다(또는 `TapiMgmt.msc` / `tcmsetup /c <server>`를 통해 구성). 기본적으로 `tapsrv`는 local-only입니다.
- Interface: **SMB named pipe**를 통한 MS-TRP (`tapsrv`)이므로 공격자에게 유효한 SMB auth가 필요합니다.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)`는 async event delivery를 초기화합니다. pull mode에서 service는 다음을 실행합니다.
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser`가 mailslot path (`\\*\MAILSLOT\...`)인지 검증하지 않습니다. `NETWORK SERVICE`가 쓸 수 있는 **기존 filesystem path**는 무엇이든 허용됩니다.
- 각 async event write는 열린 handle에 단일 **`DWORD` = `InitContext`**(이후 `Initialize` request에서 공격자가 제어)를 저장하여 **write-what/write-where (4 bytes)**를 제공합니다.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Target file 열기**: `pszDomainUser = <existing writable path>`(예: `C:\Windows\TAPI\tsec.ini`)로 `ClientAttach`를 호출합니다.
2. 작성할 각 `DWORD`에 대해 `ClientRequest`에서 다음 RPC sequence를 실행합니다.
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>`를 설정하고 `pszModuleName = DIALER.EXE`(또는 per-user priority list의 다른 top entry)로 지정합니다.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1`로 설정합니다(line app을 등록하고 highest priority recipient를 다시 계산).
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient`를 강제로 실행하여 async event를 생성합니다.
- `GetAsyncEvents` (`Req_Func 0`): write를 dequeue/completion합니다.
- 다시 `LRegisterRequestRecipient`를 `bEnable = 0`으로 실행합니다(unregister).
- `Shutdown` (`Req_Func 86`)으로 line app을 정리합니다.
- Priority control: “highest priority” recipient는 `pszModuleName`을 `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall`과 비교하여 선택됩니다(클라이언트를 impersonating하는 동안 읽음). 필요한 경우 `LSetAppPriority` (`Req_Func 69`)를 통해 module name을 삽입합니다.
- `OPEN_EXISTING`이 사용되므로 파일이 **이미 존재해야 합니다**. 일반적인 `NETWORK SERVICE` writable candidate는 `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`입니다.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **자신에게 Telephony “admin” 권한 부여**: `C:\Windows\TAPI\tsec.ini`를 대상으로 위의 4-byte writes를 사용해 `[TapiAdministrators]\r\n<DOMAIN\\user>=1`을 append합니다. 새 session(`ClientAttach`)을 시작하면 service가 INI를 다시 읽고 해당 account에 대해 `ptClient->dwFlags |= 9`를 설정합니다.
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID`로 `GetUIDllName`을 전송하고 `dwProviderFilenameOffset`를 통해 path를 제공합니다. admin의 경우 service는 `LoadLibrary(path)`를 실행한 뒤 export인 `TSPI_providerUIIdentify`를 호출합니다.
- 실제 Windows SMB share에 대한 UNC paths에서 작동하지만 일부 공격자 SMB server는 `ERROR_SMB_GUEST_LOGON_BLOCKED`로 실패합니다.
- Alternative: 동일한 4-byte write primitive를 사용해 local DLL을 천천히 drop한 다음 load합니다.
3. **Payload**: export는 `NETWORK SERVICE` 권한으로 실행됩니다. minimal DLL은 `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt`를 실행하고 non-zero value(예: `0x1337`)를 return하여 service가 DLL을 unload하도록 할 수 있으며, 이를 통해 execution을 확인합니다.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- CVE-2026-20931에 대한 Microsoft security update를 설치합니다. 별도로 필요하지 않은 경우 TAPI server mode를 disable하고 `\pipe\tapsrv`에 대한 remote access를 block합니다.
- client가 제공한 paths를 열기 전에 mailslot namespace validation(`\\*\MAILSLOT\`)을 적용합니다.
- `C:\Windows\TAPI\tsec.ini` ACLs를 제한하고 변경을 monitor합니다. non-default paths를 load하는 `GetUIDllName` calls에 alert를 설정합니다.<sup>[[1]](#references)</sup>

## References

- [1] [누가 통화 중인가? Windows Telephony Service의 RCE Exploiting (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
