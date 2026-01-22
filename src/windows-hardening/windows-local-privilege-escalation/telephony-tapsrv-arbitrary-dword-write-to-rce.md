# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

When the Windows Telephony service (TapiSrv, `tapisrv.dll`) is configured as a **TAPI server**, it exposes the **`tapsrv` MSRPC interface over the `\pipe\tapsrv` named pipe** to authenticated SMB clients. A design bug in the asynchronous event delivery for remote clients lets an attacker turn a mailslot handle into a **controlled 4-byte write to any pre-existing file writable by `NETWORK SERVICE`**. That primitive can be chained to overwrite the Telephony admin list and abuse an **admin-only arbitrary DLL load** to execute code as `NETWORK SERVICE`.

## 공격 표면
- **원격 노출은 활성화된 경우에만**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing`가 공유를 허용해야 함(또는 `TapiMgmt.msc` / `tcmsetup /c <server>`로 구성). 기본적으로 `tapsrv`는 로컬 전용임.
- 인터페이스: MS-TRP (`tapsrv`)가 **SMB named pipe**를 통해 제공되므로 공격자는 유효한 SMB 인증이 필요함.
- 서비스 계정: `NETWORK SERVICE` (수동 시작, 온디맨드).

## 원시 기능: Mailslot 경로 혼동 → 임의 DWORD 쓰기
- `ClientAttach(pszDomainUser, pszMachine, ...)`는 비동기 이벤트 전달을 초기화함. pull 모드에서 서비스는 다음을 수행:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser`가 mailslot 경로(`\\*\MAILSLOT\...`)인지 검증하지 않음. `NETWORK SERVICE`로 쓰기가 가능한 **기존 파일 시스템 경로**라면 모두 허용됨.
- 각 비동기 이벤트 쓰기는 열린 핸들에 공격자가 제어하는 단일 **`DWORD` = `InitContext`**(이후 `Initialize` 요청에서 제어 가능)를 저장하므로 **write-what/write-where (4 bytes)**가 발생함.

## 결정적 쓰기 강제 방법
1. **대상 파일 열기**: `ClientAttach`를 `pszDomainUser = <existing writable path>`(예: `C:\Windows\TAPI\tsec.ini`)로 호출.
2. 각 `DWORD`를 쓰려면 `ClientRequest`에 대해 다음 RPC 시퀀스를 실행:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>`와 `pszModuleName = DIALER.EXE`(또는 per-user priority 리스트의 상위 항목) 설정.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1`(라인 앱 등록, 최고 우선 수신자 재계산).
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient`를 강제하여 비동기 이벤트 생성.
- `GetAsyncEvents` (`Req_Func 0`): 큐에서 꺼내어/완료하여 쓰기 실행.
- 다시 `LRegisterRequestRecipient`를 `bEnable = 0`으로(등록 해제).
- `Shutdown` (`Req_Func 86`)으로 라인 앱 종료.
- 우선순위 제어: “highest priority” 수신자는 `pszModuleName`을 `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall`과 비교하여 선택(클라이언트로 위임(impersonate)한 상태에서 읽음). 필요시 `LSetAppPriority` (`Req_Func 69`)로 모듈 이름을 삽입.
- 파일은 `OPEN_EXISTING`을 사용하므로 **이미 존재해야 함**. `NETWORK SERVICE`로 쓰기가 가능한 일반 후보: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## DWORD 쓰기에서 TapiSrv 내부 RCE로
1. **자기 자신에게 Telephony “admin” 권한 부여**: `C:\Windows\TAPI\tsec.ini`를 목표로 하고 위의 4바이트 쓰기를 이용해 `[TapiAdministrators]\r\n<DOMAIN\\user>=1`을 추가. 서비스가 INI를 다시 읽고 계정에 대해 `ptClient->dwFlags |= 9`을 설정하도록 **새로운** 세션(`ClientAttach`)을 시작.
2. **관리자 전용 DLL 로드 오용**: `GetUIDllName`을 `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID`로 보내고 `dwProviderFilenameOffset`로 경로를 제공. 관리자라면 서비스는 `LoadLibrary(path)`를 호출한 뒤 내보낸 함수 `TSPI_providerUIIdentify`를 호출:
- UNC 경로로 실제 Windows SMB 공유를 가리키면 동작; 일부 공격자 SMB 서버는 `ERROR_SMB_GUEST_LOGON_BLOCKED`로 실패함.
- 대안: 동일한 4바이트 쓰기 원시 기능을 사용해 로컬에 DLL을 천천히 생성한 뒤 로드.
3. **페이로드**: 해당 export는 `NETWORK SERVICE` 권한으로 실행됨. 최소한의 DLL은 `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt`를 실행하고 서비스가 DLL을 언로드하도록 비영(非0) 값을 반환(예: `0x1337`)하면 실행 확인 가능.

## 하드닝 / 탐지 메모
- 필요하지 않다면 TAPI server 모드를 비활성화; `\pipe\tapsrv`에 대한 원격 접근 차단.
- 클라이언트가 제공한 경로를 열기 전에 mailslot 네임스페이스 검증(`\\*\MAILSLOT\`)을 적용.
- `C:\Windows\TAPI\tsec.ini` ACL을 잠그고 변경을 모니터링; 기본 경로가 아닌 경로로 로드하는 `GetUIDllName` 호출에 대해 경고.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
