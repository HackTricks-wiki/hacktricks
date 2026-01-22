# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

When the Windows Telephony service (TapiSrv, `tapisrv.dll`) is configured as a **TAPI server**, it exposes the **`tapsrv` MSRPC interface over the `\pipe\tapsrv` named pipe** to authenticated SMB clients. A design bug in the asynchronous event delivery for remote clients lets an attacker turn a mailslot handle into a **controlled 4-byte write to any pre-existing file writable by `NETWORK SERVICE`**. That primitive can be chained to overwrite the Telephony admin list and abuse an **admin-only arbitrary DLL load** to execute code as `NETWORK SERVICE`.

## Attack Surface
- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` must allow sharing (or configured via `TapiMgmt.msc` / `tcmsetup /c <server>`). By default `tapsrv` is local-only.
- Interface: MS-TRP (`tapsrv`) over **SMB named pipe**, so the attacker needs valid SMB auth.
- Service account: `NETWORK SERVICE` (manual start, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initializes async event delivery. In pull mode, the service does:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
without validating that `pszDomainUser` is a mailslot path (`\\*\MAILSLOT\...`). Any **existing filesystem path** writable by `NETWORK SERVICE` is accepted.
- Every async event write stores a single **`DWORD` = `InitContext`** (attacker-controlled in the subsequent `Initialize` request) to the opened handle, yielding **write-what/write-where (4 bytes)**.

## Wymuszanie deterministycznych zapisów
1. **Otwórz plik docelowy**: `ClientAttach` with `pszDomainUser = <existing writable path>` (e.g., `C:\Windows\TAPI\tsec.ini`).
2. For each `DWORD` to write, execute this RPC sequence against `ClientRequest`:
- `Initialize` (`Req_Func 47`): ustaw `InitContext = <4-byte value>` oraz `pszModuleName = DIALER.EXE` (lub inny wpis najwyższego priorytetu w per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (rejestruje aplikację linii, przelicza odbiorcę o najwyższym priorytecie).
- `TRequestMakeCall` (`Req_Func 121`): wymusza `NotifyHighestPriorityRequestRecipient`, generując zdarzenie asynchroniczne.
- `GetAsyncEvents` (`Req_Func 0`): zdejmuje z kolejki/kończy zapis.
- `LRegisterRequestRecipient` ponownie z `bEnable = 0` (wyrejestrowuje).
- `Shutdown` (`Req_Func 86`) aby zakończyć aplikację linii.
- Kontrola priorytetu: „odbiorca o najwyższym priorytecie” jest wybierany przez porównanie `pszModuleName` z `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (odczytywane podczas impersonacji klienta). W razie potrzeby wstaw swoją nazwę modułu za pomocą `LSetAppPriority` (`Req_Func 69`).
- Plik **musi już istnieć**, ponieważ używane jest `OPEN_EXISTING`. Typowe kandydaty zapisywalne przez `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: target `C:\Windows\TAPI\tsec.ini` and append `[TapiAdministrators]\r\n<DOMAIN\\user>=1` using the 4-byte writes above. Start a **new** session (`ClientAttach`) so the service re-reads the INI and sets `ptClient->dwFlags |= 9` for your account.
2. **Admin-only DLL load**: send `GetUIDllName` with `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` and supply a path via `dwProviderFilenameOffset`. For admins, the service does `LoadLibrary(path)` then calls the export `TSPI_providerUIIdentify`:
- Works with UNC paths to a real Windows SMB share; some attacker SMB servers fail with `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative: slowly drop a local DLL using the same 4-byte write primitive, then load it.
3. **Payload**: the export executes under `NETWORK SERVICE`. A minimal DLL can run `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` and return a non-zero value (e.g., `0x1337`) so the service unloads the DLL, confirming execution.

## Zalecenia dotyczące zabezpieczeń i wykrywania
- Wyłącz TAPI server mode, jeśli nie jest wymagany; zablokuj zdalny dostęp do `\pipe\tapsrv`.
- Wymuszaj walidację przestrzeni nazw mailslot (`\\*\MAILSLOT\`) przed otwarciem ścieżek dostarczonych przez klienta.
- Zablokuj ACL dla `C:\Windows\TAPI\tsec.ini` i monitoruj zmiany; generuj alerty przy wywołaniach `GetUIDllName` ładujących nietypowe ścieżki.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
