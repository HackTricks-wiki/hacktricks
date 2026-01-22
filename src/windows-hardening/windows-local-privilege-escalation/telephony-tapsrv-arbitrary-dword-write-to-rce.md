# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wanneer die Windows Telephony service (TapiSrv, `tapisrv.dll`) gekonfigureer is as 'n **TAPI server**, openbaar dit die **`tapsrv` MSRPC interface oor die `\pipe\tapsrv` named pipe** aan geverifieerde SMB-kliente. 'n Ontwerpfout in die asynchrone gebeurtenisaflewering vir remote kliente laat 'n aanvaller toe om 'n mailslot-handle te omskep in 'n **beheerde 4-byte skrywing na enige reeds-bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word**. Daardie primitief kan gekoppel word om die Telephony adminlys oor te skryf en 'n **slegs-admin arbitrary DLL load** te misbruik om kode as `NETWORK SERVICE` uit te voer.

## Aanvalsoppervlakte
- **Remote blootstelling slegs wanneer geaktiveer**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` moet sharing toelaat (of gekonfigureer via `TapiMgmt.msc` / `tcmsetup /c <server>`). Standaard is `tapsrv` plaaslik-alleen.
- Interface: MS-TRP (`tapsrv`) oor **SMB named pipe**, so die aanvaller benodig geldige SMB-auth.
- Service account: `NETWORK SERVICE` (manual start, on-demand).

## Primitief: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialiseer asynchrone gebeurtenisaflewering. In pull-modus doen die service:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sonder om te valideer dat `pszDomainUser` 'n mailslot-pad is (`\\*\MAILSLOT\...`). Enige **bestaande filesystem-pad** wat deur `NETWORK SERVICE` geskryf kan word, word aanvaar.
- Elke asynchrone gebeurtenisskrywing stoor 'n enkele **`DWORD` = `InitContext`** (deur die aanvaller beheer in die daaropvolgende `Initialize` versoek) na die geopende handle, wat 'n **write-what/write-where (4 bytes)** gee.

## Forcering van Deterministiese Skrywings
1. **Open teikengileer**: `ClientAttach` met `pszDomainUser = <existing writable path>` (bv. `C:\Windows\TAPI\tsec.ini`).
2. Vir elke `DWORD` om te skryf, voer hierdie RPC-volgorde uit teen `ClientRequest`:
- `Initialize` (`Req_Func 47`): stel `InitContext = <4-byte value>` en `pszModuleName = DIALER.EXE` (of 'n ander boonste inskrywing in die per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registreer die line app, herbereken hoogste prioriteitsontvanger).
- `TRequestMakeCall` (`Req_Func 121`): dwing `NotifyHighestPriorityRequestRecipient`, wat die asynchrone gebeurtenis genereer.
- `GetAsyncEvents` (`Req_Func 0`): ontknoop/voltooi die skrywing.
- `LRegisterRequestRecipient` weer met `bEnable = 0` (ontregistreer).
- `Shutdown` (`Req_Func 86`) om die line app af te breek.
- Prioriteitsbeheer: die "hoogste prioriteit" ontvanger word gekies deur `pszModuleName` te vergelyk teen `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (gelees terwyl geïmpersonifieer as die klient). Indien nodig, voeg jou module-naam by via `LSetAppPriority` (`Req_Func 69`).
- Die lêer **moet reeds bestaan** omdat `OPEN_EXISTING` gebruik word. Algemene `NETWORK SERVICE`-skryfbare kandidaten: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Gee jouself Telephony “admin”**: teiken `C:\Windows\TAPI\tsec.ini` en voeg `[TapiAdministrators]\r\n<DOMAIN\\user>=1` by deur die 4-byte skrywings hierbo. Begin 'n **nuwe** sessie (`ClientAttach`) sodat die service die INI herlees en `ptClient->dwFlags |= 9` vir jou rekening stel.
2. **Admin-only DLL load**: stuur `GetUIDllName` met `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` en voorsien 'n pad via `dwProviderFilenameOffset`. Vir admins doen die service `LoadLibrary(path)` en roep dan die export `TSPI_providerUIIdentify` aan:
- Werk met UNC-paaie na 'n regte Windows SMB share; sommige kwaadwillige SMB-bedieners faal met `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternatief: drop stadig 'n plaaslike DLL met dieselfde 4-byte skrywingprimitief, en laai dit dan.
3. **Payload**: die export word uitgevoer onder `NETWORK SERVICE`. 'n Minimale DLL kan `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` uitvoer en 'n nie-nul waarde teruggee (bv. `0x1337`) sodat die service die DLL unload, wat uitvoering bevestig.

## Verharding / Opsporingsnotas
- Deaktiveer TAPI server-modus tensy dit nodig is; blokkeer remote toegang tot `\pipe\tapsrv`.
- Handhaaf mailslot namespace validasie (`\\*\MAILSLOT\`) voordat client-verskafte paaie oopgemaak word.
- Hardlock `C:\Windows\TAPI\tsec.ini` ACLs en monitor veranderings; waarschuw vir `GetUIDllName` oproepe wat nie-standaard paaie laai.

## Verwysings
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
