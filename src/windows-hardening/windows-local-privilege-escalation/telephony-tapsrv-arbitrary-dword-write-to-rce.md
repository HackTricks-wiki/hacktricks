# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wanneer die Windows Telephony-diens (TapiSrv, `tapisrv.dll`) as ’n **TAPI server** gekonfigureer is, stel dit die **`tapsrv` MSRPC-interface oor die `\pipe\tapsrv` named pipe** aan geauthentiseerde SMB-clients bloot. ’n Ontwerpfout in die asinchroniese gebeurtenisaflewering vir afgeleë clients laat ’n aanvaller toe om ’n mailslot-handle te verander in ’n **beheerde 4-grepe-skrywing na enige bestaande lêer wat deur `NETWORK SERVICE` beskryfbaar is**. Hierdie primitive kan gekombineer word om die Telephony-adminlys te oorskryf en ’n **admin-only arbitrary DLL load** te misbruik om kode as `NETWORK SERVICE` uit te voer.<sup>[[1]](#references)</sup>

## Aanvalsoppervlak

- **Afgeleë blootstelling slegs wanneer dit geaktiveer is**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` moet sharing toelaat (of via `TapiMgmt.msc` / `tcmsetup /c <server>` gekonfigureer word). By verstek is `tapsrv` slegs plaaslik beskikbaar.
- Interface: MS-TRP (`tapsrv`) oor **SMB named pipe**, dus benodig die aanvaller geldige SMB-auth.
- Diensrekening: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialiseer asinchroniese gebeurtenisaflewering. In pull mode doen die diens:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sonder om te valideer dat `pszDomainUser` ’n mailslot-pad (`\\*\MAILSLOT\...`) is. Enige **bestaande lêerstelselpad** wat deur `NETWORK SERVICE` beskryfbaar is, word aanvaar.
- Elke asinchroniese gebeurtenisskrywing stoor ’n enkele **`DWORD` = `InitContext`** (wat die aanvaller in die daaropvolgende `Initialize`-versoek beheer) na die oopgemaakte handle, wat **write-what/write-where (4 bytes)** lewer.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` met `pszDomainUser = <existing writable path>` (byvoorbeeld `C:\Windows\TAPI\tsec.ini`).
2. Vir elke `DWORD` wat geskryf moet word, voer hierdie RPC-volgorde teen `ClientRequest` uit:
- `Initialize` (`Req_Func 47`): stel `InitContext = <4-byte value>` en `pszModuleName = DIALER.EXE` (of ’n ander top entry in die per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registreer die line app en bereken die hoogste-prioriteit-ontvanger opnuut).
- `TRequestMakeCall` (`Req_Func 121`): forseer `NotifyHighestPriorityRequestRecipient`, wat die asinchroniese gebeurtenis genereer.
- `GetAsyncEvents` (`Req_Func 0`): haal die gebeurtenis uit die tou en voltooi die skrywing.
- `LRegisterRequestRecipient` weer met `bEnable = 0` (unregister).
- `Shutdown` (`Req_Func 86`) om die line app af te breek.
- Priority control: die “highest priority”-ontvanger word gekies deur `pszModuleName` te vergelyk met `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (gelees terwyl die client nageboots word). Indien nodig, voeg jou modulenaam via `LSetAppPriority` (`Req_Func 69`) in.
- Die lêer **moet reeds bestaan** omdat `OPEN_EXISTING` gebruik word. Algemene kandidate wat deur `NETWORK SERVICE` beskryfbaar is: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: teiken `C:\Windows\TAPI\tsec.ini` en voeg `[TapiAdministrators]\r\n<DOMAIN\\user>=1` by deur die bogenoemde 4-grepe-skrywings te gebruik. Begin ’n **new** session (`ClientAttach`) sodat die diens die INI weer lees en `ptClient->dwFlags |= 9` vir jou rekening stel.
2. **Admin-only DLL load**: stuur `GetUIDllName` met `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` en verskaf ’n pad via `dwProviderFilenameOffset`. Vir admins doen die diens `LoadLibrary(path)` en roep dan die export `TSPI_providerUIIdentify` aan:
- Werk met UNC-paaie na ’n werklike Windows SMB share; sommige attacker SMB servers misluk met `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternatief: laat ’n plaaslike DLL stadig val deur dieselfde 4-grepe-skryfprimitive te gebruik, en laai dit dan.
3. **Payload**: die export word onder `NETWORK SERVICE` uitgevoer. ’n Minimale DLL kan `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` uitvoer en ’n nie-nulwaarde (byvoorbeeld `0x1337`) terugstuur sodat die diens die DLL unload, wat uitvoering bevestig.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Deaktiveer TAPI server mode tensy dit benodig word; blokkeer afgeleë toegang tot `\pipe\tapsrv`.
- Dwing mailslot-namespace-validasie (`\\*\MAILSLOT\`) af voordat paaie wat deur die client verskaf word, oopgemaak word.
- Beperk die ACLs van `C:\Windows\TAPI\tsec.ini` en monitor veranderinge; genereer alerts vir `GetUIDllName`-calls wat nie-verstekpaaie laai.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
