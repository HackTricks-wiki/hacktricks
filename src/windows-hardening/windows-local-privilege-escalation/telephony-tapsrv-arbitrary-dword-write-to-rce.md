# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wanneer die Windows Telephony-diens (TapiSrv, `tapisrv.dll`) as ’n **TAPI-bediener** gekonfigureer is, stel dit die **`tapsrv` MSRPC-koppelvlak oor die `\pipe\tapsrv` named pipe** bloot aan geauthentiseerde SMB-kliënte. CVE-2026-20931 in asynchronous event delivery stel ’n aanvaller in staat om ’n sogenaamde mailslot-handle in ’n **beheerde 4-grepe-skrywing na ’n voorafbestaande lêer wat deur `NETWORK SERVICE` beskryfbaar is** te verander. Die gepubliseerde chain oorskryf die Telephony-administratelys, bereik daarna ’n administrator-only DLL load en voer kode as `NETWORK SERVICE` uit.<sup>[[1]](#references)[[2]](#references)</sup>

## Aanvaloppervlak

- **Remote exposure slegs wanneer enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` moet sharing toelaat (of via `TapiMgmt.msc` / `tcmsetup /c <server>` gekonfigureer word). By verstek is `tapsrv` local-only.
- Interface: MS-TRP (`tapsrv`) oor **SMB named pipe**, dus benodig die aanvaller geldige SMB-auth.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialiseer async event delivery. In pull mode doen die service:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sonder om te valideer dat `pszDomainUser` ’n mailslot path (`\\*\MAILSLOT\...`) is. Enige **bestaande filesystem path** wat deur `NETWORK SERVICE` beskryfbaar is, word aanvaar.
- Elke async event write stoor ’n enkele **`DWORD` = `InitContext`** (deur die aanvaller beheer in die daaropvolgende `Initialize` request) na die geopende handle, wat **write-what/write-where (4 bytes)** oplewer.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` met `pszDomainUser = <existing writable path>` (byvoorbeeld, `C:\Windows\TAPI\tsec.ini`).
2. Vir elke `DWORD` om te skryf, voer hierdie RPC sequence teen `ClientRequest` uit:
- `Initialize` (`Req_Func 47`): stel `InitContext = <4-byte value>` en `pszModuleName = DIALER.EXE` (of ’n ander top entry in die per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registreer die line app en herbereken die hoogste-priority recipient).
- `TRequestMakeCall` (`Req_Func 121`): forseer `NotifyHighestPriorityRequestRecipient`, wat die async event genereer.
- `GetAsyncEvents` (`Req_Func 0`): dequeue/voltooi die write.
- `LRegisterRequestRecipient` weer met `bEnable = 0` (unregister).
- `Shutdown` (`Req_Func 86`) om die line app af te breek.
- Priority control: die “highest priority”-recipient word gekies deur `pszModuleName` te vergelyk met `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (gelees terwyl daar as die client geimpersonate word). Indien nodig, voeg jou module name by via `LSetAppPriority` (`Req_Func 69`).
- Die lêer **moet reeds bestaan**, omdat `OPEN_EXISTING` gebruik word. Algemene `NETWORK SERVICE`-writable candidates: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: target `C:\Windows\TAPI\tsec.ini` en append `[TapiAdministrators]\r\n<DOMAIN\\user>=1` deur die 4-byte writes hierbo te gebruik. Begin ’n **nuwe** session (`ClientAttach`) sodat die service die INI herlees en `ptClient->dwFlags |= 9` vir jou account stel.
2. **Admin-only DLL load**: stuur `GetUIDllName` met `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` en verskaf ’n path via `dwProviderFilenameOffset`. Vir admins doen die service `LoadLibrary(path)` en roep dan die export `TSPI_providerUIIdentify`:
- Werk met UNC paths na ’n werklike Windows SMB share; sommige attacker SMB servers misluk met `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative: drop stadig ’n local DLL deur dieselfde 4-byte write primitive te gebruik, en laai dit dan.
3. **Payload**: die export voer uit onder `NETWORK SERVICE`. ’n Minimale DLL kan `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` uitvoer en ’n non-zero value (byvoorbeeld, `0x1337`) terugstuur sodat die service die DLL unload, wat execution bevestig.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Installeer die Microsoft security update vir CVE-2026-20931. Disable TAPI server mode onafhanklik daarvan, tensy dit vereis word, en blokkeer remote access na `\pipe\tapsrv`.
- Enforce mailslot namespace validation (`\\*\MAILSLOT\`) voordat client-supplied paths oopgemaak word.
- Lock down `C:\Windows\TAPI\tsec.ini` ACLs en monitor changes; alert op `GetUIDllName` calls wat non-default paths laai.<sup>[[1]](#references)</sup>

## References

- [1] [Wie is aan die lyn? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
