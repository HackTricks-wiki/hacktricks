# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Kada je Windows Telephony service (TapiSrv, `tapisrv.dll`) konfigurisan kao **TAPI server**, izlaže **`tapsrv` MSRPC interfejs preko `\pipe\tapsrv` named pipe** autentifikovanim SMB klijentima. Dizajnerska greška u asinhronoj isporuci događaja za udaljene klijente omogućava napadaču da pretvori mailslot handle u **kontrolisani 4-bajtni zapis u bilo koji postojeći fajl koji je upisiv od strane `NETWORK SERVICE`**. Taj primitiv se može povezati da pregazi Telephony admin listu i zloupotrebi **admin-only arbitrary DLL load** za izvršavanje koda kao `NETWORK SERVICE`.

## Attack Surface
- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` mora dozvoliti deljenje (ili biti konfigurisan putem `TapiMgmt.msc` / `tcmsetup /c <server>`). Po defaultu `tapsrv` je samo lokalni.
- Interface: MS-TRP (`tapsrv`) preko **SMB named pipe**, tako da napadač treba validnu SMB autentifikaciju.
- Service account: `NETWORK SERVICE` (manual start, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicijalizuje asinhronu isporuku događaja. U pull režimu, servis poziva:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bez validacije da li je `pszDomainUser` mailslot putanja (`\\*\MAILSLOT\...`). Bilo koja **postojeća putanja na fajl sistemu** upisiva od strane `NETWORK SERVICE` je prihvaćena.
- Svaki asinhroni zapis događaja snima jedan jedini **`DWORD` = `InitContext`** (kontrolisan od strane napadača u naknadnom `Initialize` zahtevu) u otvoreni handle, dajući **write-what/write-where (4 bytes)**.

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` sa `pszDomainUser = <existing writable path>` (npr. `C:\Windows\TAPI\tsec.ini`).
2. Za svaki `DWORD` koji treba upisati, izvrši sledeću RPC sekvencu protiv `ClientRequest`:
- `Initialize` (`Req_Func 47`): postavi `InitContext = <4-byte value>` i `pszModuleName = DIALER.EXE` (ili drugi top unos u per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registruje line app, ponovo izračunava highest priority recipient).
- `TRequestMakeCall` (`Req_Func 121`): forsira `NotifyHighestPriorityRequestRecipient`, generišući asinhroni događaj.
- `GetAsyncEvents` (`Req_Func 0`): dequeue/kompletira zapis.
- `LRegisterRequestRecipient` ponovo sa `bEnable = 0` (odregistruje).
- `Shutdown` (`Req_Func 86`) da sruši line app.
- Kontrola prioriteta: “highest priority” recipient se bira poređenjem `pszModuleName` protiv `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (čitano dok se impersonira klijent). Ako je potrebno, ubaci svoj module name putem `LSetAppPriority` (`Req_Func 69`).
- Fajl **mora već postojati** zato što se koristi `OPEN_EXISTING`. Uobičajeni kandidati upisivi od strane `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: ciljanje `C:\Windows\TAPI\tsec.ini` i dodavanje `[TapiAdministrators]\r\n<DOMAIN\\user>=1` koristeći gore navedene 4-bajtne zapise. Pokreni **novu** sesiju (`ClientAttach`) da servis ponovo učita INI i postavi `ptClient->dwFlags |= 9` za tvoj nalog.
2. **Admin-only DLL load**: pošalji `GetUIDllName` sa `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` i obezbedi putanju preko `dwProviderFilenameOffset`. Za admine, servis radi `LoadLibrary(path)` zatim poziva export `TSPI_providerUIIdentify`:
- Radi sa UNC putanjama ka realnom Windows SMB share-u; neki napadački SMB serveri ne uspevaju sa `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: polako ispusti lokalni DLL koristeći isti 4-bajtni primitiv, zatim ga učitaj.
3. **Payload**: export se izvršava pod `NETWORK SERVICE`. Minimalni DLL može pokrenuti `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` i vratiti nenultu vrednost (npr. `0x1337`) tako da servis unload-uje DLL, potvrđujući izvršenje.

## Hardening / Detection Notes
- Disable TAPI server mode osim ako nije neophodan; blokiraj udaljeni pristup `\pipe\tapsrv`.
- Sprovodi validaciju mailslot namespace (`\\*\MAILSLOT\`) pre nego što se otvore putanje koje šalje klijent.
- Zatvori ACL-e `C:\Windows\TAPI\tsec.ini` i prati izmene; alertuj na `GetUIDllName` pozive koji učitavaju nenormalne putanje.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
