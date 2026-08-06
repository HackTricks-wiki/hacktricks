# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Kada je Windows Telephony servis (TapiSrv, `tapisrv.dll`) konfigurisan kao **TAPI server**, on izlaže **`tapsrv` MSRPC interfejs preko `\pipe\tapsrv` named pipe-a** autentifikovanim SMB klijentima. Greška u dizajnu asinhrone isporuke događaja za udaljene klijente omogućava napadaču da pretvori mailslot handle u **kontrolisani upis od 4 bajta u bilo koji postojeći fajl u koji `NETWORK SERVICE` može da upisuje**. Ovaj primitive može da se iskoristi za prepisivanje admin liste Telephony servisa i zloupotrebu **arbitrary DLL load funkcionalnosti dostupne samo admin korisnicima**, čime se izvršava kod kao `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Attack Surface

- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` mora dozvoljavati deljenje (ili biti konfigurisan preko `TapiMgmt.msc` / `tcmsetup /c <server>`). Podrazumevano je `tapsrv` dostupan samo lokalno.
- Interfejs: MS-TRP (`tapsrv`) preko **SMB named pipe-a**, tako da napadaču treba validna SMB autentifikacija.
- Nalog servisa: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicijalizuje asinhronu isporuku događaja. U pull režimu servis izvršava:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bez provere da li je `pszDomainUser` putanja do mailslot-a (`\\*\MAILSLOT\...`). Prihvata se bilo koja **postojeća putanja u filesystemu** u koju `NETWORK SERVICE` može da upisuje.
- Svaki upis asinhronog događaja skladišti jedan **`DWORD` = `InitContext`** (koji napadač kontroliše u narednom `Initialize` request-u) u otvoreni handle, čime se dobija **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: Pozvati `ClientAttach` sa `pszDomainUser = <existing writable path>` (npr. `C:\Windows\TAPI\tsec.ini`).
2. Za svaki `DWORD` koji treba upisati, izvršiti sledeću RPC sekvencu prema `ClientRequest`:
- `Initialize` (`Req_Func 47`): postaviti `InitContext = <4-byte value>` i `pszModuleName = DIALER.EXE` (ili drugi modul sa vrha per-user priority liste).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registruje line app i ponovo izračunava recipient sa najvišim prioritetom).
- `TRequestMakeCall` (`Req_Func 121`): forsira `NotifyHighestPriorityRequestRecipient`, čime se generiše asinhroni događaj.
- `GetAsyncEvents` (`Req_Func 0`): preuzima/završava upis.
- Ponovo pozvati `LRegisterRequestRecipient` sa `bEnable = 0` (unregister).
- `Shutdown` (`Req_Func 86`) za uklanjanje line app-a.
- Kontrola prioriteta: recipient sa “najvišim prioritetom” bira se poređenjem `pszModuleName` sa `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (čita se uz impersonation klijenta). Ako je potrebno, naziv modula se može dodati pomoću `LSetAppPriority` (`Req_Func 69`).
- Fajl **mora već da postoji** zato što se koristi `OPEN_EXISTING`. Uobičajeni kandidati u koje `NETWORK SERVICE` može da upisuje su: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: ciljati `C:\Windows\TAPI\tsec.ini` i dodati `[TapiAdministrators]\r\n<DOMAIN\\user>=1` pomoću prethodno opisanih upisa od 4 bajta. Zatim pokrenuti novu sesiju (`ClientAttach`), kako bi servis ponovo učitao INI i postavio `ptClient->dwFlags |= 9` za vaš nalog.
2. **Admin-only DLL load**: poslati `GetUIDllName` sa `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` i proslediti putanju preko `dwProviderFilenameOffset`. Za admin korisnike servis izvršava `LoadLibrary(path)`, a zatim poziva export `TSPI_providerUIIdentify`:
- Funkcioniše sa UNC putanjama do stvarnog Windows SMB share-a; neki attacker SMB serveri ne uspevaju zbog `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: polako drop-ovati lokalni DLL pomoću istog 4-byte write primitive-a, a zatim ga učitati.
3. **Payload**: export se izvršava pod nalogom `NETWORK SERVICE`. Minimalni DLL može da pokrene `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` i vrati vrednost različitu od nule (npr. `0x1337`), kako bi servis unload-ovao DLL i potvrdio izvršavanje.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Onemogućiti TAPI server mode osim ako je potreban; blokirati remote access do `\pipe\tapsrv`.
- Uvesti proveru mailslot namespace-a (`\\*\MAILSLOT\`) pre otvaranja putanja koje prosleđuje klijent.
- Ograničiti ACL-ove za `C:\Windows\TAPI\tsec.ini` i pratiti izmene; generisati alert za `GetUIDllName` pozive koji učitavaju putanje koje nisu podrazumevane.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
