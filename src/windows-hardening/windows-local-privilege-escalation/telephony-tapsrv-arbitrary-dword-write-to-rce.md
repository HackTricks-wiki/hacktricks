# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Kada je Windows Telephony servis (TapiSrv, `tapisrv.dll`) konfigurisan kao **TAPI server**, on izlaže **`tapsrv` MSRPC interfejs preko `\pipe\tapsrv` named pipe-a** autentifikovanim SMB klijentima. CVE-2026-20931 u asinhronoj isporuci događaja omogućava napadaču da pretvori navodni mailslot handle u **kontrolisani upis od 4 bajta u postojeći fajl u koji `NETWORK SERVICE` može da upisuje**. Objavljeni chain prepisuje listu Telephony administratora, zatim dolazi do učitavanja DLL-a koje je dostupno samo administratorima i izvršava kod kao `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Površina napada

- **Remote exposure samo kada je omogućeno**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` mora da dozvoli deljenje (ili se podešava preko `TapiMgmt.msc` / `tcmsetup /c <server>`). Podrazumevano je `tapsrv` dostupan samo lokalno.
- Interfejs: MS-TRP (`tapsrv`) preko **SMB named pipe-a**, tako da je napadaču potrebna validna SMB autentikacija.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicijalizuje asinhronu isporuku događaja. U pull modu servis izvršava:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bez provere da je `pszDomainUser` putanja do mailslot-a (`\\*\MAILSLOT\...`). Prihvata se bilo koja **postojeća putanja u filesystemu** u koju `NETWORK SERVICE` može da upisuje.
- Svaki asinhroni upis skladišti jedan **`DWORD` = `InitContext`** (koji napadač kontroliše u narednom `Initialize` zahtevu) u otvoreni handle, čime se dobija **write-what/write-where (4 bajta)**.<sup>[[1]](#references)</sup>

## Forsiranje determinističkih upisa
1. **Otvorite ciljni fajl**: `ClientAttach` sa `pszDomainUser = <existing writable path>` (npr. `C:\Windows\TAPI\tsec.ini`).
2. Za svaki `DWORD` koji treba upisati, izvršite sledeću RPC sekvencu prema `ClientRequest`:
- `Initialize` (`Req_Func 47`): postavite `InitContext = <4-byte value>` i `pszModuleName = DIALER.EXE` (ili drugi modul sa vrha per-user priority liste).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registruje line app i ponovo izračunava recipient-a sa najvišim prioritetom).
- `TRequestMakeCall` (`Req_Func 121`): prisiljava `NotifyHighestPriorityRequestRecipient`, generišući asinhroni događaj.
- `GetAsyncEvents` (`Req_Func 0`): preuzima/završava upis.
- Ponovo `LRegisterRequestRecipient` sa `bEnable = 0` (odjavljuje registraciju).
- `Shutdown` (`Req_Func 86`) za uklanjanje line app-a.
- Kontrola prioriteta: recipient sa „najvišim prioritetom“ bira se poređenjem `pszModuleName` sa `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (koji se čita uz impersonation klijenta). Ako je potrebno, ubacite naziv svog modula pomoću `LSetAppPriority` (`Req_Func 69`).
- Fajl **mora već da postoji** jer se koristi `OPEN_EXISTING`. Česti kandidati u koje `NETWORK SERVICE` može da upisuje: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Od DWORD Write do RCE unutar TapiSrv
1. **Dodelite sebi Telephony „admin“ privilegiju**: ciljajte `C:\Windows\TAPI\tsec.ini` i dodajte `[TapiAdministrators]\r\n<DOMAIN\\user>=1` pomoću prethodno opisanih upisa od 4 bajta. Započnite **novu** sesiju (`ClientAttach`) kako bi servis ponovo pročitao INI i postavio `ptClient->dwFlags |= 9` za vaš nalog.
2. **DLL load dostupan samo administratorima**: pošaljite `GetUIDllName` sa `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` i navedite putanju preko `dwProviderFilenameOffset`. Za administratore servis izvršava `LoadLibrary(path)`, a zatim poziva export `TSPI_providerUIIdentify`:
- Radi sa UNC putanjama ka stvarnom Windows SMB share-u; neki attacker SMB serveri ne uspevaju sa greškom `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: polako kreirajte lokalni DLL pomoću istog 4-byte write primitive-a, a zatim ga učitajte.
3. **Payload**: export se izvršava pod nalogom `NETWORK SERVICE`. Minimalni DLL može da pokrene `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` i vrati vrednost različitu od nule (npr. `0x1337`), kako bi servis unload-ovao DLL i potvrdio izvršavanje.<sup>[[1]](#references)</sup>

## Napomene o hardeningu / detekciji
- Instalirajte Microsoft security update za CVE-2026-20931. Nezavisno od toga, onemogućite TAPI server mode osim ako je potreban i blokirajte remote access ka `\pipe\tapsrv`.
- Uvedite validaciju mailslot namespace-a (`\\*\MAILSLOT\`) pre otvaranja putanja koje dostavlja klijent.
- Ograničite ACL-ove za `C:\Windows\TAPI\tsec.ini` i nadzirite promene; generišite alert za `GetUIDllName` pozive koji učitavaju putanje koje nisu podrazumevane.<sup>[[1]](#references)</sup>

## References

- [1] [Ko je na liniji? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
