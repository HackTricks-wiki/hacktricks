# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wakati Windows Telephony service (TapiSrv, `tapisrv.dll`) imewekwa kama **TAPI server**, inatoa **`tapsrv` MSRPC interface over the `\pipe\tapsrv` named pipe** kwa wateja wa SMB walioidhinishwa. Hitilafu ya muundo katika utoaji wa matukio asynchronous kwa wateja wa mbali inamruhusu mshambuliaji kubadilisha handle ya mailslot kuwa **controlled 4-byte write to any pre-existing file writable by `NETWORK SERVICE`**. Primitive hiyo inaweza kuunganishwa kuandika upya orodha ya admin ya Telephony na kutumia **admin-only arbitrary DLL load** ili kutekeleza msimbo kama `NETWORK SERVICE`.

## Attack Surface
- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` lazima irahisishe sharing (au iwe imewekwa kupitia `TapiMgmt.msc` / `tcmsetup /c <server>`). Kwa default `tapsrv` ni local-only.
- Interface: MS-TRP (`tapsrv`) over **SMB named pipe**, kwa hivyo mshambuliaji anahitaji SMB auth halali.
- Service account: `NETWORK SERVICE` (manual start, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inaanzisha async event delivery. Katika pull mode, service inafanya:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bila kuthibitisha kwamba `pszDomainUser` ni mailslot path (`\\*\MAILSLOT\...`). Njia yoyote ya filesystem iliyopo ambayo inaweza kuandikwa na `NETWORK SERVICE` inakubaliwa.
- Kila async event write inaweka single **`DWORD` = `InitContext`** (inayodhibitiwa na mshambuliaji katika ombi la `Initialize` lililofuatia) kwenye handle iliyofunguliwa, ikitoa **write-what/write-where (4 bytes)**.

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` na `pszDomainUser = <existing writable path>` (mfano, `C:\Windows\TAPI\tsec.ini`).
2. Kwa kila `DWORD` unayotaka kuandika, fanya mnyororo huu wa RPC dhidi ya `ClientRequest`:
- `Initialize` (`Req_Func 47`): weka `InitContext = <4-byte value>` na `pszModuleName = DIALER.EXE` (au entry nyingine ya juu katika per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (hurejesha line app, inarekebisha recipient mwenye kipaumbele cha juu).
- `TRequestMakeCall` (`Req_Func 121`): inalazimisha `NotifyHighestPriorityRequestRecipient`, ikizalisha async event.
- `GetAsyncEvents` (`Req_Func 0`): inatoa/inakamilisha write.
- `LRegisterRequestRecipient` tena kwa `bEnable = 0` (kuondoa usajili).
- `Shutdown` (`Req_Func 86`) kuondoa line app.
- Udhibiti wa priority: recipient mwenye “highest priority” huchaguliwa kwa kulinganisha `pszModuleName` dhidi ya `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (inayosomwa wakati wa kujitambulisha kama client). Ikiwa inahitajika, ingiza module name yako kupitia `LSetAppPriority` (`Req_Func 69`).
- Faili lazima **iwe tayari imepo** kwa sababu `OPEN_EXISTING` inatumika. Kandidati za kawaida zinazoweza kuandikwa na `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Jipe Telephony “admin”**: lipa `C:\Windows\TAPI\tsec.ini` na ongeza `[TapiAdministrators]\r\n<DOMAIN\\user>=1` kwa kutumia uandishi wa 4-byte ulioelezewa hapo juu. Anzisha session **mpya** (`ClientAttach`) ili service isome tena INI na iwe `ptClient->dwFlags |= 9` kwa akaunti yako.
2. **Admin-only DLL load**: tuma `GetUIDllName` na `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` na toa path kupitia `dwProviderFilenameOffset`. Kwa admins, service hufanya `LoadLibrary(path)` kisha inaita export `TSPI_providerUIIdentify`:
- Inafanya kazi na UNC paths kwenda kwa Windows SMB share halisi; baadhi ya attacker SMB servers zinashindwa na `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Mbadala: punguza polepole DLL ya ndani kutumia primitive ya uandishi wa 4-byte hiyo, kisha iipe.
3. **Payload**: export inatekelezwa chini ya `NETWORK SERVICE`. DLL minimal inaweza kuendesha `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` na kurudisha thamani isiyo sifuri (mfano, `0x1337`) ili service iunde DLL, ikithibitisha utekelezaji.

## Hardening / Detection Notes
- Zima TAPI server mode isipohitajika; zuia upatikanaji wa mbali kwa `\pipe\tapsrv`.
- Weka validation ya mailslot namespace (`\\*\MAILSLOT\`) kabla ya kufungua paths zinazotolewa na client.
- Funga ACLs za `C:\Windows\TAPI\tsec.ini` na ziangalie mabadiliko; kutoa tahadhari kwa wito za `GetUIDllName` zinaload paths zisizo za default.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
