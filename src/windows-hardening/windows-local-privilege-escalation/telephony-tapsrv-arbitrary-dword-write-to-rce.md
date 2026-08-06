# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wakati Windows Telephony service (TapiSrv, `tapisrv.dll`) imesanidiwa kama **TAPI server**, hufichua **`tapsrv` MSRPC interface kupitia `\pipe\tapsrv` named pipe** kwa authenticated SMB clients. Hitilafu ya muundo katika uwasilishaji wa asynchronous events kwa remote clients humruhusu attacker kubadilisha mailslot handle kuwa **controlled 4-byte write kwa faili yoyote iliyokuwepo awali na inayoweza kuandikwa na `NETWORK SERVICE`**. Primitive hii inaweza kuunganishwa ili kubadilisha Telephony admin list na kutumia vibaya **admin-only arbitrary DLL load** kutekeleza code kama `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Attack Surface

- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` lazima iruhusu sharing (au isanidiwe kupitia `TapiMgmt.msc` / `tcmsetup /c <server>`). Kwa default, `tapsrv` ni local-only.
- Interface: MS-TRP (`tapsrv`) kupitia **SMB named pipe**, kwa hivyo attacker anahitaji valid SMB auth.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` huanzisha async event delivery. Katika pull mode, service hufanya:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bila kuthibitisha kwamba `pszDomainUser` ni mailslot path (`\\*\MAILSLOT\...`). **Any existing filesystem path** inayoweza kuandikwa na `NETWORK SERVICE` inakubaliwa.
- Kila async event write huhifadhi **`DWORD` moja = `InitContext`** (inayodhibitiwa na attacker katika subsequent `Initialize` request) kwenye handle iliyofunguliwa, hivyo kutoa **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` kwa `pszDomainUser = <existing writable path>` (kwa mfano, `C:\Windows\TAPI\tsec.ini`).
2. Kwa kila `DWORD` ya kuandika, tekeleza RPC sequence hii dhidi ya `ClientRequest`:
- `Initialize` (`Req_Func 47`): weka `InitContext = <4-byte value>` na `pszModuleName = DIALER.EXE` (au entry nyingine ya juu katika per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (husajili line app na kuhesabu upya highest priority recipient).
- `TRequestMakeCall` (`Req_Func 121`): hulazimisha `NotifyHighestPriorityRequestRecipient`, na kuzalisha async event.
- `GetAsyncEvents` (`Req_Func 0`): huondoa na kukamilisha write.
- `LRegisterRequestRecipient` tena kwa `bEnable = 0` (hu-unregister).
- `Shutdown` (`Req_Func 86`) ili kuondoa line app.
- Priority control: “highest priority” recipient huchaguliwa kwa kulinganisha `pszModuleName` dhidi ya `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (husomwa wakati wa kum impersonate client). Ikihitajika, ingiza module name yako kupitia `LSetAppPriority` (`Req_Func 69`).
- Faili **lazima iwe tayari ipo** kwa sababu `OPEN_EXISTING` inatumika. Mifano ya common candidates zinazoweza kuandikwa na `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Jipe Telephony “admin”**: lenga `C:\Windows\TAPI\tsec.ini` na uongeze `[TapiAdministrators]\r\n<DOMAIN\\user>=1` kwa kutumia 4-byte writes zilizo hapo juu. Anzisha session **mpya** (`ClientAttach`) ili service isome tena INI na kuweka `ptClient->dwFlags |= 9` kwa account yako.
2. **Admin-only DLL load**: tuma `GetUIDllName` ukiwa na `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` na toa path kupitia `dwProviderFilenameOffset`. Kwa admins, service hufanya `LoadLibrary(path)` kisha kuita export `TSPI_providerUIIdentify`:
- Hufanya kazi na UNC paths zinazoelekeza kwenye Windows SMB share halisi; baadhi ya attacker SMB servers hushindwa kwa `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative: drop local DLL polepole kwa kutumia 4-byte write primitive hiyo hiyo, kisha uipakie.
3. **Payload**: export hutekelezwa chini ya `NETWORK SERVICE`. DLL ndogo inaweza kuendesha `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` na kurudisha non-zero value (kwa mfano, `0x1337`) ili service i-unload DLL, ikithibitisha execution.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Zima TAPI server mode isipokuwa inahitajika; zuia remote access kwenye `\pipe\tapsrv`.
- Tekeleza mailslot namespace validation (`\\*\MAILSLOT\`) kabla ya kufungua paths zinazotolewa na client.
- Funga ACLs za `C:\Windows\TAPI\tsec.ini` na fuatilia mabadiliko; toa alert kwa `GetUIDllName` calls zinazopakia non-default paths.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
