# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wakati huduma ya Windows Telephony (TapiSrv, `tapisrv.dll`) imesanidiwa kama **TAPI server**, huweka wazi **interface ya `tapsrv` MSRPC kupitia named pipe ya `\pipe\tapsrv`** kwa SMB clients waliothibitishwa. CVE-2026-20931 katika uwasilishaji wa matukio ya asynchronous humwezesha attacker kubadilisha handle inayodaiwa kuwa ya mailslot kuwa **uandishi unaodhibitiwa wa bytes 4 kwenye faili iliyokuwepo awali na inayoweza kuandikwa na `NETWORK SERVICE`**. Chain iliyochapishwa hubadilisha orodha ya administrators wa Telephony, kisha kufikia upakiaji wa DLL unaohitaji administrator na kutekeleza kama `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` lazima iruhusu sharing (au isanidiwe kupitia `TapiMgmt.msc` / `tcmsetup /c <server>`). Kwa default, `tapsrv` ni local-only.
- Interface: MS-TRP (`tapsrv`) kupitia **SMB named pipe**, hivyo attacker anahitaji SMB auth halali.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` huanzisha uwasilishaji wa matukio ya async. Katika pull mode, service hufanya:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bila kuthibitisha kuwa `pszDomainUser` ni mailslot path (`\\*\MAILSLOT\...`). Njia yoyote ya filesystem iliyopo na inayoweza kuandikwa na `NETWORK SERVICE` inakubaliwa.
- Kila uandishi wa tukio la async huhifadhi **`DWORD` moja = `InitContext`** (inayodhibitiwa na attacker katika request inayofuata ya `Initialize`) kwenye handle iliyofunguliwa, na hivyo kutoa **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` kwa `pszDomainUser = <existing writable path>` (kwa mfano, `C:\Windows\TAPI\tsec.ini`).
2. Kwa kila `DWORD` ya kuandika, tekeleza RPC sequence hii dhidi ya `ClientRequest`:
- `Initialize` (`Req_Func 47`): weka `InitContext = <4-byte value>` na `pszModuleName = DIALER.EXE` (au entry nyingine ya juu katika per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (husajili line app na kuhesabu upya recipient mwenye priority ya juu zaidi).
- `TRequestMakeCall` (`Req_Func 121`): hulazimisha `NotifyHighestPriorityRequestRecipient`, na kuzalisha tukio la async.
- `GetAsyncEvents` (`Req_Func 0`): huondoa na kukamilisha uandishi.
- `LRegisterRequestRecipient` tena kwa `bEnable = 0` (hu-unregister).
- `Shutdown` (`Req_Func 86`) ili kuondoa line app.
- Priority control: recipient wa “highest priority” huchaguliwa kwa kulinganisha `pszModuleName` dhidi ya `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (husomwa wakati wa kum-impersonate client). Ikihitajika, weka jina la module yako kupitia `LSetAppPriority` (`Req_Func 69`).
- Faili **lazima iwepo tayari** kwa sababu `OPEN_EXISTING` inatumika. Kandideti za kawaida zinazoweza kuandikwa na `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Jipe Telephony “admin”**: lenga `C:\Windows\TAPI\tsec.ini` na uongeze `[TapiAdministrators]\r\n<DOMAIN\\user>=1` kwa kutumia 4-byte writes zilizo hapo juu. Anzisha session **mpya** (`ClientAttach`) ili service isome tena INI na kuweka `ptClient->dwFlags |= 9` kwa account yako.
2. **Admin-only DLL load**: tuma `GetUIDllName` ukiwa na `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` na toa path kupitia `dwProviderFilenameOffset`. Kwa administrators, service hufanya `LoadLibrary(path)` kisha kuita export `TSPI_providerUIIdentify`:
- Hufanya kazi na UNC paths zinazoelekea Windows SMB share halisi; baadhi ya attacker SMB servers hushindwa kwa `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative: pakua DLL ya local polepole kwa kutumia primitive hiyo hiyo ya 4-byte write, kisha ipakie.
3. **Payload**: export hutekelezwa chini ya `NETWORK SERVICE`. DLL ndogo inaweza kuendesha `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` na kurudisha value isiyo ya zero (kwa mfano, `0x1337`) ili service i-unload DLL, ikithibitisha execution.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Sakinisha Microsoft security update ya CVE-2026-20931. Pia zima TAPI server mode isipokuwa inahitajika na zuia remote access kwa `\pipe\tapsrv`.
- Tekeleza uthibitishaji wa mailslot namespace (`\\*\MAILSLOT\`) kabla ya kufungua paths zinazotolewa na client.
- Imarisha ACLs za `C:\Windows\TAPI\tsec.ini` na fuatilia mabadiliko; toa alert kuhusu calls za `GetUIDllName` zinazopakia paths zisizo za default.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
