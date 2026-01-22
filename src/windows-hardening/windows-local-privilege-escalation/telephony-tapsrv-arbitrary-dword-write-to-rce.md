# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Quando il servizio Windows Telephony (TapiSrv, `tapisrv.dll`) è configurato come **TAPI server**, espone l'**MSRPC interface `tapsrv` tramite la named pipe `\pipe\tapsrv`** ai client SMB autenticati. Un bug di progettazione nella delivery asincrona degli eventi per client remoti permette a un attaccante di trasformare un handle mailslot in una **scrittura controllata di 4 byte su qualsiasi file preesistente scrivibile da `NETWORK SERVICE`**. Questa primitive può essere concatenata per sovrascrivere la lista degli amministratori di Telephony e abusare di un **caricamento arbitrario di DLL riservato agli admin** per eseguire codice come `NETWORK SERVICE`.

## Attack Surface
- **Esposizione remota solo se abilitata**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` deve consentire lo sharing (o essere configurato tramite `TapiMgmt.msc` / `tcmsetup /c <server>`). Di default `tapsrv` è locale.
- Interfaccia: MS-TRP (`tapsrv`) su **SMB named pipe**, quindi l'attaccante necessita di autenticazione SMB valida.
- Service account: `NETWORK SERVICE` (avvio manuale, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inizializza la delivery asincrona degli eventi. In pull mode, il servizio esegue:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
senza validare che `pszDomainUser` sia un mailslot path (`\\*\MAILSLOT\...`). Viene accettato qualsiasi **percorso filesystem esistente** scrivibile da `NETWORK SERVICE`.
- Ogni write di evento asincrono memorizza un singolo **`DWORD` = `InitContext`** (controllato dall'attaccante nella successiva richiesta `Initialize`) sull'handle aperto, ottenendo una **write-what/write-where (4 byte)**.

## Forcing Deterministic Writes
1. **Aprire il file target**: `ClientAttach` con `pszDomainUser = <existing writable path>` (es. `C:\Windows\TAPI\tsec.ini`).
2. Per ogni `DWORD` da scrivere, eseguire questa sequenza RPC contro `ClientRequest`:
- `Initialize` (`Req_Func 47`): impostare `InitContext = <4-byte value>` e `pszModuleName = DIALER.EXE` (o un altro top entry nella per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra la line app, ricalcola il recipient a più alta priorità).
- `TRequestMakeCall` (`Req_Func 121`): forza `NotifyHighestPriorityRequestRecipient`, generando l'evento asincrono.
- `GetAsyncEvents` (`Req_Func 0`): dequeue/completa la write.
- `LRegisterRequestRecipient` di nuovo con `bEnable = 0` (deregistra).
- `Shutdown` (`Req_Func 86`) per terminare la line app.
- Controllo delle priorità: il “highest priority” recipient è scelto confrontando `pszModuleName` con `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (lettura durante l'impersonificazione del client). Se necessario, inserire il nome del proprio modulo tramite `LSetAppPriority` (`Req_Func 69`).
- Il file **deve esistere già** perché è usato `OPEN_EXISTING`. Possibili target scrivibili da `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Ottenere lo status di Telephony “admin”**: mirare a `C:\Windows\TAPI\tsec.ini` e appendere `[TapiAdministrators]\r\n<DOMAIN\\user>=1` usando le write da 4 byte sopra descritte. Avviare una sessione **nuova** (`ClientAttach`) così il servizio rilegge l'INI e imposta `ptClient->dwFlags |= 9` per il vostro account.
2. **Caricamento DLL riservato agli admin**: inviare `GetUIDllName` con `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` e fornire un percorso via `dwProviderFilenameOffset`. Per gli admin, il servizio esegue `LoadLibrary(path)` e poi chiama l'export `TSPI_providerUIIdentify`:
- Funziona con UNC path verso una reale condivisione SMB di Windows; alcuni SMB server dell'attaccante falliscono con `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: riversare lentamente una DLL locale usando la stessa primitive di scrittura a 4 byte, poi caricarla.
3. **Payload**: l'export viene eseguito sotto `NETWORK SERVICE`. Una DLL minima può eseguire `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` e restituire un valore non-zero (es. `0x1337`) così il servizio scarica la DLL, confermando l'esecuzione.

## Hardening / Detection Notes
- Disabilitare TAPI server mode a meno che non sia necessario; bloccare l'accesso remoto a `\pipe\tapsrv`.
- Valida la mailslot namespace (`\\*\MAILSLOT\`) prima di aprire i path forniti dal client.
- Restringere gli ACL di `C:\Windows\TAPI\tsec.ini` e monitorarne le modifiche; allertare sulle chiamate `GetUIDllName` che caricano percorsi non di default.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
