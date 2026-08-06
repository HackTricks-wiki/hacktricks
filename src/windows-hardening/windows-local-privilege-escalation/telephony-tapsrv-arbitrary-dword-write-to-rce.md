# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Quando il servizio Windows Telephony (TapiSrv, `tapisrv.dll`) è configurato come **TAPI server**, espone l'interfaccia **`tapsrv` MSRPC sulla named pipe `\pipe\tapsrv`** ai client SMB autenticati. Un bug di progettazione nella distribuzione degli eventi asincroni per i client remoti consente a un attacker di trasformare un handle mailslot in una **scrittura controllata di 4 byte su qualsiasi file preesistente scrivibile da `NETWORK SERVICE`**. Questa primitive può essere concatenata per sovrascrivere l'elenco degli amministratori Telephony e abusare di un **arbitrary DLL load riservato agli amministratori** per eseguire codice come `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Superficie d'attacco

- **Esposizione remota solo quando abilitata**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` deve consentire la condivisione (oppure essere configurata tramite `TapiMgmt.msc` / `tcmsetup /c <server>`). Per impostazione predefinita, `tapsrv` è accessibile solo localmente.
- Interfaccia: MS-TRP (`tapsrv`) tramite **SMB named pipe**, quindi l'attacker necessita di credenziali SMB valide.
- Account del servizio: `NETWORK SERVICE` (avvio manuale, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inizializza la distribuzione degli eventi asincroni. In pull mode, il servizio esegue:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
senza verificare che `pszDomainUser` sia un path mailslot (`\\*\MAILSLOT\...`). Qualsiasi **path del filesystem esistente** e scrivibile da `NETWORK SERVICE` viene accettato.
- Ogni scrittura di un evento asincrono memorizza un singolo **`DWORD` = `InitContext`** (controllato dall'attacker nella successiva richiesta `Initialize`) sull'handle aperto, ottenendo una **write-what/write-where di 4 byte**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Aprire il file target**: `ClientAttach` con `pszDomainUser = <existing writable path>` (ad esempio, `C:\Windows\TAPI\tsec.ini`).
2. Per ogni `DWORD` da scrivere, eseguire questa sequenza RPC su `ClientRequest`:
- `Initialize` (`Req_Func 47`): impostare `InitContext = <4-byte value>` e `pszModuleName = DIALER.EXE` (o un'altra voce principale della priority list per-user).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra la line app e ricalcola il recipient con la priorità più alta).
- `TRequestMakeCall` (`Req_Func 121`): forza `NotifyHighestPriorityRequestRecipient`, generando l'evento asincrono.
- `GetAsyncEvents` (`Req_Func 0`): estrae e completa la scrittura.
- `LRegisterRequestRecipient` di nuovo con `bEnable = 0` (annulla la registrazione).
- `Shutdown` (`Req_Func 86`) per chiudere la line app.
- Controllo della priority: il recipient con la “highest priority” viene scelto confrontando `pszModuleName` con `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (letto durante l'impersonation del client). Se necessario, inserire il nome del proprio modulo tramite `LSetAppPriority` (`Req_Func 69`).
- Il file **deve già esistere** perché viene utilizzato `OPEN_EXISTING`. Candidati comuni scrivibili da `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Concedersi i privilegi di Telephony “admin”**: scegliere come target `C:\Windows\TAPI\tsec.ini` e aggiungere `[TapiAdministrators]\r\n<DOMAIN\\user>=1` utilizzando le scritture di 4 byte descritte sopra. Avviare una **nuova** sessione (`ClientAttach`) affinché il servizio rilegga l'INI e imposti `ptClient->dwFlags |= 9` per il proprio account.
2. **Admin-only DLL load**: inviare `GetUIDllName` con `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` e fornire un path tramite `dwProviderFilenameOffset`. Per gli amministratori, il servizio esegue `LoadLibrary(path)` e poi chiama l'export `TSPI_providerUIIdentify`:
- Funziona con path UNC verso una condivisione SMB Windows reale; alcuni SMB server dell'attacker falliscono con `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: eseguire lentamente il drop di una DLL locale utilizzando la stessa primitive di scrittura di 4 byte, quindi caricarla.
3. **Payload**: l'export viene eseguito sotto `NETWORK SERVICE`. Una DLL minimale può eseguire `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` e restituire un valore diverso da zero (ad esempio, `0x1337`) in modo che il servizio scarichi la DLL, confermando l'esecuzione.<sup>[[1]](#references)</sup>

## Note su Hardening / Detection
- Disabilitare la modalità TAPI server se non necessaria; bloccare l'accesso remoto a `\pipe\tapsrv`.
- Applicare la validazione del namespace mailslot (`\\*\MAILSLOT\`) prima di aprire i path forniti dal client.
- Limitare gli ACL di `C:\Windows\TAPI\tsec.ini` e monitorare le modifiche; generare alert sulle chiamate a `GetUIDllName` che caricano path non predefiniti.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
