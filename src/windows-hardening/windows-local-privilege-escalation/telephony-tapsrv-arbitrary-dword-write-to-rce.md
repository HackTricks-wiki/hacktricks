# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Quando il servizio Windows Telephony (TapiSrv, `tapisrv.dll`) è configurato come **TAPI server**, espone l'interfaccia **`tapsrv` MSRPC sulla named pipe `\pipe\tapsrv`** ai client SMB autenticati. CVE-2026-20931 nella consegna asincrona degli eventi consente a un attacker di trasformare un presunto handle mailslot in una **scrittura controllata di 4 byte in un file preesistente scrivibile da `NETWORK SERVICE`**. La chain pubblicata sovrascrive l'elenco degli amministratori Telephony, quindi raggiunge un caricamento di DLL riservato agli amministratori ed esegue codice come `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Esposizione remota solo quando abilitata**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` deve consentire la condivisione (oppure essere configurata tramite `TapiMgmt.msc` / `tcmsetup /c <server>`). Per impostazione predefinita, `tapsrv` è solo locale.
- Interfaccia: MS-TRP (`tapsrv`) tramite **SMB named pipe**, quindi l'attacker necessita di credenziali SMB valide.
- Account del servizio: `NETWORK SERVICE` (avvio manuale, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inizializza la consegna asincrona degli eventi. In pull mode, il servizio esegue:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
senza verificare che `pszDomainUser` sia un percorso mailslot (`\\*\MAILSLOT\...`). Viene accettato qualsiasi **percorso del filesystem esistente** scrivibile da `NETWORK SERVICE`.
- Ogni scrittura di un evento asincrono memorizza un singolo **`DWORD` = `InitContext`** (controllato dall'attacker nella successiva richiesta `Initialize`) sull'handle aperto, ottenendo una primitiva **write-what/write-where (4 byte)**.<sup>[[1]](#references)</sup>

## Forzare scritture deterministiche
1. **Aprire il file target**: `ClientAttach` con `pszDomainUser = <existing writable path>` (ad esempio `C:\Windows\TAPI\tsec.ini`).
2. Per ogni `DWORD` da scrivere, eseguire questa sequenza RPC contro `ClientRequest`:
- `Initialize` (`Req_Func 47`): impostare `InitContext = <4-byte value>` e `pszModuleName = DIALER.EXE` (oppure un'altra voce iniziale nella priority list per-user).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra la line app e ricalcola il recipient con la priorità più alta).
- `TRequestMakeCall` (`Req_Func 121`): forza `NotifyHighestPriorityRequestRecipient`, generando l'evento asincrono.
- `GetAsyncEvents` (`Req_Func 0`): rimuove dalla coda e completa la scrittura.
- `LRegisterRequestRecipient` di nuovo con `bEnable = 0` (annulla la registrazione).
- `Shutdown` (`Req_Func 86`) per rimuovere la line app.
- Controllo della priorità: il recipient con la “priorità più alta” viene scelto confrontando `pszModuleName` con `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (letto durante l'impersonation del client). Se necessario, inserire il nome del proprio modulo tramite `LSetAppPriority` (`Req_Func 69`).
- Il file **deve già esistere** perché viene usato `OPEN_EXISTING`. Candidati comunemente scrivibili da `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Dal DWORD Write a RCE dentro TapiSrv
1. **Concedersi i privilegi di “admin” Telephony**: selezionare `C:\Windows\TAPI\tsec.ini` come target e aggiungere `[TapiAdministrators]\r\n<DOMAIN\\user>=1` usando le scritture di 4 byte descritte sopra. Avviare una nuova sessione (`ClientAttach`) affinché il servizio rilegga l'INI e imposti `ptClient->dwFlags |= 9` per il proprio account.
2. **Caricamento di una DLL riservato agli amministratori**: inviare `GetUIDllName` con `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` e fornire un percorso tramite `dwProviderFilenameOffset`. Per gli amministratori, il servizio esegue `LoadLibrary(path)` e quindi chiama l'export `TSPI_providerUIIdentify`:
- Funziona con percorsi UNC verso una reale condivisione SMB Windows; alcuni SMB server dell'attacker falliscono con `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: rilasciare lentamente una DLL locale usando la stessa primitiva di scrittura di 4 byte, quindi caricarla.
3. **Payload**: l'export viene eseguito con l'account `NETWORK SERVICE`. Una DLL minimale può eseguire `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` e restituire un valore diverso da zero (ad esempio `0x1337`) affinché il servizio scarichi la DLL, confermando l'esecuzione.<sup>[[1]](#references)</sup>

## Note su Hardening / Detection
- Installare l'aggiornamento di sicurezza Microsoft per CVE-2026-20931. Inoltre, disabilitare TAPI server mode salvo necessità e bloccare l'accesso remoto a `\pipe\tapsrv`.
- Applicare la validazione del namespace mailslot (`\\*\MAILSLOT\`) prima di aprire percorsi forniti dal client.
- Limitare le ACL di `C:\Windows\TAPI\tsec.ini` e monitorare le modifiche; generare alert sulle chiamate `GetUIDllName` che caricano percorsi non predefiniti.<sup>[[1]](#references)</sup>

## References

- [1] [Chi è in linea? Sfruttare una RCE nel servizio Windows Telephony (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
