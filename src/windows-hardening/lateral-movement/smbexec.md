# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Ottieni la prospettiva di un hacker sulle tue app web, rete e cloud**

**Trova e segnala vulnerabilità critiche ed exploitabili con un impatto reale sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti permettano di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Come Funziona

**Smbexec** è uno strumento utilizzato per l'esecuzione remota di comandi su sistemi Windows, simile a **Psexec**, ma evita di posizionare file dannosi sul sistema target.

### Punti Chiave su **SMBExec**

- Funziona creando un servizio temporaneo (ad esempio, "BTOBTO") sulla macchina target per eseguire comandi tramite cmd.exe (%COMSPEC%), senza scaricare alcun binario.
- Nonostante il suo approccio furtivo, genera log degli eventi per ogni comando eseguito, offrendo una forma di "shell" non interattiva.
- Il comando per connettersi utilizzando **Smbexec** appare così:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Esecuzione di Comandi Senza Binaries

- **Smbexec** consente l'esecuzione diretta di comandi attraverso i binPath dei servizi, eliminando la necessità di binaries fisici sul target.
- Questo metodo è utile per eseguire comandi una tantum su un target Windows. Ad esempio, abbinarlo al modulo `web_delivery` di Metasploit consente l'esecuzione di un payload Meterpreter inverso mirato a PowerShell.
- Creando un servizio remoto sulla macchina dell'attaccante con binPath impostato per eseguire il comando fornito tramite cmd.exe, è possibile eseguire con successo il payload, ottenendo callback ed esecuzione del payload con il listener di Metasploit, anche se si verificano errori di risposta del servizio.

### Esempio di Comandi

La creazione e l'avvio del servizio possono essere realizzati con i seguenti comandi:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Per ulteriori dettagli controlla [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Riferimenti

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Ottieni la prospettiva di un hacker sulle tue app web, rete e cloud**

**Trova e segnala vulnerabilità critiche ed exploitabili con un reale impatto sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti permettano di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
