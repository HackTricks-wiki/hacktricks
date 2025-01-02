# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano

Il processo è delineato nei passaggi seguenti, illustrando come i file binari di servizio vengano manipolati per ottenere l'esecuzione remota su una macchina target tramite SMB:

1. **Copia di un file binario di servizio nella condivisione ADMIN$ tramite SMB** viene eseguita.
2. **Creazione di un servizio sulla macchina remota** viene effettuata puntando al file binario.
3. Il servizio viene **avviato remotamente**.
4. Al termine, il servizio viene **interrotto e il file binario viene eliminato**.

### **Processo di Esecuzione Manuale di PsExec**

Assumendo che ci sia un payload eseguibile (creato con msfvenom e offuscato usando Veil per eludere la rilevazione antivirus), chiamato 'met8888.exe', che rappresenta un payload meterpreter reverse_http, vengono eseguiti i seguenti passaggi:

- **Copia del file binario**: L'eseguibile viene copiato nella condivisione ADMIN$ da un prompt dei comandi, anche se può essere posizionato ovunque nel filesystem per rimanere nascosto.

- **Creazione di un servizio**: Utilizzando il comando Windows `sc`, che consente di interrogare, creare ed eliminare servizi Windows in remoto, viene creato un servizio chiamato "meterpreter" che punta al file binario caricato.

- **Avvio del servizio**: L'ultimo passaggio comporta l'avvio del servizio, che probabilmente risulterà in un errore di "timeout" a causa del fatto che il file binario non è un vero file binario di servizio e non riesce a restituire il codice di risposta atteso. Questo errore è irrilevante poiché l'obiettivo principale è l'esecuzione del file binario.

L'osservazione del listener di Metasploit rivelerà che la sessione è stata avviata con successo.

[Scopri di più sul comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trova passaggi più dettagliati in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Puoi anche utilizzare il file binario PsExec.exe di Windows Sysinternals:**

![](<../../images/image (165).png>)

Puoi anche utilizzare [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
