# Livelli di integrità

{{#include ../../banners/hacktricks-training.md}}

## Livelli di integrità

In Windows Vista e nelle versioni successive, tutti gli elementi protetti hanno un tag di **livello di integrità**. Questa configurazione assegna principalmente un livello di integrità "medio" a file e chiavi del registro, ad eccezione di alcune cartelle e file in cui Internet Explorer 7 può scrivere con un livello di integrità basso. Il comportamento predefinito prevede che i processi avviati dagli utenti standard abbiano un livello di integrità medio, mentre i servizi operino generalmente a livello di integrità del sistema. Un'etichetta di integrità elevata protegge la directory principale.

Una regola fondamentale è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore a quello dell'oggetto. I livelli di integrità sono:

- **Untrusted**: questo livello è destinato ai processi con accessi anonimi. Esempio: Chrome
- **Low**: utilizzato principalmente per le interazioni Internet, soprattutto nella Protected Mode di Internet Explorer, con effetti sui file e sui processi associati e su alcune cartelle come la **Temporary Internet Folder**. I processi con integrità bassa sono soggetti a restrizioni significative, tra cui l'assenza di accesso in scrittura al registro e l'accesso in scrittura limitato al profilo utente.
- **Medium**: il livello predefinito per la maggior parte delle attività, assegnato agli utenti standard e agli oggetti privi di livelli di integrità specifici. Anche i membri del gruppo Administrators operano per impostazione predefinita a questo livello.
- **High**: riservato agli amministratori, consente loro di modificare gli oggetti con livelli di integrità inferiori, inclusi quelli dello stesso livello elevato.
- **System**: il livello operativo più alto per il kernel di Windows e i servizi principali, non accessibile neppure agli amministratori, garantendo la protezione delle funzioni essenziali del sistema.
- **Installer**: un livello unico che si colloca al di sopra di tutti gli altri e consente agli oggetti a questo livello di disinstallare qualsiasi altro oggetto.

È possibile ottenere il livello di integrità di un processo utilizzando **Process Explorer** di **Sysinternals**, accedendo alle **properties** del processo e visualizzando la scheda "**Security**":

![Livelli di integrità - Livelli di integrità: è possibile ottenere il livello di integrità di un processo utilizzando Process Explorer di Sysinternals, accedendo alle properties del processo e visualizzando la scheda "...](<../../images/image (824).png>)

È inoltre possibile ottenere il proprio **livello di integrità corrente** utilizzando `whoami /groups`

![Livelli di integrità - Livelli di integrità: è inoltre possibile ottenere il proprio livello di integrità corrente utilizzando whoami /groups](<../../images/image (325).png>)

### Livelli di integrità nel file system

Un oggetto all'interno del file system può richiedere un **livello di integrità minimo** e, se un processo non possiede questo livello di integrità, non sarà in grado di interagire con esso.\
Ad esempio, **creiamo un file normale dalla console di un utente normale e controlliamo le autorizzazioni**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Ora assegniamo un livello di integrità minimo **High** al file. Questa operazione **deve essere eseguita da una console** avviata come **amministratore**, poiché una **console normale** verrà eseguita con un livello di integrità Medium e **non potrà** assegnare un livello di integrità High a un oggetto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
È qui che le cose si fanno interessanti. Puoi vedere che l'utente `DESKTOP-IDJHTKP\user` dispone di **FULL privileges** sul file (infatti è stato proprio questo utente a creare il file); tuttavia, a causa del livello di integrità minimo implementato, non sarà più in grado di modificare il file a meno che non sia in esecuzione all'interno di un High Integrity Level (nota che potrà comunque leggerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Pertanto, quando un file ha un livello di integrità minimo, per modificarlo è necessario essere in esecuzione almeno a quel livello di integrità.**

### Livelli di integrità nei binari

Ho creato una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e le ho impostato un **livello di integrità basso da una console amministrativa:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ora, quando eseguo `cmd-low.exe`, verrà **eseguito con un livello di integrità basso** invece che medio:

![Integrity Levels in File-system - Integrity Levels in Binaries: Ora, quando eseguo cmd-low.exe, verrà eseguito con un livello di integrità basso invece che medio](<../../images/image (313).png>)

Per i più curiosi, se assegni un livello di integrità elevato a un binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), questo non verrà eseguito automaticamente con un livello di integrità elevato (se lo invochi da un livello di integrità medio --per impostazione predefinita-- verrà eseguito con un livello di integrità medio).

### Livelli di integrità nei processi

Non tutti i file e le cartelle hanno un livello di integrità minimo, **ma tutti i processi vengono eseguiti con un livello di integrità**. Analogamente a quanto accadeva con il file-system, **se un processo vuole scrivere all'interno di un altro processo deve avere almeno lo stesso livello di integrità**. Ciò significa che un processo con un livello di integrità basso non può aprire un handle con accesso completo a un processo con un livello di integrità medio.

A causa delle restrizioni descritte in questa e nella sezione precedente, dal punto di vista della sicurezza è sempre **consigliato eseguire un processo con il livello di integrità più basso possibile**.

{{#include ../../banners/hacktricks-training.md}}
