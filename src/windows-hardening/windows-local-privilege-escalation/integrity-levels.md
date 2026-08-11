# Livelli di integrità

{{#include ../../banners/hacktricks-training.md}}

## Livelli di integrità

In Windows Vista e nelle versioni successive, gli oggetti che supportano la protezione possono avere un'etichetta di **livello di integrità**. La maggior parte degli oggetti viene trattata come avente un livello di integrità medio, mentre le posizioni specifiche destinate alle applicazioni con bassa integrità possono essere etichettate come basse. I processi avviati dagli utenti standard vengono normalmente eseguiti con integrità media, le applicazioni con privilegi elevati con integrità alta e molti servizi con integrità di sistema.<sup>[[1]](#references)</sup>

Una regola fondamentale è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore a quello dell'oggetto. Windows applica questo controllo Mandatory Integrity Control (MIC) prima di valutare la discretionary access control list (DACL) dell'oggetto. I livelli comunemente riscontrati sono:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: il livello più basso, rappresentato da `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Non bisogna confondere questa etichetta di integrità con l'identità **Anonymous Logon** (`S-1-5-7`); le identità di autenticazione e le etichette MIC appartengono a namespace SID separati. In un esempio reale, la sandbox di Chromium per Windows assegna inizialmente ai target sottoposti a sandbox il livello di integrità Low e successivamente riduce i target renderer al livello di integrità Untrusted dopo l'avvio.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: utilizzato principalmente per le interazioni con Internet, soprattutto nella Protected Mode di Internet Explorer, con effetti sui file e sui processi associati e su determinate cartelle come la **Temporary Internet Folder**. I processi con bassa integrità sono soggetti a restrizioni significative, tra cui l'assenza di accesso in scrittura al registro e l'accesso in scrittura limitato al profilo utente.
- **Medium**: il livello predefinito per la maggior parte delle attività, assegnato agli utenti standard e agli oggetti privi di livelli di integrità specifici. Anche i membri del gruppo Administrators operano a questo livello per impostazione predefinita.
- **High**: riservato agli amministratori, consentendo loro di modificare gli oggetti con livelli di integrità inferiori, inclusi quelli allo stesso livello high.
- **System**: il livello operativo più alto per il kernel di Windows e i servizi principali, non accessibile neppure agli amministratori, che garantisce la protezione delle funzioni essenziali del sistema.

Windows definisce anche un valore di integrità per i protected process superiore a System. **TrustedInstaller**, tuttavia, è un'identità di servizio Windows e non un livello MIC separato; la sua capacità di modificare le risorse protette del sistema operativo deriva dalle autorizzazioni concesse a tale identità.

Non bisogna presumere che una posizione come la radice di un'unità di sistema abbia sempre un'etichetta di integrità High fissa. Esaminare la DACL effettiva e qualsiasi mandatory label esplicita con `icacls`; un oggetto senza etichetta viene trattato come Medium per MIC, mentre la DACL e la proprietà possono comunque limitare l'accesso in modo indipendente.<sup>[[1]](#references)[[4]](#references)</sup>

È possibile ottenere il livello di integrità di un processo usando **Process Explorer** di **Sysinternals**, aprendo le proprietà del processo e visualizzando la scheda **Security**:<sup>[[3]](#references)</sup>

![Livelli di integrità - Livelli di integrità: è possibile ottenere il livello di integrità di un processo usando Process Explorer di Sysinternals, accedendo alle proprietà del processo e visualizzando la scheda "...](<../../images/image (824).png>)

È inoltre possibile ottenere il proprio **livello di integrità corrente** usando `whoami /groups`:

![Livelli di integrità - Livelli di integrità: è inoltre possibile ottenere il proprio livello di integrità corrente usando whoami /groups](<../../images/image (325).png>)

### Livelli di integrità nel file system

Un oggetto nel file system può avere un **requisito minimo di livello di integrità**. Un processo con un livello inferiore è soggetto ai criteri obbligatori dell'oggetto anche quando la sua DACL concederebbe altrimenti l'accesso. Ad esempio, creare un file normale da una console di un utente standard e controllarne le autorizzazioni:<sup>[[1]](#references)[[4]](#references)</sup>
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
Ora assegna al file un livello di integrità minimo **High**. Questa operazione **deve essere eseguita da una console** avviata come **amministratore**, perché una console normale viene eseguita con integrità Medium e **non potrà assegnare un livello di integrità High a un oggetto**:
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
L'utente `DESKTOP-IDJHTKP\user` dispone di **FULL privileges** sul file perché lo ha creato. Tuttavia, l'etichetta obbligatoria impedisce all'utente di modificare il file, a meno che il processo non sia in esecuzione con livello di integrità High. L'utente può comunque leggerlo perché la mandatory policy visualizzata è `(NW)`, ovvero no-write-up:
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

L'esempio seguente utilizza una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e le assegna un **livello di integrità Low da una console amministrativa**:
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

![Livelli di integrità nel file system - Livelli di integrità nei binari: ora, quando eseguo cmd-low.exe, verrà eseguito con un livello di integrità basso invece che medio](<../../images/image (313).png>)

Assegnare un'etichetta di integrità High a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) non fa sì che venga eseguito automaticamente con integrità High. Se viene avviato da un processo con integrità Medium, viene eseguito con integrità Medium, perché un nuovo processo riceve il livello di integrità più basso tra quello del file eseguibile e quello del chiamante.<sup>[[1]](#references)</sup>

### Livelli di integrità nei processi

Non tutti i file e le cartelle hanno un'etichetta di integrità minima esplicita, **ma ogni processo viene eseguito a un determinato livello di integrità**. Come per gli oggetti del file system, **un processo che vuole ottenere l'accesso in scrittura a un altro processo deve avere almeno lo stesso livello di integrità**. Pertanto, un processo con integrità Low non può aprire un processo con integrità Medium con accesso completo.<sup>[[1]](#references)</sup>

A causa di queste restrizioni, l'approccio più sicuro consiste nell'**eseguire ogni processo al livello di integrità più basso che gli consenta comunque di svolgere il lavoro previsto**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – enumerazione MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Codice sorgente di Chromium – policy di integrità della sandbox predefinita di Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – SID noti](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
