# Livelli di integrità

{{#include ../../banners/hacktricks-training.md}}

## Livelli di integrità

In Windows Vista e nelle versioni successive, gli oggetti proteggibili possono contenere un'etichetta di **livello di integrità**. La maggior parte degli oggetti viene trattata come avente un livello di integrità medio, mentre le posizioni specifiche destinate alle applicazioni con bassa integrità possono essere contrassegnate come basse. I processi avviati dagli utenti standard vengono normalmente eseguiti con integrità media, le applicazioni elevate con integrità alta e molti servizi con integrità di sistema.<sup>[[1]](#references)</sup>

Una regola fondamentale è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore a quello dell'oggetto. Windows applica questo controllo Mandatory Integrity Control (MIC) prima di valutare la discretionary access control list (DACL) dell'oggetto. I livelli più comuni sono:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: il livello più basso, rappresentato da `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: utilizzato principalmente per le interazioni con Internet, soprattutto nella Protected Mode di Internet Explorer, influenzando i file e i processi associati e determinate cartelle come la **Temporary Internet Folder**. I processi con bassa integrità sono soggetti a restrizioni significative, tra cui l'assenza di accesso in scrittura al registro e l'accesso in scrittura limitato al profilo utente.
- **Medium**: il livello predefinito per la maggior parte delle attività, assegnato agli utenti standard e agli oggetti privi di livelli di integrità specifici. Anche i membri del gruppo Administrators operano a questo livello per impostazione predefinita.
- **High**: riservato agli amministratori, consentendo loro di modificare gli oggetti con livelli di integrità inferiori, inclusi quelli al livello alto stesso.
- **System**: il livello operativo più alto per il kernel di Windows e i servizi principali, inaccessibile anche agli amministratori, per garantire la protezione delle funzioni di sistema fondamentali.

Windows definisce inoltre un valore di integrità per i protected process superiore a System. **TrustedInstaller**, tuttavia, è un'identità di servizio Windows e non un livello MIC separato; la sua capacità di modificare le risorse protette del sistema operativo deriva dalle autorizzazioni concesse a tale identità.

È possibile ottenere il livello di integrità di un processo usando **Process Explorer** di **Sysinternals**, aprendo le proprietà del processo e visualizzando la scheda **Security**:<sup>[[3]](#references)</sup>

![Livelli di integrità - Livelli di integrità: è possibile ottenere il livello di integrità di un processo usando Process Explorer di Sysinternals, accedendo alle proprietà del processo e visualizzando la scheda "...](<../../images/image (824).png>)

È inoltre possibile ottenere il proprio **livello di integrità corrente** usando `whoami /groups`:

![Livelli di integrità - Livelli di integrità: è inoltre possibile ottenere il proprio livello di integrità corrente usando whoami /groups](<../../images/image (325).png>)

### Livelli di integrità nel file system

Un oggetto nel file system può avere un **requisito minimo di livello di integrità**. Un processo con un livello inferiore è soggetto ai criteri obbligatori dell'oggetto anche quando la relativa DACL concederebbe altrimenti l'accesso. Ad esempio, creare un file normale da una console con un utente standard e verificarne le autorizzazioni:<sup>[[1]](#references)[[4]](#references)</sup>
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
Ora, assegna un livello di integrità minimo **High** al file. Questa operazione **deve essere eseguita da una console** avviata come **amministratore**, perché una console normale viene eseguita con integrità Medium e **non sarà autorizzata ad assegnare un livello di integrità High a un oggetto**:
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
L'utente `DESKTOP-IDJHTKP\user` dispone di **privilegi COMPLETI** sul file perché lo ha creato. Tuttavia, l'etichetta obbligatoria impedisce all'utente di modificare il file, a meno che il processo non venga eseguito con un livello di integrità High. L'utente può comunque leggerlo perché la policy obbligatoria visualizzata è `(NW)`, ovvero no-write-up:
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

L'esempio seguente utilizza una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e le assegna un **livello di integrità Low da una console di amministratore**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ora, quando eseguo `cmd-low.exe`, verrà **eseguito a un livello di integrità basso** invece che medio:

![Livelli di integrità nel file system - Livelli di integrità nei binari: ora, quando eseguo cmd-low.exe, verrà eseguito a un livello di integrità basso invece che medio](<../../images/image (313).png>)

Assegnare un'etichetta di integrità High a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) non fa sì che venga eseguito automaticamente con integrità High. Se viene avviato da un processo con integrità Medium, viene eseguito con integrità Medium perché un nuovo processo riceve il livello di integrità più basso tra quello del file eseguibile e quello del processo chiamante.<sup>[[1]](#references)</sup>

### Livelli di integrità nei processi

Non tutti i file e le cartelle hanno un'etichetta di integrità minima esplicita, **ma ogni processo viene eseguito a un livello di integrità**. Come per gli oggetti del file system, **un processo che vuole ottenere l'accesso in scrittura a un altro processo deve avere almeno lo stesso livello di integrità**. Pertanto, un processo con integrità Low non può aprire un processo con integrità Medium con accesso completo.<sup>[[1]](#references)</sup>

A causa di queste restrizioni, l'approccio più sicuro consiste nell'**eseguire ogni processo al livello di integrità più basso che gli consenta comunque di svolgere il lavoro previsto**.

## References

- [1] [Microsoft Learn – Controllo obbligatorio dell'integrità](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Enumerazione MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
