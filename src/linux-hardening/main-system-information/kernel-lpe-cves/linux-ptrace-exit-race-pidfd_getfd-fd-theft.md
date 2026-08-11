# Linux ptrace exit-race `pidfd_getfd()` furto di FD

{{#include ../../../banners/hacktricks-training.md}}

Un utile **pattern di privesc nel kernel Linux** consiste nel trasformare un **bug di autorizzazione di ptrace** in un **furto di file descriptor** da un processo privilegiato.

Nel case study di Qualys su `__ptrace_may_access()` (CVE-2026-46333), l'attaccante esegue una race contro un **processo privilegiato in fase di terminazione o di abbandono delle credenziali** e usa `pidfd_getfd()` per duplicare un FD nel processo dell'attaccante.<sup>[[1]](#references)[[2]](#references)</sup>

## Idea centrale

`pidfd_getfd()` duplica un file descriptor da un altro processo, ma prima verifica i permessi in stile ptrace rispetto al target.<sup>[[3]](#references)</sup> Se tale autorizzazione viene concessa erroneamente durante una **finestra di teardown**, un attaccante non privilegiato può copiare:

- FD di **file sensibili** già aperti da un helper privilegiato
- FD di **canali IPC autenticati** già autorizzati come root

Questo trasforma un bug di autorizzazione lato kernel in una primitiva userspace molto pratica.<sup>[[1]](#references)</sup>

## Perché la primitiva è pericolosa

L'attacco **non** richiede un bug nell'helper privilegiato. L'helper deve solo mantenere temporaneamente qualcosa di utile:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una connessione D-Bus / systemd privilegiata
- qualsiasi altro secret già aperto o canale autorizzato

Una volta duplicato nel processo dell'attaccante, il duplicato fa riferimento alla stessa open file description, quindi le letture successive o le richieste IPC usano l'FD già aperto invece di riaprire il pathname originale o avviare un nuovo flusso di autenticazione.<sup>[[2]](#references)[[3]](#references)</sup>

## Pattern di exploitation

1. Identificare un **binary setuid / setgid / con file-capability** o un **root daemon** che apra file sensibili o mantenga connessioni IPC utili.<sup>[[2]](#references)</sup>
2. Ottenere una relazione che soddisfi i controlli della policy ptrace pertinenti per il target path (per esempio, essere il **parent** di un processo child privilegiato generato in presenza di impostazioni YAMA permissive).<sup>[[2]](#references)[[4]](#references)</sup>
3. Eseguire una race contro il processo mentre è **in fase di terminazione**, **abbandona le credenziali** o entra altrimenti in uno stato in cui l'accesso ptrace dovrebbe essere diventato non disponibile.<sup>[[2]](#references)</sup>
4. Usare `pidfd_open()` + `pidfd_getfd()` per duplicare l'FD del target durante la stretta finestra di autorizzazione.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Riutilizzare l'FD rubato dal contesto non privilegiato.<sup>[[2]](#references)</sup>
- `read()` dei secret da un file descriptor privilegiato
- inviare richieste attraverso un canale IPC autenticato rubato per ottenere **azioni lato root**

Forma minima della primitiva.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Obiettivi pratici da sottoporre ad audit

Dare priorità ai binari e ai daemon che, anche solo brevemente, fanno una di queste cose:<sup>[[1]](#references)[[2]](#references)</sup>

- aprono file accessibili solo a root prima di completare le transizioni di privilegio
- si connettono al **system bus** e mantengono un channel già autorizzato
- passano FD privilegiati oltre i confini degli helper
- eseguono operazioni sensibili per la sicurezza durante il teardown adiacente a `do_exit()`

Buoni candidati per la ricerca:<sup>[[1]](#references)</sup>

- helper per la gestione di password / account
- helper SSH
- helper mediati da PolicyKit / D-Bus
- daemon desktop root che espongono metodi D-Bus

## YAMA come gate per gli exploit

`kernel.yama.ptrace_scope` è un gate pratico importante per l'abuso della famiglia ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: comportamento ptrace classico con lo stesso UID
- `1`: in genere consente il tracing da parent a child, mantenendo raggiungibili alcuni public exploit path
- `2`: richiede `CAP_SYS_PTRACE` per l'accesso in stile attach e blocca l'abuso non privilegiato di `pidfd_getfd()` in questo percorso
- `3`: disabilita completamente il ptrace attach fino al reboot

Per questa tecnica, `ptrace_scope=2` è una **mitigazione temporanea** efficace perché interrompe il public `pidfd_getfd()` exploitation path restituendo `-EPERM` agli utenti non privilegiati.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Idee per il rilevamento / la revisione

Durante l'audit di software Linux privilegiato, cercare queste combinazioni:

- **processo child privilegiato** + **parent controllato dall'attacker**.<sup>[[2]](#references)[[4]](#references)</sup>
- accesso temporaneo a **file aperti di valore**
- accesso temporaneo a **channel D-Bus/systemd autenticati**.<sup>[[2]](#references)</sup>
- decisioni di sicurezza che riutilizzano l'**autorizzazione in stile ptrace** al di fuori del `ptrace(2)` classico
- API del kernel in grado di **duplicare, ereditare o riesportare** FD privilegiati esistenti

Durante l'audit del kernel, considerare ad alto rischio qualsiasi percorso che esegua un'**autorizzazione equivalente a ptrace** durante il **teardown del task**, soprattutto se il successo fornisce accesso diretto a `task->files` o ad altre risorse di processo già autorizzate.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Escalation locale dei privilegi a root e divulgazione di credenziali nel percorso ptrace del kernel Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Avviso TXT di Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Pagina del manuale pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentazione Yama del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Pagina del manuale pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
