# Linux ptrace exit-race `pidfd_getfd()` FD theft

Un utile **Linux kernel privesc pattern** consiste nel trasformare un **ptrace authorization bug** in un **file descriptor theft** da un processo privilegiato.

Nel case study di Qualys su `__ptrace_may_access()` (CVE-2026-46333), l'attacker esegue una race su un **privileged process che sta terminando o abbandonando le credenziali** e usa `pidfd_getfd()` per duplicare un FD nel processo dell'attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` duplica un file descriptor da un altro processo, ma prima verifica i permessi in stile ptrace rispetto al target.<sup>[[3]](#references)</sup> Se tale autorizzazione viene concessa erroneamente durante una **teardown window**, un attacker non privilegiato può copiare:

- FD per **sensitive files** già aperti da un helper privilegiato
- FD per **authenticated IPC channels** già autorizzati come root

Questo trasforma un authorization bug lato kernel in una primitiva userspace molto pratica.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

L'attacco **non** richiede un bug nell'helper privilegiato stesso. L'helper deve solo mantenere temporaneamente qualcosa di prezioso:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una connessione D-Bus / systemd privilegiata
- qualsiasi altro secret già aperto o authorized channel

Una volta duplicato nel processo dell'attacker, il duplicato fa riferimento alla stessa open file description, quindi le letture successive o le richieste IPC usano l'FD già aperto invece di riaprire il pathname originale o avviare un nuovo authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Identificare un **setuid / setgid / file-capability binary** o un **root daemon** che apre file sensibili o mantiene utili connessioni IPC.<sup>[[2]](#references)</sup>
2. Ottenere una relazione che soddisfi i controlli della ptrace policy pertinenti per il target path (ad esempio, essere il **parent** di un privileged child generato con impostazioni YAMA permissive).<sup>[[2]](#references)[[4]](#references)</sup>
3. Eseguire una race sul processo mentre sta **terminando**, **abbandonando le credenziali** o entrando altrimenti in uno stato in cui l'accesso ptrace dovrebbe essere diventato non disponibile.<sup>[[2]](#references)</sup>
4. Usare `pidfd_open()` + `pidfd_getfd()` per duplicare il target FD durante la stretta authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Riutilizzare l'FD rubato dal contesto non privilegiato.<sup>[[2]](#references)</sup>
- `read()` dei secret da un privileged file descriptor
- inviare richieste attraverso un authenticated IPC channel rubato per ottenere **azioni lato root**

Forma minima della primitiva.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Obiettivi pratici da sottoporre ad audit

Dare priorità ai binari e ai daemon che, anche solo brevemente, fanno una di queste cose:<sup>[[1]](#references)[[2]](#references)</sup>

- aprono file accessibili solo a root prima di completare le transizioni dei privilegi
- si connettono al **system bus** e mantengono un canale già autorizzato
- trasferiscono FD privilegiati oltre i confini degli helper
- eseguono operazioni sensibili per la sicurezza durante il teardown adiacente a `do_exit()`

Buoni candidati per la ricerca:<sup>[[1]](#references)</sup>

- helper per la gestione di password / account
- helper SSH
- helper mediati da PolicyKit / D-Bus
- daemon desktop root che espongono metodi D-Bus

## YAMA come gate per exploit

`kernel.yama.ptrace_scope` è un gate pratico importante per l'abuso della famiglia ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: comportamento classico di ptrace per lo stesso UID
- `1`: in genere consente il tracing parent -> child, mantenendo raggiungibili alcuni public exploit path
- `2`: richiede `CAP_SYS_PTRACE` per l'accesso di tipo attach e blocca l'abuso non privilegiato di `pidfd_getfd()` in questo path
- `3`: disabilita completamente l'attach di ptrace fino al riavvio

Per questa tecnica, `ptrace_scope=2` è una forte **mitigazione temporanea** perché interrompe il public `pidfd_getfd()` exploitation path restituendo `-EPERM` agli utenti non privilegiati.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Idee per il rilevamento / la revisione

Durante l'audit di software Linux privilegiato, cercare queste combinazioni:

- **processo child privilegiato** + **parent controllato dall'attacker**.<sup>[[2]](#references)[[4]](#references)</sup>
- accesso temporaneo a **file open di valore**
- accesso temporaneo a **canali D-Bus/systemd autenticati**.<sup>[[2]](#references)</sup>
- decisioni di sicurezza che riutilizzano l'**autorizzazione di tipo ptrace** al di fuori del `ptrace(2)` classico
- API del kernel in grado di **duplicare, ereditare o riesportare** FD privilegiati esistenti

Durante l'audit del kernel, considerare ad alto rischio qualsiasi path che esegua un'**autorizzazione equivalente a ptrace** durante il **teardown del task**, soprattutto se il successo fornisce accesso diretto a `task->files` o ad altre risorse di processo già autorizzate.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Escalation locale dei privilegi a root e divulgazione di credenziali nel path ptrace del kernel Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT dell'advisory Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Pagina di manuale di pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentazione Yama del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Pagina di manuale di pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
