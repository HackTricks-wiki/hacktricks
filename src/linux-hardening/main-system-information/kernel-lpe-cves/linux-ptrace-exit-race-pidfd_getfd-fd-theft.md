# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un utile **Linux kernel privesc pattern** consiste nel trasformare un **ptrace authorization bug** in un **file descriptor theft** da un processo privilegiato.

Nel case study di Qualys su `__ptrace_may_access()` (CVE-2026-46333), l'attacker esegue una race contro un **privileged process che sta terminando o abbandonando le proprie credenziali** e usa `pidfd_getfd()` per duplicare un FD nel processo dell'attacker.

## Core idea

`pidfd_getfd()` duplica un file descriptor da un altro processo, ma prima verifica i permessi in stile ptrace rispetto al target. Se tale autorizzazione viene concessa erroneamente durante una **teardown window**, un attacker non privilegiato può copiare:

- FD di **sensitive files** già aperti da un helper privilegiato
- FD di **authenticated IPC channels** già autorizzati come root

Questo trasforma un authorization bug lato kernel in una primitiva userspace molto pratica.

## Perché la primitive è pericolosa

L'attacco **non** richiede un bug nell'helper privilegiato. L'helper deve solo mantenere temporaneamente qualcosa di utile:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una connessione privilegiata D-Bus / systemd
- qualsiasi altro secret o authorized channel già aperto

Una volta duplicato nel processo dell'attacker, il kernel applica le operazioni sullo **stolen FD**, non sul pathname originale né tramite un nuovo authentication flow.

## Exploitation pattern

1. Identificare un **setuid / setgid / file-capability binary** o un **root daemon** che apra file sensibili o mantenga connessioni IPC utili.
2. Ottenere una relazione che soddisfi i relativi ptrace policy checks per il target path (ad esempio, essere il **parent** di un privileged child generato con impostazioni YAMA permissive).
3. Eseguire una race contro il processo mentre sta **terminando**, **abbandonando le proprie credenziali** o entrando in uno stato in cui l'accesso ptrace dovrebbe essere diventato non disponibile.
4. Usare `pidfd_open()` + `pidfd_getfd()` per duplicare il target FD durante la breve authorization window.
5. Riutilizzare lo stolen FD dal contesto non privilegiato:
- leggere i secret da un privileged file descriptor con `read()`
- inviare richieste tramite uno stolen authenticated IPC channel per ottenere **root-side actions**

Forma minima della primitive:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Obiettivi pratici da sottoporre ad audit

Dare priorità a binari e daemon che, anche solo brevemente, fanno una di queste cose:

- aprono file accessibili solo a root prima di completare le transizioni di privilegi
- si connettono al **system bus** e mantengono un canale già autorizzato
- trasferiscono FD privilegiati oltre i confini degli helper
- eseguono operazioni sensibili per la sicurezza durante il teardown adiacente a `do_exit()`

Buoni candidati per la ricerca:

- helper per la gestione delle password / degli account
- helper SSH
- helper mediati da PolicyKit / D-Bus
- daemon desktop root che espongono metodi D-Bus

## YAMA come gate di exploit

`kernel.yama.ptrace_scope` è un gate pratico importante per l'abuso della famiglia ptrace:

- `0`: comportamento ptrace classico per lo stesso UID
- `1`: in genere consente il tracing da parent -> child, mantenendo raggiungibili alcuni public exploit path
- `2`: richiede `CAP_SYS_PTRACE` per l'accesso di tipo attach e blocca l'abuso non privilegiato di `pidfd_getfd()` in questo path
- `3`: disabilita completamente il ptrace attach fino al reboot

Per questa tecnica, `ptrace_scope=2` è una forte **mitigazione temporanea**, perché interrompe il public exploitation path di `pidfd_getfd()` restituendo `-EPERM` agli utenti non privilegiati.

## Idee per il rilevamento / la revisione

Durante l'audit di software Linux privilegiato, cercare queste combinazioni:

- **processo child privilegiato** + **parent controllato dall'attaccante**
- accesso temporaneo a **file aperti di valore**
- accesso temporaneo a **canali D-Bus/systemd autenticati**
- decisioni di sicurezza che riutilizzano l'**autorizzazione in stile ptrace** al di fuori del `ptrace(2)` classico
- API del kernel in grado di **duplicare, ereditare o riesportare** FD privilegiati esistenti

Durante l'audit del kernel, considerare ad alto rischio qualsiasi path che esegua un'**autorizzazione equivalente a ptrace** durante il **teardown del task**, soprattutto se il successo fornisce accesso diretto a `task->files` o ad altre risorse di processo già autorizzate.

## Riferimenti

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
