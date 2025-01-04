# Abusare del Docker Socket per l'Escalation dei Privilegi

{{#include ../../../banners/hacktricks-training.md}}

Ci sono alcune occasioni in cui hai **accesso al docker socket** e vuoi usarlo per **escalare i privilegi**. Alcune azioni potrebbero essere molto sospette e potresti voler evitarle, quindi qui puoi trovare diverse opzioni che possono essere utili per escalare i privilegi:

### Via mount

Puoi **montare** diverse parti del **filesystem** in un container in esecuzione come root e **accedervi**.\
Potresti anche **abusare di un mount per escalare i privilegi** all'interno del container.

- **`-v /:/host`** -> Monta il filesystem dell'host nel container in modo da poter **leggere il filesystem dell'host.**
- Se vuoi **sentirti come se fossi nell'host** ma essere nel container, potresti disabilitare altri meccanismi di difesa usando opzioni come:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Questo è simile al metodo precedente, ma qui stiamo **montando il disco del dispositivo**. Poi, all'interno del container esegui `mount /dev/sda1 /mnt` e puoi **accedere** al **filesystem dell'host** in `/mnt`
- Esegui `fdisk -l` nell'host per trovare il dispositivo `</dev/sda1>` da montare
- **`-v /tmp:/host`** -> Se per qualche motivo puoi **solo montare una directory** dall'host e hai accesso all'interno dell'host. Montala e crea un **`/bin/bash`** con **suid** nella directory montata in modo da poter **eseguirlo dall'host e escalare a root**.

> [!NOTE]
> Nota che forse non puoi montare la cartella `/tmp` ma puoi montare una **differente cartella scrivibile**. Puoi trovare directory scrivibili usando: `find / -writable -type d 2>/dev/null`
>
> **Nota che non tutte le directory in una macchina linux supporteranno il bit suid!** Per controllare quali directory supportano il bit suid esegui `mount | grep -v "nosuid"` Ad esempio, di solito `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` non supportano il bit suid.
>
> Nota anche che se puoi **montare `/etc`** o qualsiasi altra cartella **contenente file di configurazione**, puoi modificarli dal container docker come root per **abusarne nell'host** e escalare i privilegi (magari modificando `/etc/shadow`)

### Uscire dal container

- **`--privileged`** -> Con questa opzione [rimuovi tutta l'isolamento dal container](docker-privileged.md#what-affects). Controlla le tecniche per [uscire dai container privilegiati come root](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Per [escalare abusando delle capacità](../linux-capabilities.md), **concedi quella capacità al container** e disabilita altri metodi di protezione che potrebbero impedire il funzionamento dell'exploit.

### Curl

In questa pagina abbiamo discusso modi per escalare i privilegi usando le opzioni docker, puoi trovare **modi per abusare di questi metodi usando il comando curl** nella pagina:

{{#include ../../../banners/hacktricks-training.md}}
