# Abus des bibliothèques partagées et de l’éditeur de liens SUID

{{#include ../../banners/hacktricks-training.md}}

Les binaires SUID sont généralement examinés pour détecter l’exécution directe de commandes, mais les programmes SUID personnalisés peuvent également être vulnérables via l’éditeur de liens dynamique. Le principe est simple : un exécutable privilégié charge du code depuis un chemin ou une configuration qu’un utilisateur moins privilégié peut influencer.<sup>[[1]](#references)</sup>

Cette page se concentre sur des modèles de techniques génériques : bibliothèques manquantes, répertoires de bibliothèques accessibles en écriture, `RPATH`/`RUNPATH`, `LD_PRELOAD` via sudo, configuration de l’éditeur de liens et confusion autour des hardlinks SUID.

Pour en savoir plus sur les en-têtes de programme ELF, la section dynamique et le comportement du chargeur à l’origine de ces vérifications, consultez [Informations de base sur ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Énumération rapide

Commencez par rechercher les fichiers SUID inhabituels et vérifier s’ils sont liés dynamiquement :<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Utilisez `readelf` pour examiner un exécutable inconnu : [`ldd` peut exécuter un interpréteur ELF non fiable](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` affiche les dépendances directes ; vérifiez donc séparément le chemin réellement choisi par le chargeur.<sup>[[1]](#references)[[3]](#references)</sup>

Concentrez-vous sur les emplacements non standard, les chemins d’application personnalisés, les binaires appartenant à root mais situés hors des répertoires gérés par les paquets, ainsi que les dépendances chargées depuis des répertoires accessibles en écriture.<sup>[[1]](#references)</sup>

Vérifications utiles des droits d’écriture :

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Certains binaires SUID personnalisés essaient de charger un shared object inexistant. Si le chemin manquant se trouve dans un répertoire contrôlé par l’attaquant, le binaire peut charger du code fourni par l’attaquant avec les privilèges de l’utilisateur effectif.<sup>[[1]](#references)</sup>

La même limite s’applique à un **binaire personnalisé autorisé via sudo** lorsqu’il appelle `dlopen()` sur un chemin `.so` absolu situé dans un répertoire personnel ou de configuration où l’appelant peut écrire. Ce chargement tardif de bibliothèque peut ne pas apparaître dans `ldd` ni dans les entrées ELF `NEEDED`. Une inspection limitée avec `strings` ou le traçage d’une invocation **sans privilèges** peut révéler le chemin recherché ; un mot de passe applicatif ou un choix de menu peut conditionner cette recherche. Vérifiez la règle sudo effective, le chemin exact et les permissions du répertoire parent, ainsi que le fait que l’invocation privilégiée atteigne cette recherche, avant de considérer cela comme une élévation de privilèges. N’invoquez pas la cible sudo dans le seul but de l’énumérer.

Trouvez les recherches de bibliothèques infructueuses avec le filtre d’appels système de `strace` :<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Si le binaire recherche `libexample.so` dans un chemin accessible en écriture, une bibliothèque de démonstration minimale peut utiliser un constructeur. Veillez à ce que la preuve d’impact reste inoffensive pendant la validation :<sup>[[6]](#references)</sup>

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

La condition exploitable ne se limite pas à l’absence de bibliothèque. L’attaquant doit pouvoir placer un objet partagé compatible à un chemin que le loader privilégié acceptera.<sup>[[1]](#references)</sup>

## Répertoire de bibliothèques accessible en écriture

Parfois, toutes les dépendances sont présentes, mais l’un des répertoires utilisés pour les résoudre est accessible en écriture. Cela peut permettre de remplacer une bibliothèque chargée ou d’en placer une portant le même nom, mais prioritaire.<sup>[[1]](#references)</sup>

La même vérification s’applique à un ELF personnalisé **autorisé via sudo**, même si l’ELF n’a pas de bit SUID et que le compte RunAs autorisé n’est pas root. Comparez ses entrées `DT_NEEDED` au chemin de bibliothèque que le loader résoudra ; vérifiez ensuite si l’utilisateur peut écrire dans ce fichier ou le remplacer via un répertoire parent accessible en écriture et en recherche. Confirmez la règle sudo exacte pour RunAs, les liens symboliques et les ACL, la politique du loader, ainsi que le fait que le processus cible charge la bibliothèque avec le compte disposant de privilèges supérieurs. Un fichier `.so` accessible en écriture ou un nom de dépendance constitue seulement une piste ; inspectez les métadonnées sans exécuter la commande sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Vérifiez les chemins des dépendances :<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Si le répertoire est accessible en écriture, validez cela dans un labo avec une approche qui préserve les copies. Remplacer des bibliothèques système sur un hôte actif peut laisser des processus qui démarrent simultanément avec des versions incohérentes des bibliothèques.<sup>[[8]](#references)</sup>

### Bibliothèques accessibles en écriture dans un chroot

Un chroot seul ne ferme pas les descripteurs de fichiers hérités et ne confine pas tous les accès au système de fichiers. Si un sandbox laisse un descripteur de répertoire pointant en dehors de sa nouvelle racine, et que le processus emprisonné peut déréférencer ce descripteur (par exemple via une entrée `/proc/<pid>/fd/` accessible), les chemins de l'hôte peuvent rester accessibles. Il s'agit d'un problème de frontière du système de fichiers ; cela ne confère pas, à lui seul, les privilèges root.<sup>[[11]](#references)[[12]](#references)</sup>

Vérifiez séparément si l'utilisateur emprisonné peut écrire dans un répertoire de bibliothèques qu'un **exécutable SUID root de l'hôte** utilisera lorsqu'il sera lancé depuis le chroot. Le chargeur résout les dépendances dans la vue du système de fichiers du processus ; une bibliothèque contrôlée par l'attaquant à cet emplacement peut donc s'exécuter avec l'identité effective du programme SUID. Confirmez l'exécutable exact, son bit SUID et la politique de montage, la cible du descripteur et les permissions d'accès, le chemin de recherche des bibliothèques du chroot, ainsi que la possibilité pour le programme d'accéder réellement à l'exécutable de l'hôte. Une file capability sur le lanceur du sandbox, un chroot accessible en écriture ou un binaire SUID de l'hôte constituent uniquement des pistes ; la chaîne complète dépend de l'implémentation du sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH et RUNPATH

`RPATH` et `RUNPATH` sont des entrées de la section dynamique qui indiquent au chargeur où rechercher des bibliothèques. Elles sont dangereuses dans les programmes SUID lorsqu'elles pointent vers des répertoires accessibles en écriture par l'attaquant.<sup>[[1]](#references)</sup>

Détectez-les :<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Exemple de sortie risquée :

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Si `/opt/app/lib` est accessible en écriture et que le binaire a besoin de `libcustom.so`, l’attaquant peut être en mesure d’y placer un `libcustom.so` malveillant :<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` et `RUNPATH` ne sont pas identiques dans tous les détails de résolution, mais pour l'analyse d'une élévation de privilèges, la question pratique est la même : le binaire SUID recherche-t-il une bibliothèque dans un répertoire accessible en écriture à un attaquant ?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH et SUID

Pour les programmes normaux, `LD_PRELOAD` et `LD_LIBRARY_PATH` peuvent forcer ou influencer le chargement des objets partagés. Pour les programmes SUID, le chargeur dynamique passe normalement en mode d'exécution sécurisé et ignore les variables d'environnement dangereuses.<sup>[[1]](#references)</sup>

Cela signifie qu'un binaire SUID standard n'est généralement pas vulnérable simplement parce que l'utilisateur peut définir `LD_PRELOAD` :<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

L’exception courante est une règle sudo qui autorise l’assignation d’une variable d’environnement sur la ligne de commande pour la cible, par exemple une balise `SETENV` ou une option `setenv` applicable. Si la cible est liée dynamiquement et que sudo accepte `LD_PRELOAD=/path/to/library`, la cible peut charger du code contrôlé par l’appelant. Vérifiez la règle effective et l’identité de la cible. Ajouter simplement `LD_PRELOAD` à `env_keep` ne suffit pas sur les systèmes où le chargeur dynamique supprime un `LD_PRELOAD` hérité avant le démarrage du processus `sudo` SUID ; sudo évalue une assignation sur la ligne de commande après son propre démarrage.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Ne confondez pas ces cas ; les règles du loader et de la politique sudo ci-dessus permettent de les distinguer :<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` sur un binaire SUID normal : généralement bloqué par l’exécution sécurisée.
- `LD_PRELOAD` accepté comme affectation en ligne de commande sudo pour une cible privilégiée liée dynamiquement : potentiellement exploitable.
- `.so` manquant dans un chemin accessible en écriture : exploitable lorsque le binaire SUID charge naturellement ce chemin.
- `RPATH`/`RUNPATH` vers un répertoire accessible en écriture : exploitable lorsqu’une bibliothèque requise peut être contrôlée.
- Accès en écriture à `/etc/ld.so.preload` ou à la configuration du linker : impact à l’échelle du système et élevé.

## Configuration du linker

`ld.so` utilise le cache du linker et `/etc/ld.so.preload` ; `ldconfig` construit ce cache à partir de `/etc/ld.so.conf` et des fichiers qu’il inclut, généralement ceux de `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Vérifications prioritaires :

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Une configuration de l’éditeur de liens modifiable est généralement plus grave qu’un seul binaire SUID vulnérable, car elle peut affecter de nombreux processus liés dynamiquement. `/etc/ld.so.preload` est particulièrement dangereux, car il peut forcer le chargement d’un objet partagé dans des processus privilégiés.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Les hardlinks peuvent faire apparaître le même inode SUID sous plusieurs noms.<sup>[[9]](#references)</sup> Cela permet de dissimuler un helper privilégié, de compliquer le nettoyage ou de contourner une vérification naïve basée sur les chemins.

Rechercher les fichiers SUID ayant plusieurs liens :<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspectez tous les chemins vers le même inode :<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

L’abus ne consiste pas à ce qu’un hardlink modifie les permissions. Il s’agit d’une confusion de chemins : un inode privilégié peut être accessible via un nom auquel les défenseurs ou les scripts ne s’attendent pas.<sup>[[9]](#references)</sup> Pour en savoir plus sur les inodes et le fonctionnement des hardlinks, consultez [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notes défensives

- Gardez les binaires SUID aussi peu nombreux que possible, audités et gérés par les paquets lorsque c’est possible.
- Évitez les entrées `RPATH`/`RUNPATH` pointant vers des répertoires accessibles en écriture ou gérés par une application.<sup>[[1]](#references)[[8]](#references)</sup>
- Assurez-vous que les répertoires de bibliothèques appartiennent à root et ne sont pas accessibles en écriture aux utilisateurs ordinaires.<sup>[[8]](#references)</sup>
- Ne préservez pas `LD_PRELOAD`, `LD_LIBRARY_PATH` ni les variables de linker similaires via sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Surveillez `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` et les fichiers SUID inattendus.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Examinez les fichiers SUID dotés de hardlinks et enquêtez sur les wrappers SUID personnalisés situés en dehors des chemins système standard.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — page du manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — page du manuel Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (utilitaires binaires GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — page du manuel Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — page du manuel Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Attributs communs (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — page du manuel Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Renforcement du linker dynamique (bibliothèque C GNU)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Liens physiques (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (utilitaires binaires GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — page du manuel Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — page du manuel Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
