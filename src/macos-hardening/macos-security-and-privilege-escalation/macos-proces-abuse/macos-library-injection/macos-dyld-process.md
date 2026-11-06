# Processus Dyld de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Le véritable **point d’entrée** d’un binaire Mach-o est le linker dynamique, défini dans `LC_LOAD_DYLINKER`, généralement `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Ce linker doit localiser toutes les bibliothèques exécutables, les mapper en mémoire et lier toutes les bibliothèques non paresseuses. Ce n’est qu’après ce processus que le point d’entrée du binaire sera exécuté.

Bien sûr, **`dyld`** n’a aucune dépendance (il utilise des syscalls et des extraits de libSystem).

> [!CAUTION]
> Si ce linker contient une vulnérabilité, comme il est exécuté avant tout binaire (même ceux disposant de privilèges élevés), il serait possible d’**escalader les privilèges**.

### Flux

Dyld sera chargé par **`dyldboostrap::start`**, qui chargera également des éléments comme le **stack canary**. En effet, cette fonction recevra dans son vecteur d’arguments **`apple`** cette valeur et d’autres **valeurs** **sensibles**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** est le point d’entrée de dyld et sa première tâche consiste à exécuter `configureProcessRestrictions()`, qui restreint généralement les variables d’environnement **`DYLD_*`** expliquées dans :<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Ensuite, il mappe le dyld shared cache, qui pré-lie toutes les bibliothèques système importantes, puis mappe les bibliothèques dont dépend le binaire et continue récursivement jusqu’à ce que toutes les bibliothèques requises soient chargées. Par conséquent :

1. il commence par charger les bibliothèques insérées avec `DYLD_INSERT_LIBRARIES` (si cela est autorisé)
2. Ensuite, celles du shared cache
3. Ensuite, celles importées
   1. Puis il continue à importer récursivement les bibliothèques

Une fois toutes les bibliothèques chargées, leurs **initialiseurs** sont exécutés. Ils sont codés avec **`__attribute__((constructor))`**, défini dans `LC_ROUTINES[_64]` (désormais obsolète), ou au moyen d’un pointeur dans une section marquée avec `S_MOD_INIT_FUNC_POINTERS` (généralement : **`__DATA.__MOD_INIT_FUNC`**).

Les terminateurs sont codés avec **`__attribute__((destructor))`** et se trouvent dans une section marquée avec `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Voir aussi : [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Tous les binaires sous macOS sont liés dynamiquement. Ils contiennent donc des sections de stubs qui aident le binaire à accéder au code approprié sur différentes machines et dans différents contextes. Lorsque le binaire est exécuté, c’est dyld qui doit résoudre ces adresses (au moins celles non paresseuses).

Quelques sections de stubs dans le binaire :

- **`__TEXT.__[auth_]stubs`** : Pointeurs provenant des sections `__DATA`
- **`__TEXT.__stub_helper`** : Petit morceau de code invoquant le dynamic linking avec les informations sur la fonction à appeler
- **`__DATA.__[auth_]got`** : Global Offset Table (adresses des fonctions importées, résolues et liées au chargement, car elles sont marquées avec le flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`** : Pointeurs de symboles non paresseux (liés au chargement, car ils sont marqués avec le flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`** : Pointeurs de symboles paresseux (liés au premier accès)

> [!WARNING]
> Notez que les pointeurs préfixés par « auth_ » utilisent une clé de chiffrement propre au processus pour les protéger (PAC). De plus, il est possible d’utiliser l’instruction arm64 `BLRA[A/B]` pour vérifier le pointeur avant de le suivre. Et RETA\[A/B] peut être utilisé à la place d’une adresse RET.\
> En fait, le code dans **`__TEXT.__auth_stubs`** utilisera **`braa`** au lieu de **`bl`** pour appeler la fonction demandée et authentifier le pointeur.
>
> Notez également que les versions actuelles de dyld chargent **tout comme non paresseux**.

### Rechercher les symboles paresseux

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Partie intéressante du désassemblage :

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

On peut voir que le saut pour appeler printf mène à **`__TEXT.__stubs`** :

```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
  0 __text        00000038 0000000100003f60 TEXT
  1 __stubs       0000000c 0000000100003f98 TEXT
  2 __cstring     00000004 0000000100003fa4 DATA
  3 __unwind_info 00000058 0000000100003fa8 DATA
  4 __got         00000008 0000000100004000 DATA
```

Dans le désassemblage de la section **`__stubs`** :

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

vous pouvez voir que nous **sautons à l’adresse de la GOT**, qui, dans ce cas, est résolue de manière non paresseuse et contient l’adresse de la fonction printf.

Dans d’autres cas, au lieu de sauter directement à la GOT, le code peut sauter vers **`__DATA.__la_symbol_ptr`**, qui chargera une valeur représentant la fonction qu’il tente de charger, puis sauter vers **`__TEXT.__stub_helper`**, qui saute vers **`__DATA.__nl_symbol_ptr`**, qui contient l’adresse de **`dyld_stub_binder`**. Cette fonction reçoit en paramètres le numéro de la fonction et une adresse.\
Le binder résout le symbole et met à jour son emplacement dans **`__DATA.__la_symbol_ptr`**. Le stub utilise ensuite ce pointeur résolu lors des appels suivants ; il n’est pas réécrit dans `__TEXT.__stub_helper`.<sup>[[5]](#references)</sup>

> [!TIP]
> Cependant, notez que les versions actuelles de dyld chargent tout de manière non paresseuse.

#### OpCodes de dyld

Enfin, **`dyld_stub_binder`** doit trouver la fonction indiquée et l’écrire à l’adresse appropriée afin de ne pas avoir à la rechercher de nouveau. Pour cela, il utilise des opcodes (une machine à états finis) dans dyld.

## vecteur d’arguments apple\[]

Dans macOS, la fonction principale reçoit en réalité 4 arguments au lieu de 3. Le quatrième s’appelle apple, et chaque entrée est de la forme `key=value`. Par exemple :

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

Résultat:

```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```

> [!TIP]
> Lorsque ces valeurs atteignent la fonction main, les informations sensibles ont déjà été supprimées, sinon il s’agirait d’un leak de données.

Il est possible de voir toutes ces valeurs intéressantes en déboguant avant d’entrer dans main avec :

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Il s’agit d’une structure exportée par dyld qui contient des informations sur son état. On peut la trouver dans le [**code source**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html). Elle contient notamment la version, un pointeur vers le tableau dyld_image_info, vers dyld_image_notifier, indique si le processus est détaché du cache partagé et si l’initialiseur de libSystem a été appelé, ainsi qu’un pointeur vers le propre en-tête Mach de dyld et vers la chaîne de version de dyld...<sup>[[4]](#references)</sup>

## variables d’environnement dyld

### debug dyld

Variables d’environnement intéressantes qui aident à comprendre ce que fait dyld :

- **DYLD_PRINT_LIBRARIES**

Vérifier chaque bibliothèque chargée :

```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```

- **DYLD_PRINT_SEGMENTS**

Vérifiez comment chaque bibliothèque est chargée :

```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```

- **DYLD_PRINT_INITIALIZERS**

Affiche lorsque l'initialiseur de chaque bibliothèque s'exécute :

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Tracer la résolution des bibliothèques à l’exécution

Pour un lancement que vous contrôlez, tracez un candidat `@rpath` ou de bibliothèque faible avant de placer un dylib de remplacement. `DYLD_PRINT_SEARCHING` indique les chemins examinés par dyld, tandis que `DYLD_PRINT_LIBRARIES` affiche les images effectivement chargées. `DYLD_PRINT_LOADERS` distingue un `JustInTimeLoader` d’un `PrebuiltLoader` et indique l’utilisation d’un ensemble de loaders précompilés.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Recherchez la ligne `LC_RPATH` qui identifie l’image ayant fourni un chemin de recherche, puis comparez les candidats `possible path(...)` avec `found: dylib-from-disk`, `found: dylib-from-cache` ou un rejet. Un chemin candidat ne prouve **pas** que la dylib a été chargée. Le premier chemin disque utilisable avant celui de la bibliothèque attendue est celui dont il faut vérifier les droits d’écriture et les [restrictions de library validation](./#library-validation).<sup>[[7]](#references)</sup>

Un loader précompilé peut réutiliser les informations de dépendances enregistrées au lieu de répéter une recherche complète des chemins. Une sortie de recherche clairsemée ne prouve donc pas qu’une image n’a aucune dépendance ; inspectez ses commandes de chargement avec `otool -l` et comparez la liste des bibliothèques.<sup>[[8]](#references)</sup> Ces diagnostics nécessitent également l’autorisation d’affichage des variables de dyld ; une cible protégée peut donc les ignorer entièrement.<sup>[[2]](#references)</sup> Consultez [Dylib Hijacking](./#dylib-hijacking) pour connaître les prérequis d’une bibliothèque de remplacement.

### Autres

Certaines options ci-dessous sont propres aux anciennes versions de dyld. Vérifiez leur prise en charge sur la version cible plutôt que de supposer que chaque variable fonctionne toujours.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Les liaisons paresseuses sont résolues avec les liaisons non paresseuses
- `DYLD_DISABLE_PREFETCH`: Désactiver le préchargement du contenu \_\_DATA et \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Liaisons à un seul niveau
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Chemins de résolution
- `DYLD_INSERT_LIBRARIES`: Charger une bibliothèque spécifique
- `DYLD_PRINT_TO_FILE`: Écrire les informations de débogage de dyld dans un fichier
- `DYLD_PRINT_APIS`: Afficher les appels de l’API libdyld
- `DYLD_PRINT_APIS_APP`: Afficher les appels de l’API libdyld effectués par le processus principal
- `DYLD_PRINT_BINDINGS`: Afficher les symboles lors de leur liaison
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Afficher les liaisons des symboles faibles
- `DYLD_PRINT_CODE_SIGNATURES`: Afficher les opérations d’enregistrement des signatures de code
- `DYLD_PRINT_DOFS`: Afficher les sections au format d’objet D-Trace lors de leur chargement
- `DYLD_PRINT_ENV`: Afficher l’environnement vu par dyld
- `DYLD_PRINT_INTERPOSING`: Afficher les opérations d’interposition
- `DYLD_PRINT_LIBRARIES`: Afficher les bibliothèques chargées
- `DYLD_PRINT_OPTS`: Afficher les options de chargement
- `DYLD_PRINT_REBASINGS` (dyld2): Afficher les opérations de rebasage des symboles
- `DYLD_PRINT_RPATHS` (dyld2): Afficher les expansions de `@rpath`
- `DYLD_PRINT_SEGMENTS`: Afficher les mappages des segments Mach-O
- `DYLD_PRINT_STATISTICS`: Afficher les statistiques de durée
- `DYLD_PRINT_STATISTICS_DETAILS`: Afficher les statistiques détaillées de durée
- `DYLD_PRINT_WARNINGS`: Afficher les messages d’avertissement
- `DYLD_SHARED_CACHE_DIR`: Chemin à utiliser pour le cache des bibliothèques partagées
- `DYLD_SHARED_REGION`: « use », « private », « avoid »
- `DYLD_USE_CLOSURES`: Activer les closures

Il est possible d’en trouver d’autres avec une commande similaire à celle-ci :

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Ou en téléchargeant le projet dyld depuis [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz), puis en exécutant dans le dossier :

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (chemin de démarrage du processus)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (configuration du processus et de la sécurité)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (côté noyau d’`execve`, chargement de dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (structure `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — binding des pointeurs de symboles lazy et non-lazy](https://github.com/meta/fishhook)
- [6] [dyld(1) — diagnostics de l’éditeur de liens dynamique](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — recherche des chemins de bibliothèques à l’exécution](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — chargeurs précompilés et juste-à-temps](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — anciens noms de variables de diagnostic](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
