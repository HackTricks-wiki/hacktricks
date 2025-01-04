# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Le code de **dyld est open source** et peut être trouvé sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et peut être téléchargé en tar en utilisant une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Processus Dyld**

Jetez un œil à la façon dont Dyld charge des bibliothèques à l'intérieur des binaires dans :

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

C'est comme le [**LD_PRELOAD sur Linux**](../../../../linux-hardening/privilege-escalation/index.html#ld_preload). Cela permet d'indiquer à un processus qui va être exécuté de charger une bibliothèque spécifique à partir d'un chemin (si la variable d'environnement est activée)

Cette technique peut également être **utilisée comme une technique ASEP** car chaque application installée a un plist appelé "Info.plist" qui permet **l'attribution de variables environnementales** en utilisant une clé appelée `LSEnvironmental`.

> [!NOTE]
> Depuis 2012, **Apple a considérablement réduit le pouvoir** de **`DYLD_INSERT_LIBRARIES`**.
>
> Allez dans le code et **vérifiez `src/dyld.cpp`**. Dans la fonction **`pruneEnvironmentVariables`**, vous pouvez voir que les variables **`DYLD_*`** sont supprimées.
>
> Dans la fonction **`processRestricted`**, la raison de la restriction est définie. En vérifiant ce code, vous pouvez voir que les raisons sont :
>
> - Le binaire est `setuid/setgid`
> - Existence de la section `__RESTRICT/__restrict` dans le binaire macho.
> - Le logiciel a des droits (runtime durci) sans le droit [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Vérifiez les **droits** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`
>
> Dans des versions plus récentes, vous pouvez trouver cette logique dans la deuxième partie de la fonction **`configureProcessRestrictions`**. Cependant, ce qui est exécuté dans les versions plus récentes est les **vérifications initiales de la fonction** (vous pouvez supprimer les ifs liés à iOS ou à la simulation car ceux-ci ne seront pas utilisés dans macOS).

### Validation de la bibliothèque

Même si le binaire permet d'utiliser la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, si le binaire vérifie la signature de la bibliothèque à charger, il ne chargera pas une bibliothèque personnalisée.

Pour charger une bibliothèque personnalisée, le binaire doit avoir **l'un des droits suivants** :

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binaire **ne devrait pas** avoir le **drapeau de runtime durci** ou le **drapeau de validation de bibliothèque**.

Vous pouvez vérifier si un binaire a un **runtime durci** avec `codesign --display --verbose <bin>` en vérifiant le drapeau runtime dans **`CodeDirectory`** comme : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une bibliothèque si elle est **signée avec le même certificat que le binaire**.

Trouvez un exemple sur comment (ab)user de cela et vérifiez les restrictions dans :

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> N'oubliez pas que **les restrictions de validation de bibliothèque précédentes s'appliquent également** pour effectuer des attaques de détournement de Dylib.

Comme sous Windows, sous MacOS, vous pouvez également **détourner des dylibs** pour faire **exécuter** **du code** **arbitraire** par des **applications** (en fait, cela pourrait ne pas être possible pour un utilisateur régulier car vous pourriez avoir besoin d'une autorisation TCC pour écrire à l'intérieur d'un bundle `.app` et détourner une bibliothèque).\
Cependant, la façon dont les applications **MacOS** **chargent** des bibliothèques est **plus restreinte** que sous Windows. Cela implique que les développeurs de **malware** peuvent toujours utiliser cette technique pour **la furtivité**, mais la probabilité de pouvoir **en abuser pour élever les privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de trouver que les **binaires MacOS indiquent le chemin complet** vers les bibliothèques à charger. Et deuxièmement, **MacOS ne recherche jamais** dans les dossiers du **$PATH** pour les bibliothèques.

La **partie principale** du **code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Il existe **4 commandes d'en-tête différentes** qu'un binaire macho peut utiliser pour charger des bibliothèques :

- La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger un dylib.
- La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si le dylib n'est pas trouvé, l'exécution continue sans aucune erreur.
- La commande **`LC_REEXPORT_DYLIB`** proxy (ou ré-exporte) les symboles d'une bibliothèque différente.
- La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux bibliothèques dépendent l'une de l'autre (ce qui est appelé une _dépendance ascendante_).

Cependant, il existe **2 types de détournement de dylib** :

- **Bibliothèques liées faibles manquantes** : Cela signifie que l'application essaiera de charger une bibliothèque qui n'existe pas configurée avec **LC_LOAD_WEAK_DYLIB**. Ensuite, **si un attaquant place un dylib là où il est attendu, il sera chargé**.
- Le fait que le lien soit "faible" signifie que l'application continuera à s'exécuter même si la bibliothèque n'est pas trouvée.
- Le **code lié** à cela se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` où `lib->required` est seulement `false` lorsque `LC_LOAD_WEAK_DYLIB` est vrai.
- **Trouvez des bibliothèques liées faibles** dans les binaires avec (vous avez plus tard un exemple sur comment créer des bibliothèques de détournement) :
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configuré avec @rpath** : Les binaires Mach-O peuvent avoir les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **bibliothèques** vont être **chargées** à partir de **différents répertoires**.
- **`LC_RPATH`** contient les chemins de certains dossiers utilisés pour charger des bibliothèques par le binaire.
- **`LC_LOAD_DYLIB`** contient le chemin vers des bibliothèques spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs dans **`LC_RPATH`**. S'il y a plusieurs chemins dans **`LC_RPATH`**, tous seront utilisés pour rechercher la bibliothèque à charger. Exemple :
- Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`. Les deux dossiers vont être utilisés pour charger `library.dylib`**.** Si la bibliothèque n'existe pas dans `[...]/v1/` et qu'un attaquant pouvait la placer là pour détourner le chargement de la bibliothèque dans `[...]/v2/` car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est suivi.
- **Trouvez des chemins rpath et des bibliothèques** dans les binaires avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`** : Est le **chemin** vers le répertoire contenant le **fichier exécutable principal**.
>
> **`@loader_path`** : Est le **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la commande de chargement.
>
> - Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement le **même** que **`@executable_path`**.
> - Lorsqu'il est utilisé dans un **dylib**, **`@loader_path`** donne le **chemin** vers le **dylib**.

La façon d'**élever les privilèges** en abusant de cette fonctionnalité serait dans le cas rare où une **application** exécutée **par** **root** **cherche** une **bibliothèque dans un dossier où l'attaquant a des permissions d'écriture.**

> [!TIP]
> Un bon **scanner** pour trouver des **bibliothèques manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou une [**version CLI**](https://github.com/pandazheng/DylibHijack).\
> Un bon **rapport avec des détails techniques** sur cette technique peut être trouvé [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Exemple**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> N'oubliez pas que **les restrictions de validation de bibliothèque précédentes s'appliquent également** pour effectuer des attaques de détournement de Dlopen.

D'après **`man dlopen`** :

- Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit simplement d'un nom de feuille), **dlopen() fera une recherche**. Si **`$DYLD_LIBRARY_PATH`** a été défini au lancement, dyld regardera d'abord dans ce répertoire. Ensuite, si le fichier macho appelant ou l'exécutable principal spécifient un **`LC_RPATH`**, alors dyld regardera dans ces répertoires. Ensuite, si le processus est **non restreint**, dyld recherchera dans le **répertoire de travail actuel**. Enfin, pour les anciens binaires, dyld essaiera quelques solutions de secours. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** a été défini au lancement, dyld recherchera dans **ces répertoires**, sinon, dyld regardera dans **`/usr/local/lib/`** (si le processus est non restreint), puis dans **`/usr/lib/`** (cette info a été tirée de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(si non restreint)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si non restreint)
6. `/usr/lib/`

> [!CAUTION]
> S'il n'y a pas de slash dans le nom, il y aurait 2 façons de faire un détournement :
>
> - Si un **`LC_RPATH`** est **écrivable** (mais la signature est vérifiée, donc pour cela, vous devez également que le binaire soit non restreint)
> - Si le binaire est **non restreint** et qu'il est alors possible de charger quelque chose depuis le CWD (ou en abusant de l'une des variables d'environnement mentionnées)

- Lorsque le chemin **ressemble à un chemin de framework** (par exemple, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** a été défini au lancement, dyld regardera d'abord dans ce répertoire pour le **chemin partiel du framework** (par exemple, `foo.framework/foo`). Ensuite, dyld essaiera le **chemin fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera quelques solutions de secours. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** a été défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera **`/Library/Frameworks`** (sur macOS si le processus est non restreint), puis **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si non restreint)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si non restreint)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Si un chemin de framework, la façon de le détourner serait :
>
> - Si le processus est **non restreint**, en abusant du **chemin relatif depuis CWD** les variables d'environnement mentionnées (même si cela n'est pas dit dans la documentation si le processus est restreint, les variables d'environnement DYLD\_\* sont supprimées)

- Lorsque le chemin **contient un slash mais n'est pas un chemin de framework** (c'est-à-dire un chemin complet ou un chemin partiel vers un dylib), dlopen() regarde d'abord (si défini) dans **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs (mais seulement pour les processus non restreints)). Enfin, pour les anciens binaires, dyld essaiera des solutions de secours. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** a été défini au lancement, dyld recherchera dans ces répertoires, sinon, dyld regardera dans **`/usr/local/lib/`** (si le processus est non restreint), puis dans **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si non restreint)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si non restreint)
5. `/usr/lib/`

> [!CAUTION]
> S'il y a des slashes dans le nom et que ce n'est pas un framework, la façon de le détourner serait :
>
> - Si le binaire est **non restreint** et qu'il est alors possible de charger quelque chose depuis le CWD ou `/usr/local/lib` (ou en abusant de l'une des variables d'environnement mentionnées)

> [!NOTE]
> Note : Il n'y a **pas** de fichiers de configuration pour **contrôler la recherche de dlopen**.
>
> Note : Si l'exécutable principal est un **binaire set\[ug]id ou signé avec des droits**, alors **toutes les variables d'environnement sont ignorées**, et seul un chemin complet peut être utilisé ([vérifiez les restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) pour plus d'infos détaillées)
>
> Note : Les plateformes Apple utilisent des fichiers "universels" pour combiner des bibliothèques 32 bits et 64 bits. Cela signifie qu'il n'y a **pas de chemins de recherche séparés pour 32 bits et 64 bits**.
>
> Note : Sur les plateformes Apple, la plupart des dylibs du système d'exploitation sont **combinés dans le cache dyld** et n'existent pas sur le disque. Par conséquent, appeler **`stat()`** pour pré-vérifier si un dylib du système d'exploitation existe **ne fonctionnera pas**. Cependant, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.

**Vérifiez les chemins**

Vérifions toutes les options avec le code suivant :
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Si vous le compilez et l'exécutez, vous pouvez voir **où chaque bibliothèque a été recherchée sans succès**. De plus, vous pourriez **filtrer les journaux FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Détournement de chemin relatif

Si un **binaire/app privilégié** (comme un SUID ou un binaire avec des droits puissants) charge une bibliothèque de **chemin relatif** (par exemple en utilisant `@executable_path` ou `@loader_path`) et a **la validation de bibliothèque désactivée**, il pourrait être possible de déplacer le binaire vers un emplacement où l'attaquant pourrait **modifier la bibliothèque chargée par le chemin relatif**, et en abuser pour injecter du code dans le processus.

## Élaguer les variables d'environnement `DYLD_*` et `LD_LIBRARY_PATH`

Dans le fichier `dyld-dyld-832.7.1/src/dyld2.cpp`, il est possible de trouver la fonction **`pruneEnvironmentVariables`**, qui supprimera toute variable d'environnement qui **commence par `DYLD_`** et **`LD_LIBRARY_PATH=`**.

Elle mettra également à **null** spécifiquement les variables d'environnement **`DYLD_FALLBACK_FRAMEWORK_PATH`** et **`DYLD_FALLBACK_LIBRARY_PATH`** pour les binaires **suid** et **sgid**.

Cette fonction est appelée depuis la fonction **`_main`** du même fichier si l'on cible OSX comme ceci :
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
et ces indicateurs booléens sont définis dans le même fichier dans le code :
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Ce qui signifie essentiellement que si le binaire est **suid** ou **sgid**, ou a un segment **RESTRICT** dans les en-têtes ou a été signé avec le drapeau **CS_RESTRICT**, alors **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** est vrai et les variables d'environnement sont supprimées.

Notez que si CS_REQUIRE_LV est vrai, alors les variables ne seront pas supprimées mais la validation de la bibliothèque vérifiera qu'elles utilisent le même certificat que le binaire original.

## Vérifier les restrictions

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Section `__RESTRICT` avec le segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime durci

Créez un nouveau certificat dans le trousseau et utilisez-le pour signer le binaire :
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Notez que même s'il existe des binaires signés avec les drapeaux **`0x0(none)`**, ils peuvent obtenir le drapeau **`CS_RESTRICT`** dynamiquement lors de leur exécution et donc cette technique ne fonctionnera pas avec eux.
>
> Vous pouvez vérifier si un processus a ce drapeau avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> puis vérifier si le drapeau 0x800 est activé.

## Références

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. Par Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
