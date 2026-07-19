# Injection de bibliothèques macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Le code de **dyld est open source** et peut être consulté sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et téléchargé sous forme d'archive tar via une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Processus Dyld**

Observez comment Dyld charge les bibliothèques dans les binaires dans :


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Cela ressemble à [**LD_PRELOAD sous Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Cela permet d'indiquer à un processus qui va être exécuté de charger une bibliothèque spécifique depuis un chemin (si la variable d'environnement est activée).

Cette technique peut également être **utilisée comme technique ASEP**, car chaque application installée possède un plist appelé "Info.plist", qui permet **d'assigner des variables d'environnement** à l'aide d'une clé appelée `LSEnvironmental`.

> [!TIP]
> Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**.
>
> Consultez le code et **vérifiez `src/dyld.cpp`**. Dans la fonction **`pruneEnvironmentVariables`**, vous pouvez voir que les variables **`DYLD_*`** sont supprimées.
>
> Dans la fonction **`processRestricted`**, la raison de la restriction est définie. En examinant ce code, vous pouvez voir que les raisons sont les suivantes :
>
> - Le binaire est `setuid/setgid`
> - Présence d'une section `__RESTRICT/__restrict` dans le binaire macho.
> - Le logiciel possède des entitlements (hardened runtime) sans l'entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Vérifiez les **entitlements** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`
>
> Dans les versions plus récentes, vous trouverez cette logique dans la seconde partie de la fonction **`configureProcessRestrictions`.** Cependant, dans les versions récentes, ce sont les vérifications initiales de la fonction qui sont exécutées (vous pouvez supprimer les if liés à iOS ou à la simulation, car ils ne seront pas utilisés dans macOS).

### Validation des bibliothèques

Même si le binaire autorise l'utilisation de la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, si le binaire vérifie la signature de la bibliothèque à charger, il ne chargera pas une bibliothèque personnalisée.

Pour charger une bibliothèque personnalisée, le binaire doit posséder **l'un des entitlements suivants** :

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binaire **ne doit pas** avoir le **hardened runtime flag** ou le **library validation flag**.

Vous pouvez vérifier si un binaire possède le **hardened runtime** avec `codesign --display --verbose <bin>`, en vérifiant le runtime flag dans **`CodeDirectory`**, comme dans : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une bibliothèque si elle est **signée avec le même certificat que le binaire**.

Trouvez un exemple d'utilisation abusive de cette fonctionnalité et de vérification des restrictions dans :


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** pour effectuer des attaques de Dylib hijacking.

Comme sous Windows, sous MacOS vous pouvez également **hijacker des dylibs** afin de faire **exécuter** du **code** **arbitraire** aux **applications** (en réalité, cela peut ne pas être possible depuis un utilisateur standard, car une permission TCC peut être nécessaire pour écrire dans un bundle `.app` et hijacker une bibliothèque).\
Cependant, la manière dont les applications **MacOS** **chargent** les bibliothèques est **plus restrictive** que sous Windows. Cela implique que les développeurs de **malware** peuvent toujours utiliser cette technique à des fins de **stealth**, mais la probabilité de pouvoir **abuser de cette technique pour effectuer une élévation de privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de constater que les binaires **MacOS indiquent le chemin complet** des bibliothèques à charger. Ensuite, **MacOS ne recherche jamais** les bibliothèques dans les dossiers du **$PATH**.

La partie **principale** du **code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`**, dans `ImageLoader.cpp`.

Un binaire macho peut utiliser **4 commandes d'en-tête** différentes pour charger des bibliothèques :

- La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger une dylib.
- La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib n'est pas trouvée, l'exécution continue sans erreur.
- La commande **`LC_REEXPORT_DYLIB`** proxy (ou réexporte) les symboles d'une autre bibliothèque.
- La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux bibliothèques dépendent l'une de l'autre (on parle de _dépendance ascendante_).

Cependant, il existe **2 types de Dylib hijacking** :

- **Bibliothèques weak linked manquantes** : cela signifie que l'application essaiera de charger une bibliothèque inexistante configurée avec **LC_LOAD_WEAK_DYLIB**. Ensuite, **si un attaquant place une dylib à l'endroit attendu, elle sera chargée**.
- Le fait que le lien soit "weak" signifie que l'application continuera de fonctionner même si la bibliothèque n'est pas trouvée.
- Le **code associé** se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, où `lib->required` est uniquement `false` lorsque `LC_LOAD_WEAK_DYLIB` est défini sur true.
- **Trouvez les bibliothèques weak linked** dans les binaires avec (vous trouverez plus loin un exemple de création de bibliothèques de hijacking) :
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurées avec @rpath** : les binaires Mach-O peuvent posséder les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **bibliothèques** seront **chargées** depuis **différents répertoires**.
- **`LC_RPATH`** contient les chemins de certains dossiers utilisés par le binaire pour charger les bibliothèques.
- **`LC_LOAD_DYLIB`** contient le chemin des bibliothèques spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs de **`LC_RPATH`**. S'il existe plusieurs chemins dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la bibliothèque à charger. Exemple :
- Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`, les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la bibliothèque n'existe pas dans `[...]/v1/` et qu'un attaquant peut l'y placer, il pourra hijacker le chargement de la bibliothèque dans `[...]/v2/`, car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est respecté.
- **Trouvez les chemins rpath et les bibliothèques** dans les binaires avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`** : il s'agit du **chemin** vers le répertoire contenant le **fichier exécutable principal**.
>
> **`@loader_path`** : il s'agit du **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la commande de chargement.
>
> - Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement identique à **`@executable_path`**.
> - Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** fournit le **chemin** vers la **dylib**.

La manière d'**élever les privilèges** en abusant de cette fonctionnalité serait le cas rare où une **application** exécutée **par** **root** rechercherait une **bibliothèque dans un dossier où l'attaquant possède des permissions d'écriture**.

> [!TIP]
> Un bon **scanner** pour trouver les **bibliothèques manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou sa [**version CLI**](https://github.com/pandazheng/DylibHijack).\
> Vous trouverez [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) un **rapport présentant des détails techniques** sur cette technique.

**Exemple**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** pour effectuer des attaques de Dlopen hijacking.

D'après **`man dlopen`** :

- Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit uniquement d'un nom de feuille), **dlopen() effectue une recherche**. Si **`$DYLD_LIBRARY_PATH`** était défini au lancement, dyld recherchera d'abord dans ce répertoir**e**. Ensuite, si le fichier mach-o appelant ou l'exécutable principal spécifie un **`LC_RPATH`**, dyld recherchera dans ces répertoires. Ensuite, si le processus est **unrestricted**, dyld recherchera dans le répertoire de travail actuel. Enfin, pour les anciens binaires, dyld essaiera certains chemins de repli. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans **ces répertoires**, sinon dyld recherchera dans **`/usr/local/lib/`** (si le processus est unrestricted), puis dans **`/usr/lib/`** (ces informations proviennent de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> S'il n'y a aucun slash dans le nom, il existe 2 façons d'effectuer un hijacking :
>
> - Si un **`LC_RPATH`** est **inscriptible** (mais la signature est vérifiée, donc le binaire doit également être unrestricted)
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD (ou d'abuser de l'une des variables d'environnement mentionnées)

- Lorsque le chemin **ressemble** à un chemin de framework (par exemple `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera d'abord dans ce répertoire le **chemin partiel du framework** (par exemple `foo.framework/foo`). Ensuite, dyld essaiera le **chemin fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera certains chemins de repli. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera dans **`/Library/Frameworks`** (sur macOS si le processus est unrestricted), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Pour un chemin de framework, la manière de le hijacker serait :
>
> - Si le processus est **unrestricted**, en abusant du **chemin relatif depuis le CWD** ou des variables d'environnement mentionnées (même si cela n'est pas indiqué dans la documentation, les variables d'environnement DYLD\_\* sont supprimées lorsque le processus est restricted)

- Lorsque le chemin **contient un slash mais ne correspond pas à un chemin de framework** (c'est-à-dire un chemin complet ou partiel vers une dylib), dlopen() recherche d'abord (si elle est définie) dans **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs, mais uniquement pour les processus unrestricted). Enfin, pour les anciens binaires, dyld essaiera certains chemins de repli. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans ces répertoires, sinon dyld recherchera dans **`/usr/local/lib/`** (si le processus est unrestricted), puis dans **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si le nom contient des slashes et ne correspond pas à un framework, la manière de le hijacker serait :
>
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD ou **`/usr/local/lib`** (ou d'abuser de l'une des variables d'environnement mentionnées)

> [!TIP]
> Remarque : il n'existe **aucun** fichier de configuration permettant de **contrôler la recherche effectuée par dlopen**.
>
> Remarque : si l'exécutable principal est un **binaire set\[ug]id ou signé avec des entitlements**, toutes les variables d'environnement sont ignorées et seul un chemin complet peut être utilisé ([consultez les restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) pour plus d'informations).
>
> Remarque : les plateformes Apple utilisent des fichiers "universal" pour combiner les bibliothèques 32 bits et 64 bits. Il n'existe donc **aucun chemin de recherche distinct pour les bibliothèques 32 bits et 64 bits**.
>
> Remarque : sur les plateformes Apple, la plupart des dylibs du système sont **intégrées au dyld cache** et n'existent pas sur le disque. Par conséquent, appeler **`stat()`** pour vérifier au préalable si une dylib système existe **ne fonctionnera pas**. Toutefois, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.

**Vérification des chemins**

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
Si vous le compilez et l’exécutez, vous pouvez voir **où chaque bibliothèque a été recherchée sans succès**. Vous pouvez également **filtrer les logs du FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **privileged binary/app** (comme un binaire SUID ou un binaire disposant d'entitlements puissants) **charge** une bibliothèque via un chemin relatif (par exemple avec `@executable_path` ou `@loader_path`) et que la **Library Validation** est désactivée, il pourrait être possible de déplacer le binaire vers un emplacement où l'attaquant pourrait **modifier la bibliothèque chargée via le chemin relatif**, puis l'exploiter pour injecter du code dans le processus.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

Dans le fichier `dyld-dyld-832.7.1/src/dyld2.cpp`, il est possible de trouver la fonction **`pruneEnvironmentVariables`**, qui supprimera toute variable d'environnement qui **commence par `DYLD_`** ainsi que **`LD_LIBRARY_PATH=`**.

Elle définira également spécifiquement sur **null** les variables d'environnement **`DYLD_FALLBACK_FRAMEWORK_PATH`** et **`DYLD_FALLBACK_LIBRARY_PATH`** pour les binaires **suid** et **sgid**.

Cette fonction est appelée depuis la fonction **`_main`** du même fichier si la cible est OSX, comme ceci :
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
et ces indicateurs booléens sont définis dans le même fichier du code :
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
Cela signifie essentiellement que si le binaire est **suid** ou **sgid**, s'il possède un segment **RESTRICT** dans ses en-têtes ou s'il a été signé avec le flag **CS_RESTRICT**, alors **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** est vrai et les variables d'environnement sont supprimées.

Notez que si CS_REQUIRE_LV est vrai, les variables ne seront pas supprimées, mais la validation de la library vérifiera qu'elles utilisent le même certificat que le binaire d'origine.

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
### Section `__RESTRICT` avec segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Créez un nouveau certificat dans le Keychain et utilisez-le pour signer le binaire :
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
> Notez que même s'il existe des binaires signés avec les flags **`0x0(none)`**, ils peuvent obtenir dynamiquement le flag **`CS_RESTRICT`** lors de leur exécution, et cette technique ne fonctionnera donc pas avec eux.
>
> Vous pouvez vérifier si un proc possède ce flag avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> puis vérifier si le flag 0x800 est activé.

## Références

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
