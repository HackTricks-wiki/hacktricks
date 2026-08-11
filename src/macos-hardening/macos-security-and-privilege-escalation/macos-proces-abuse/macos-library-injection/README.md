# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Le code de **dyld est open source** et peut être trouvé sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et téléchargé sous forme d'archive tar via une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Processus Dyld**

Consultez la manière dont Dyld charge les libraries à l'intérieur des binaires dans :


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Cela fonctionne comme [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Cela permet d'indiquer à un processus qui va être exécuté de charger une library spécifique depuis un chemin (si la variable d'environnement est activée)<sup>[[4]](#references)</sup>

Cette technique peut également être **utilisée comme technique ASEP**, car chaque application installée possède un plist appelé "Info.plist" qui permet **d'assigner des variables d'environnement** à l'aide d'une clé appelée `LSEnvironmental`.

> [!TIP]
> Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**. Un processus est considéré comme **restreint** — et `dyld` supprime alors toutes les variables `DYLD_*` de son environnement — lorsque l'une des conditions suivantes est remplie :
>
> - Le binaire est `setuid/setgid`
> - Le Mach-O possède une section **`__RESTRICT/__restrict`**
> - Le binaire est signé avec le hardened runtime et AMFI ne lui accorde pas les permissions "path/print variables", c'est-à-dire qu'il lui manque [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Vérifiez les **entitlements** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`
>
> Dans le `dyld` actuel, cette décision n'est plus prise par `dyld` seul : `ProcessConfig::Security::Security()` interroge **AMFI** via `amfi_check_dyld_policy_self()`, puis appelle `pruneEnvVars()`. Le code exact est expliqué dans [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) ci-dessous.

### Library Validation

Même si le binaire autorise la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, il ne chargera pas de library personnalisée s'il valide la signature de la library.

Pour charger une library personnalisée, le binaire doit disposer de **l'un des entitlements suivants** :

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binaire **ne doit pas** posséder le **hardened runtime flag** ou le **library validation flag**.

Vous pouvez vérifier si un binaire possède le **hardened runtime** avec `codesign --display --verbose <bin>` en vérifiant le runtime flag dans **`CodeDirectory`**, comme dans : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une library si elle est **signée avec le même certificat que le binaire**.

Trouvez un exemple d'utilisation (abusive) de cette technique et vérifiez les restrictions dans :


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** aux attaques de Dylib hijacking.

Comme sous Windows, sur MacOS il est également possible de **hijack des dylibs** afin de faire **exécuter** aux **applications** du **code** **arbitraire** (en réalité, cela pourrait ne pas être possible depuis un utilisateur standard, car une permission TCC peut être nécessaire pour écrire dans un bundle `.app` et hijack une library).\
Cependant, la manière dont les applications **MacOS chargent** les libraries est **plus restreinte** que sous Windows. Cela signifie que les développeurs de **malware** peuvent toujours utiliser cette technique à des fins de **stealth**, mais la probabilité de pouvoir **abuser de cette technique pour escalader les privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de constater que les binaires **MacOS indiquent le chemin complet** des libraries à charger. Ensuite, **MacOS ne recherche jamais** les libraries dans les dossiers du **$PATH**.

La partie **principale** du **code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Un binaire macho peut utiliser **4 commandes d'en-tête** différentes pour charger des libraries :

- La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger une dylib.
- La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib n'est pas trouvée, l'exécution continue sans erreur.
- La commande **`LC_REEXPORT_DYLIB`** proxy (ou réexporte) les symboles d'une autre library.
- La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux libraries dépendent l'une de l'autre (ce que l'on appelle une _upward dependency_).

Cependant, il existe **2 types de Dylib hijacking** :

- **Missing weak linked libraries** : cela signifie que l'application tentera de charger une library inexistante configurée avec **LC_LOAD_WEAK_DYLIB**. Ensuite, **si un attaquant place une dylib à l'endroit prévu, elle sera chargée**.
- Le fait que le lien soit "weak" signifie que l'application continuera de s'exécuter même si la library n'est pas trouvée.
- Le **code associé** se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, où `lib->required` vaut `false` uniquement lorsque `LC_LOAD_WEAK_DYLIB` est true.
- **Trouvez les libraries faiblement liées** dans les binaires avec (vous trouverez plus loin un exemple de création de libraries de hijacking) :
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configuré avec @rpath** : les binaires Mach-O peuvent posséder les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **libraries** seront **chargées** depuis **différents répertoires**.
- **`LC_RPATH`** contient les chemins de certains dossiers utilisés par le binaire pour charger des libraries.
- **`LC_LOAD_DYLIB`** contient le chemin vers les libraries spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs de **`LC_RPATH`**. S'il existe plusieurs chemins dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la library à charger. Exemple :
- Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`. Les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la library n'existe pas dans `[...]/v1/` et qu'un attaquant peut l'y placer, il peut hijack le chargement de la library dans `[...]/v2/`, car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est respecté.
- **Trouvez les chemins rpath et les libraries** dans les binaires avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`** : correspond au **chemin** vers le répertoire contenant le **fichier exécutable principal**.
>
> **`@loader_path`** : correspond au **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la commande de chargement.
>
> - Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement identique à **`@executable_path`**.
> - Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** fournit le **chemin** vers la **dylib**.

La manière d'**escalader les privilèges** en abusant de cette fonctionnalité serait de trouver le rare cas où une **application** exécutée **par** **root** recherche une **library dans un dossier où l'attaquant possède des permissions d'écriture**.

> [!TIP]
> Un **scanner** pratique pour trouver les **libraries manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html), ou sa [**version CLI**](https://github.com/pandazheng/DylibHijack).\
> Vous trouverez [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) un **rapport intéressant contenant des détails techniques** sur cette technique.

**Exemple**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** aux attaques de Dlopen hijacking.

D'après **`man dlopen`** :

- Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit uniquement d'un nom feuille), **dlopen() effectuera une recherche**. Si **`$DYLD_LIBRARY_PATH`** était défini au lancement, dyld recherchera d'abord dans ce répertoire. Ensuite, si le fichier mach-o appelant ou l'exécutable principal spécifie un **`LC_RPATH`**, dyld recherchera dans ces répertoires. Ensuite, si le processus est **unrestricted**, dyld recherchera dans le répertoire de travail actuel. Enfin, pour les anciens binaires, dyld essaiera certains chemins de fallback. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans **ces répertoires**, sinon dyld recherchera dans **`/usr/local/lib/`** (si le processus est unrestricted), puis dans **`/usr/lib/`** (ces informations proviennent de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (si unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> S'il n'y a aucun slash dans le nom, il existe 2 façons d'effectuer un hijacking :
>
> - Si un **`LC_RPATH`** est **accessible en écriture** (mais la signature est vérifiée ; il faut donc également que le binaire soit unrestricted)
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD (ou d'abuser de l'une des variables d'environnement mentionnées)

- Lorsque le chemin **ressemble à un chemin de framework** (par exemple `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera d'abord dans ce répertoire le **chemin partiel du framework** (par exemple `foo.framework/foo`). Ensuite, dyld essaiera le chemin **fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera certains chemins de fallback. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera dans **`/Library/Frameworks`** (sur macOS si le processus est unrestricted), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> S'il s'agit d'un chemin de framework, la manière de le hijack serait la suivante :
>
> - Si le processus est **unrestricted**, en abusant du **chemin relatif depuis le CWD** ou des variables d'environnement mentionnées (même si cela n'est pas indiqué dans la documentation, les variables d'environnement DYLD\_\* sont supprimées lorsque le processus est restreint)

- Lorsque le chemin **contient un slash mais n'est pas un chemin de framework** (c'est-à-dire un chemin complet ou partiel vers une dylib), dlopen() recherche d'abord (si elle est définie) dans **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs, mais uniquement pour les processus unrestricted). Enfin, pour les anciens binaires, dyld essaiera certains chemins de fallback. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans ces répertoires, sinon dyld recherchera dans **`/usr/local/lib/`** (si le processus est unrestricted), puis dans **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si le nom contient des slashes et qu'il ne s'agit pas d'un framework, la manière de le hijack serait la suivante :
>
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD ou `/usr/local/lib` (ou d'abuser de l'une des variables d'environnement mentionnées)

> [!TIP]
> Remarque : il n'existe **aucun** fichier de configuration permettant de **contrôler la recherche de dlopen**.
>
> Remarque : si l'exécutable principal est un **binaire set\[ug]id ou signé avec des entitlements**, alors **toutes les variables d'environnement sont ignorées**, et seul un chemin complet peut être utilisé ([consultez les restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) pour plus d'informations).
>
> Remarque : les plateformes Apple utilisent des fichiers "universal" pour combiner les libraries 32 bits et 64 bits. Cela signifie qu'il n'existe **aucun chemin de recherche séparé pour les libraries 32 bits et 64 bits**.
>
> Remarque : sur les plateformes Apple, la plupart des dylibs du système sont **intégrées au dyld cache** et n'existent pas sur le disque. Par conséquent, appeler **`stat()`** pour vérifier au préalable si une dylib du système existe **ne fonctionnera pas**. Cependant, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.

**Vérifier les chemins**

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
Si vous le compilez et l’exécutez, vous pouvez voir **où chaque library a été recherchée sans succès**. Vous pouvez également **filtrer les logs FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **binaire/app privilégié** (comme un SUID ou un binaire disposant d'entitlements puissants) **charge une bibliothèque via un chemin relatif** (par exemple en utilisant `@executable_path` ou `@loader_path`) et que **Library Validation est désactivée**, il pourrait être possible de déplacer le binaire vers un emplacement où l'attaquant pourrait **modifier la bibliothèque chargée via le chemin relatif**, puis l'exploiter pour injecter du code dans le processus.

## Prune `DYLD_*` env variables

Les anciennes versions de `dyld` (`dyld2.cpp`) prenaient cette décision in-process avec `issetugid()`, `hasRestrictedSegment()` et `csops(CS_OPS_STATUS)`. Dans **la version actuelle de `dyld`, la décision est déléguée à AMFI**, et le code se trouve dans `ProcessConfig::Security::Security()` dans `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
Deux éléments méritent d’être retenus :

- L’**élagage** se produit uniquement sur **macOS / Mac Catalyst / DriverKit** — et seulement lorsque AMFI n’a accordé **aucune** des autorisations `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La requête AMFI reçoit les propriétés propres à l’exécutable :
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
où `isRestricted()` correspond littéralement à la vérification du segment `__RESTRICT` (`mach_o/UnsafeHeader.cpp`) :<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` supprime ensuite **toutes** les variables dont le nom commence par `DYLD_` et décale les paramètres `apple[]` vers le bas, afin que les processus enfants d’un processus restreint ne les héritent pas non plus :
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* environment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Conséquence pratique : **`DYLD_*` est supprimé lorsque le processus est restreint** — setuid/setgid, une section `__RESTRICT/__restrict`, ou des binaires hardened-runtime/entitled auxquels AMFI refuse d'accorder les flags path/print. Si, au contraire, le processus dispose uniquement de la **library validation** (`CS_REQUIRE_LV`), les variables sont conservées, mais la dylib injectée doit être signée par le **même Team ID** (ou par Apple) ; vous devez donc disposer de l'un des entitlements qui désactivent la library validation pour réellement injecter du code.

Comme la décision relève désormais d'AMFI, le moyen le plus rapide de savoir ce qu'un binaire donné obtiendra consiste à examiner ce sur quoi AMFI se base — les entitlements et les signing flags — plutôt que `dyld` lui-même :
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
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
### Runtime renforcé

Créez un nouveau certificat dans le Keychain et utilisez-le pour signer le binaire :
```bash
# Apply runtime protection
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
> Vous pouvez vérifier si un processus possède ce flag avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)) :
>
> ```bash
> csops -status <pid>
> ```
>
> puis vérifier si le flag 0x800 est activé.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / vérification de `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (démarrage du processus et insertion de bibliothèques)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
