# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Le code de **dyld est open source** et peut être trouvé sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et peut être téléchargé sous forme d'archive tar via une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Consultez la manière dont Dyld charge les libraries à l'intérieur des binaires dans :


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

C'est l'équivalent de [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Cela permet d'indiquer à un process qui va être exécuté de charger une library spécifique depuis un chemin (si la variable d'environnement est activée).

Cette technique peut également être **utilisée comme technique ASEP**, car chaque application installée possède un plist appelé "Info.plist", qui permet **d'assigner des variables d'environnement** à l'aide d'une clé appelée `LSEnvironmental`.

> [!TIP]
> Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**. Un process est considéré comme **restricted** — et `dyld` supprime alors chaque variable `DYLD_*` de son environnement — lorsque l'une des conditions suivantes est remplie :
>
> - Le binaire est `setuid/setgid`
> - Le Mach-O possède une section **`__RESTRICT/__restrict`**
> - Le binaire est signé avec le hardened runtime et AMFI ne lui accorde pas les permissions "path/print variables", c'est-à-dire qu'il lui manque [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - Vérifiez les **entitlements** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`
>
> Dans `dyld` actuel, cette décision ne dépend plus uniquement de `dyld` : `ProcessConfig::Security::Security()` interroge **AMFI** via `amfi_check_dyld_policy_self()`, puis appelle `pruneEnvVars()`. Le code exact est expliqué dans [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) ci-dessous.

### Library Validation

Même si le binaire autorise l'utilisation de la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, s'il vérifie la signature de la library à charger, il ne chargera pas de library personnalisée.

Pour charger une library personnalisée, le binaire doit disposer de **l'un des entitlements suivants** :

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binaire **ne doit pas** avoir le **hardened runtime flag** ou le **library validation flag**.

Vous pouvez vérifier si un binaire possède le **hardened runtime** avec `codesign --display --verbose <bin>`, en contrôlant le runtime flag dans **`CodeDirectory`**, par exemple : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une library si elle est **signée avec le même certificat que le binaire**.

Trouvez un exemple sur la manière d'abuser de cette fonctionnalité et de vérifier les restrictions dans :


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** aux attaques de Dylib hijacking.

Comme sous Windows, sur macOS il est également possible de **détourner des dylibs** afin de faire **exécuter aux applications** du **code** **arbitraire** (en réalité, cela peut ne pas être possible depuis un utilisateur standard, car une permission TCC peut être nécessaire pour écrire dans un bundle `.app` et détourner une library).\
Cependant, la manière dont les applications **macOS** **chargent** les libraries est **plus restrictive** que sous Windows. Cela signifie que les développeurs de **malware** peuvent toujours utiliser cette technique à des fins de **stealth**, mais la probabilité de pouvoir **l'exploiter pour escalader les privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de constater que les binaires **macOS indiquent le chemin complet** des libraries à charger. Ensuite, **macOS ne recherche jamais** les libraries dans les dossiers du **$PATH**.

La partie **principale du code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Il existe **4 commandes d'en-tête différentes** qu'un binaire macho peut utiliser pour charger des libraries :

- La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger une dylib.
- La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib n'est pas trouvée, l'exécution continue sans erreur.
- La commande **`LC_REEXPORT_DYLIB`** proxy (ou réexporte) les symboles d'une autre library.
- La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux libraries dépendent l'une de l'autre (on parle d'_upward dependency_).

Cependant, il existe **2 types de Dylib hijacking** :

- **Missing weak linked libraries** : cela signifie que l'application tente de charger une library inexistante configurée avec **LC_LOAD_WEAK_DYLIB**. Ensuite, **si un attaquant place une dylib à l'endroit attendu, elle sera chargée**.
- Le fait que le lien soit "weak" signifie que l'application continuera à s'exécuter même si la library n'est pas trouvée.
- Le **code associé** se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, où `lib->required` est uniquement `false` lorsque `LC_LOAD_WEAK_DYLIB` est true.
- **Recherchez les weak linked libraries** dans les binaires avec (vous trouverez plus loin un exemple de création de libraries de hijacking) :
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurées avec @rpath** : les binaires Mach-O peuvent contenir les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **libraries** seront **chargées** depuis **différents répertoires**.
- **`LC_RPATH`** contient les chemins de certains dossiers utilisés par le binaire pour charger des libraries.
- **`LC_LOAD_DYLIB`** contient le chemin vers des libraries spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs de **`LC_RPATH`**. S'il existe plusieurs chemins dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la library à charger. Exemple :
- Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`. Les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la library n'existe pas dans `[...]/v1/`, un attaquant pourrait l'y placer afin de détourner le chargement de la library dans `[...]/v2/`, car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est respecté.
- **Recherchez les chemins rpath et les libraries** dans les binaires avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`** : il s'agit du **chemin** vers le répertoire contenant le **fichier exécutable principal**.
>
> **`@loader_path`** : il s'agit du **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la load command.
>
> - Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement identique à **`@executable_path`**.
> - Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** fournit le **chemin** vers la **dylib**.

La manière d'**escalader les privilèges** en abusant de cette fonctionnalité serait de trouver le rare cas où une **application** exécutée **par** **root** **recherche** une **library dans un dossier où l'attaquant possède des permissions d'écriture**.

> [!TIP]
> Un bon **scanner** pour trouver les **libraries manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou sa [**version CLI**](https://github.com/pandazheng/DylibHijack).\
> Vous trouverez un [**rapport contenant des détails techniques**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) sur cette technique.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** aux attaques de Dlopen hijacking.

Extrait de **`man dlopen`** :

- Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit uniquement d'un nom de feuille), **dlopen() effectue une recherche**. Si **`$DYLD_LIBRARY_PATH`** a été défini au lancement, dyld recherchera d'abord dans ce répertoire. Ensuite, si le fichier mach-o appelant ou l'exécutable principal spécifie un **`LC_RPATH`**, dyld recherchera dans ces répertoires. Ensuite, si le process est **unrestricted**, dyld recherchera dans le répertoire de travail actuel. Enfin, pour les anciens binaires, dyld essaiera certains fallback. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** a été défini au lancement, dyld recherchera dans **ces répertoires**, sinon dyld recherchera dans **`/usr/local/lib/`** (si le process est unrestricted), puis dans **`/usr/lib/`** (ces informations proviennent de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (si unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Si le nom ne contient aucun slash, il existe 2 façons d'effectuer un hijacking :
>
> - Si un **`LC_RPATH`** est **accessible en écriture** (mais la signature est vérifiée, donc le binaire doit également être unrestricted)
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD (ou d'abuser de l'une des variables d'environnement mentionnées)

- Lorsque le chemin **ressemble à** un chemin de framework (par exemple `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** a été défini au lancement, dyld recherchera d'abord dans ce répertoire le **chemin partiel du framework** (par exemple `foo.framework/foo`). Ensuite, dyld essaiera le **chemin fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera certains fallback. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** a été défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera dans **`/Library/Frameworks`** (sur macOS si le process est unrestricted), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> S'il s'agit d'un chemin de framework, la manière de le détourner serait la suivante :
>
> - Si le process est **unrestricted**, exploiter le **chemin relatif depuis le CWD** ou les variables d'environnement mentionnées (même si la documentation ne le précise pas, les variables d'environnement DYLD\_\* sont supprimées lorsque le process est restricted)

- Lorsque le chemin **contient un slash mais n'est pas un chemin de framework** (c'est-à-dire un chemin complet ou partiel vers une dylib), dlopen() recherche d'abord (si elle est définie) dans **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs (mais uniquement pour les process unrestricted)). Enfin, pour les anciens binaires, dyld essaiera certains fallback. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** a été défini au lancement, dyld recherchera dans ces répertoires, sinon dyld recherchera dans **`/usr/local/lib/`** (si le process est unrestricted), puis dans **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si le nom contient des slashs et qu'il ne s'agit pas d'un framework, la manière de le détourner serait la suivante :
>
> - Si le binaire est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD ou `/usr/local/lib` (ou d'abuser de l'une des variables d'environnement mentionnées)

> [!TIP]
> Remarque : il n'existe **aucun** fichier de configuration permettant de **contrôler la recherche de dlopen**.
>
> Remarque : si l'exécutable principal est un **binaire set\[ug]id ou signé avec des entitlements**, toutes les variables d'environnement sont ignorées et seul un chemin complet peut être utilisé ([consultez les restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) pour plus d'informations).
>
> Remarque : les plateformes Apple utilisent des fichiers "universal" pour combiner les libraries 32 bits et 64 bits. Cela signifie qu'il n'existe **aucun chemin de recherche distinct pour les libraries 32 bits et 64 bits**.
>
> Remarque : sur les plateformes Apple, la plupart des dylibs de l'OS sont **regroupées dans le dyld cache** et n'existent pas sur le disque. Par conséquent, appeler **`stat()`** pour vérifier au préalable si une dylib de l'OS existe **ne fonctionnera pas**. Cependant, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.

**Check paths**

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
Si vous le compilez et l’exécutez, vous pouvez voir **où chaque bibliothèque a été recherchée sans succès**. Vous pouvez également **filtrer les logs du FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **binaire/app privilégié** (comme un SUID ou un binaire disposant d'entitlements puissants) **charge une bibliothèque via un chemin relatif** (par exemple en utilisant `@executable_path` ou `@loader_path`) et que **Library Validation est désactivé**, il pourrait être possible de déplacer le binaire vers un emplacement où l'attaquant pourrait **modifier la bibliothèque chargée via le chemin relatif**, puis l'exploiter pour injecter du code dans le processus.

## Élaguer les variables d'environnement `DYLD_*`

Les anciennes versions de `dyld` (`dyld2.cpp`) prenaient cette décision dans le processus à l'aide de `issetugid()`, `hasRestrictedSegment()` et `csops(CS_OPS_STATUS)`. Dans **dyld actuel, la décision est déléguée à AMFI**, et le code se trouve dans `ProcessConfig::Security::Security()` de `dyld/DyldProcessConfig.cpp`:<sup>[1]</sup>
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

- L’**élagage** ne se produit que sur **macOS / Mac Catalyst / DriverKit** — et uniquement lorsque AMFI n’a accordé **aucune** des autorisations `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La requête AMFI reçoit les propriétés propres à l’exécutable :
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
où `isRestricted()` correspond littéralement à la vérification du segment `__RESTRICT` (`mach_o/UnsafeHeader.cpp`) :<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` supprime ensuite **toutes** les variables dont le nom commence par `DYLD_` et fait descendre les paramètres `apple[]`, afin que les processus enfants d’un processus restreint ne les héritent pas non plus :
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Conséquence pratique : **`DYLD_*` est supprimé lorsque le processus est restreint** — setuid/setgid, une section `__RESTRICT/__restrict`, ou des binaires utilisant le hardened runtime/avec des entitlements auxquels AMFI refuse d'accorder les flags path/print. Si le processus dispose uniquement de la **library validation** (`CS_REQUIRE_LV`), les variables sont conservées, mais la dylib injectée doit être signée avec le **même Team ID** (ou par Apple) ; vous avez donc besoin de l'un des entitlements qui désactivent la library validation pour réussir à exécuter du code.

Puisque la décision relève désormais d'AMFI, le moyen le plus rapide de savoir ce qu'un binaire donné va obtenir consiste à examiner les éléments sur lesquels AMFI s'appuie — entitlements et signing flags — plutôt que `dyld` lui-même :
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
### Section `__RESTRICT` avec segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime renforcé

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
> Notez que même si certains binaires sont signés avec des flags **`0x0(none)`**, ils peuvent obtenir dynamiquement le flag **`CS_RESTRICT`** lors de leur exécution, et cette technique ne fonctionnera donc pas avec eux.
>
> Vous pouvez vérifier si un processus possède ce flag avec (récupérez [**csops ici**](https://github.com/axelexic/CSOps)) :
>
> ```bash
> csops -status <pid>
> ```
>
> puis vérifier si le flag 0x800 est activé.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
