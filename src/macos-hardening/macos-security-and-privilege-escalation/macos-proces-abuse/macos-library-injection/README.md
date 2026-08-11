# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Le code de **dyld est open source** et peut être consulté sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et téléchargé sous forme d'archive tar via une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Observez comment Dyld charge les libraries à l'intérieur des binaries dans :


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Cela fonctionne comme [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Cela permet d'indiquer à un process qui va être exécuté de charger une library spécifique depuis un path (si la variable d'environnement est activée)<sup>[[4]](#references)</sup>

Cette technique peut également être **utilisée comme technique ASEP**, car chaque application installée possède un plist appelé "Info.plist" qui permet **d'assigner des variables d'environnement** à l'aide d'une clé appelée `LSEnvironmental`.

> [!TIP]
> Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**. Un process est considéré comme **restricted** — et `dyld` supprime alors chaque variable `DYLD_*` de son environnement — lorsque l'une des conditions suivantes est remplie :
>
> - Le binary est `setuid/setgid`
> - Le Mach-O possède une section **`__RESTRICT/__restrict`**
> - Le binary est signé avec le hardened runtime et AMFI ne lui accorde pas les permissions "path/print variables", c'est-à-dire qu'il lui manque [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Vérifiez les **entitlements** d'un binary avec : `codesign -dv --entitlements :- </path/to/bin>`
>
> Dans `dyld` actuel, cela n'est plus décidé par `dyld` seul : `ProcessConfig::Security::Security()` interroge **AMFI** via `amfi_check_dyld_policy_self()`, puis appelle `pruneEnvVars()`. Le code exact est détaillé dans [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) ci-dessous.

### Library Validation

Même si le binary autorise la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, il ne chargera pas de library custom s'il valide la signature de la library.

Pour charger une library custom, le binary doit posséder **l'un des entitlements suivants** :

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binary **ne doit pas** posséder le **hardened runtime flag** ou le **library validation flag**.

Vous pouvez vérifier si un binary possède le **hardened runtime** avec `codesign --display --verbose <bin>`, en vérifiant le runtime flag dans **`CodeDirectory`**, par exemple : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une library si elle est **signée avec le même certificat que le binary**.

Trouvez un exemple d'exploitation de cette fonctionnalité et vérifiez les restrictions dans :


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** pour effectuer des attaques de Dylib hijacking.

Comme sous Windows, sur macOS vous pouvez **hijack des dylibs** afin de faire **exécuter du code arbitraire aux applications**. Depuis un compte utilisateur standard, cela peut ne pas être possible, car l'écriture dans un bundle `.app` pour hijack une library peut nécessiter une permission TCC.\
Cependant, la manière dont les applications **macOS chargent** les libraries est **plus restrictive** que sous Windows. Les développeurs de malware peuvent toujours utiliser cette technique pour la **stealth**, mais son exploitation pour escalader les privilèges est beaucoup moins probable.

Tout d'abord, il est **plus courant** de constater que les binaries **MacOS indiquent le path complet** des libraries à charger. Ensuite, **MacOS ne recherche jamais** les libraries dans les dossiers du **$PATH**.

La partie **principale** du **code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Un binary macho peut utiliser **4 commandes d'en-tête** différentes pour charger des libraries :

- La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger une dylib.
- La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib est introuvable, l'exécution continue sans erreur.
- La commande **`LC_REEXPORT_DYLIB`** proxy (ou réexporte) les symbols d'une autre library.
- La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux libraries dépendent l'une de l'autre (on parle alors d'une _upward dependency_).

Cependant, il existe **2 types de Dylib hijacking** :

- **Missing weak linked libraries** : cela signifie que l'application va essayer de charger une library inexistante configurée avec **LC_LOAD_WEAK_DYLIB**. Ensuite, **si un attacker place une dylib à l'endroit attendu, elle sera chargée**.
- Le fait que le link soit "weak" signifie que l'application continuera de s'exécuter même si la library est introuvable.
- Le **code correspondant** se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, où `lib->required` vaut `false` uniquement lorsque `LC_LOAD_WEAK_DYLIB` est true.
- **Trouvez les weak linked libraries** dans les binaries avec (vous trouverez plus loin un exemple de création de libraries de hijacking) :
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath** : les binaries Mach-O peuvent posséder les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **libraries** seront **chargées** depuis **différents répertoires**.
- **`LC_RPATH`** contient les paths de certains dossiers utilisés par le binary pour charger les libraries.
- **`LC_LOAD_DYLIB`** contient le path des libraries spécifiques à charger. Ces paths peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs de **`LC_RPATH`**. S'il existe plusieurs paths dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la library à charger. Exemple :
- Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`, les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la library n'existe pas dans `[...]/v1/` et qu'un attacker peut l'y placer, il peut hijack le chargement de la library dans `[...]/v2/`, car l'ordre des paths dans **`LC_LOAD_DYLIB`** est respecté.
- **Trouvez les paths rpath et les libraries** dans les binaries avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`** : correspond au **path** du répertoire contenant le **fichier exécutable principal**.
>
> **`@loader_path`** : correspond au **path** du **répertoire** contenant le **binary Mach-O** qui possède la load command.
>
> - Lorsqu'il est utilisé dans un executable, **`@loader_path`** est effectivement identique à **`@executable_path`**.
> - Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** fournit le **path** vers la **dylib**.

La manière d'**escalader les privilèges** en exploitant cette fonctionnalité serait le cas rare où une **application** exécutée **par** **root** recherche une **library dans un dossier où l'attacker possède des permissions d'écriture**.

> [!TIP]
> Un bon **scanner** pour trouver les **missing libraries** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou une [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Un bon **rapport contenant des détails techniques** sur cette technique est disponible [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> N'oubliez pas que les **restrictions précédentes de Library Validation s'appliquent également** pour effectuer des attaques de Dlopen hijacking.

D'après **`man dlopen`** :

- Lorsque le path **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit uniquement d'un leaf name), **dlopen() effectue une recherche**. Si **`$DYLD_LIBRARY_PATH`** était défini au lancement, dyld recherchera d'abord **dans ce répertoire**. Ensuite, si le fichier mach-o appelant ou l'executable principal spécifie un **`LC_RPATH`**, dyld recherchera dans ces répertoires. Ensuite, si le process est **unrestricted**, dyld recherchera dans le répertoire de travail actuel. Enfin, pour les anciens binaries, dyld tentera certains fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans **ces répertoires** ; sinon, dyld recherchera dans **`/usr/local/lib/`** (si le process est unrestricted), puis dans **`/usr/lib/`** (ces informations proviennent de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> S'il n'y a pas de slash dans le nom, il existe 2 façons d'effectuer un hijacking :
>
> - Si un **`LC_RPATH`** est **writable** (mais la signature est vérifiée ; il faut donc également que le binary soit unrestricted)
> - Si le binary est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD (ou d'exploiter l'une des variables d'environnement mentionnées)

- Lorsque le path **ressemble à un path de framework** (par exemple `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera d'abord le **partial path du framework** dans ce répertoire (par exemple `foo.framework/foo`). Ensuite, dyld essaiera le path fourni tel quel (en utilisant le répertoire de travail actuel pour les paths relatifs). Enfin, pour les anciens binaries, dyld tentera certains fallbacks. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera dans **`/Library/Frameworks`** (sur macOS si le process est unrestricted), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Pour un framework path, la manière de l'hijack serait :
>
> - Si le process est **unrestricted**, exploiter le **relative path depuis le CWD** ou les variables d'environnement mentionnées (même si la documentation ne le précise pas, les variables d'environnement DYLD\_\* sont supprimées lorsque le process est restricted)

- Lorsque le path **contient un slash mais n'est pas un framework path** (c'est-à-dire un full path ou un partial path vers une dylib), dlopen() effectue d'abord une recherche (si elle est définie) dans **`$DYLD_LIBRARY_PATH`** (avec la partie leaf du path). Ensuite, dyld **essaie le path fourni** (en utilisant le répertoire de travail actuel pour les paths relatifs, mais uniquement pour les processes unrestricted). Enfin, pour les anciens binaries, dyld tentera des fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans ces répertoires ; sinon, dyld recherchera dans **`/usr/local/lib/`** (si le process est unrestricted), puis dans **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si le nom contient des slashes et ne correspond pas à un framework, la manière de l'hijack serait :
>
> - Si le binary est **unrestricted**, il est alors possible de charger quelque chose depuis le CWD ou `/usr/local/lib` (ou d'exploiter l'une des variables d'environnement mentionnées)

> [!TIP]
> Remarque : il n'existe **aucun** fichier de configuration permettant de **contrôler la recherche de dlopen**.
>
> Remarque : si l'executable principal est un **binary set\[ug]id ou signé avec des entitlements**, toutes les variables d'environnement sont ignorées et seul un full path peut être utilisé ([consultez les restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) pour plus d'informations)
>
> Remarque : les plateformes Apple utilisent des fichiers "universal" pour combiner les libraries 32 bits et 64 bits. Il n'existe donc **aucun path de recherche séparé pour les libraries 32 bits et 64 bits**.
>
> Remarque : sur les plateformes Apple, la plupart des dylibs de l'OS sont **combinées dans le dyld cache** et n'existent pas sur le disque. Par conséquent, appeler **`stat()`** pour vérifier au préalable si une dylib de l'OS existe **ne fonctionnera pas**. Cependant, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.

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
Si vous le compilez et l’exécutez, vous pouvez voir **où chaque library a été recherchée sans succès**. Vous pouvez également **filtrer les logs du FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **binaire/app privilégié** (comme un SUID ou un binaire avec des entitlements puissants) **charge** une library via un **chemin relatif** (par exemple en utilisant `@executable_path` ou `@loader_path`) et que la **Library Validation** est désactivée, il pourrait être possible de déplacer le binaire vers un emplacement où l’attaquant pourrait **modifier la library chargée via le chemin relatif**, et l’exploiter pour injecter du code dans le processus.

## Prune `DYLD_*` env variables

Les anciennes versions de `dyld` (`dyld2.cpp`) prenaient cette décision dans le processus avec `issetugid()`, `hasRestrictedSegment()` et `csops(CS_OPS_STATUS)`. Dans **dyld actuel, la décision est déléguée à AMFI**, et le code se trouve dans `ProcessConfig::Security::Security()` dans `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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

- L’**élagage** ne se produit que sur **macOS / Mac Catalyst / DriverKit** — et uniquement lorsque AMFI n’a accordé **aucune** des permissions `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La requête AMFI reçoit les propriétés propres de l’exécutable :
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
> Conséquence pratique : **`DYLD_*` est supprimé lorsque le processus est restreint** — setuid/setgid, une section `__RESTRICT/__restrict`, ou des binaires hardened-runtime/entitled auxquels AMFI refuse d'accorder les flags path/print. Si le processus dispose uniquement de la **library validation** (`CS_REQUIRE_LV`), les variables sont conservées, mais la dylib injectée doit être signée avec le **même Team ID** (ou par Apple) ; vous devez donc disposer de l'un des entitlements qui désactivent la library validation pour que le code soit effectivement chargé.

Comme la décision relève désormais d'AMFI, le moyen le plus rapide de savoir ce qu'un binaire donné obtiendra consiste à examiner les éléments sur lesquels AMFI se base — les entitlements et les flags de signature — plutôt que `dyld` lui-même :
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

Créez un nouveau certificat dans le Trousseau et utilisez-le pour signer le binaire :
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
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (vérification de `isRestricted()` / `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (démarrage du processus et insertion de bibliothèques)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
