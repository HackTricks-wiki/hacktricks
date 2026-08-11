# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> El código de **dyld es open source** y se puede encontrar en [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) y descargar como un tar usando una **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Consulta cómo Dyld carga libraries dentro de los binaries en:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Es como [**LD_PRELOAD en Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permite indicar a un proceso que se va a ejecutar que cargue una library específica desde una ruta (si la variable de entorno está habilitada)<sup>[[4]](#references)</sup>

Esta técnica también puede **usarse como técnica ASEP**, ya que cada aplicación instalada tiene un plist llamado "Info.plist" que permite **asignar variables de entorno** mediante una key llamada `LSEnvironmental`.

> [!TIP]
> Desde 2012, **Apple ha reducido drásticamente el poder** de **`DYLD_INSERT_LIBRARIES`**. Un proceso se considera **restricted** —y entonces `dyld` elimina todas las variables `DYLD_*` de su entorno— cuando se cumple cualquiera de estas condiciones:
>
> - El binary es `setuid/setgid`
> - El Mach-O tiene una sección **`__RESTRICT/__restrict`**
> - El binary está firmado con hardened runtime y AMFI no le concede los permisos de "path/print variables"; es decir, carece de [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Comprueba los **entitlements** de un binary con: `codesign -dv --entitlements :- </path/to/bin>`
>
> En el `dyld` actual esto ya no lo decide únicamente `dyld`: `ProcessConfig::Security::Security()` consulta a **AMFI** mediante `amfi_check_dyld_policy_self()` y después llama a `pruneEnvVars()`. El código exacto se explica en [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) más abajo.

### Library Validation

Aunque el binary permita la variable de entorno **`DYLD_INSERT_LIBRARIES`**, no cargará una library personalizada si valida la firma de la library.

Para cargar una library personalizada, el binary debe tener **uno de los siguientes entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o el binary **no debe** tener el **hardened runtime flag** ni el **library validation flag**.

Puedes comprobar si un binary tiene **hardened runtime** con `codesign --display --verbose <bin>`, comprobando el flag runtime en **`CodeDirectory`**, como en: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

También puedes cargar una library si está **firmada con el mismo certificado que el binary**.

Encuentra un ejemplo de cómo abusar de esto y comprobar las restricciones en:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Recuerda que las **restricciones anteriores de Library Validation también se aplican** para realizar ataques de Dylib hijacking.

Al igual que en Windows, en MacOS también puedes **secuestrar dylibs** para hacer que las **applications** **ejecuten** **código** **arbitrary** (en realidad, esto no sería posible desde un usuario normal, ya que podrías necesitar un permiso de TCC para escribir dentro de un bundle `.app` y secuestrar una library).\
Sin embargo, la forma en que las applications de **MacOS** **cargan** libraries está más restringida que en Windows. Esto implica que los desarrolladores de **malware** todavía pueden usar esta técnica para conseguir **stealth**, pero la probabilidad de poder **abusar de esto para escalar privilegios es mucho menor**.

En primer lugar, es **más común** encontrar que los binaries de **MacOS indican la ruta completa** de las libraries que se deben cargar. En segundo lugar, **MacOS nunca busca** libraries en las carpetas de **$PATH**.

La parte **principal** del **código** relacionada con esta funcionalidad está en **`ImageLoader::recursiveLoadLibraries`**, en `ImageLoader.cpp`.

Hay **4 Commands de header** diferentes que un binary macho puede usar para cargar libraries:

- El comando **`LC_LOAD_DYLIB`** es el comando habitual para cargar una dylib.
- El comando **`LC_LOAD_WEAK_DYLIB`** funciona como el anterior, pero si no se encuentra la dylib, la ejecución continúa sin ningún error.
- El comando **`LC_REEXPORT_DYLIB`** hace proxy (o re-exporta) de los symbols de una library diferente.
- El comando **`LC_LOAD_UPWARD_DYLIB`** se utiliza cuando dos libraries dependen entre sí (esto se denomina _upward dependency_).

Sin embargo, hay **2 tipos de Dylib hijacking**:

- **Missing weak linked libraries**: Esto significa que la application intentará cargar una library que no existe, configurada con **LC_LOAD_WEAK_DYLIB**. Entonces, **si un attacker coloca una dylib donde se espera, esta se cargará**.
- El hecho de que el link sea "weak" significa que la application continuará ejecutándose incluso si no se encuentra la library.
- El **código relacionado** se encuentra en la función `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, donde `lib->required` solo es `false` cuando `LC_LOAD_WEAK_DYLIB` es true.
- **Encuentra libraries weak linked** en binaries con (más adelante tienes un ejemplo de cómo crear libraries para hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configuradas con @rpath**: Los binaries Mach-O pueden tener los Commands **`LC_RPATH`** y **`LC_LOAD_DYLIB`**. Según los **values** de esos Commands, las **libraries** se van a **cargar** desde **diferentes directorios**.
- **`LC_RPATH`** contiene las rutas de algunas carpetas utilizadas por el binary para cargar libraries.
- **`LC_LOAD_DYLIB`** contiene la ruta de las libraries específicas que se deben cargar. Estas rutas pueden contener **`@rpath`**, que será **reemplazado** por los values de **`LC_RPATH`**. Si hay varias rutas en **`LC_RPATH`**, todas se utilizarán para buscar la library que se debe cargar. Ejemplo:
- Si **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` y **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` y `/application/app.app/Contents/Framework/v2/`, ambas carpetas se utilizarán para cargar `library.dylib`**.** Si la library no existe en `[...]/v1/` y un attacker puede colocarla allí, podrá secuestrar la carga de la library en `[...]/v2/`, ya que se sigue el orden de las rutas en **`LC_LOAD_DYLIB`**.
- **Encuentra rutas rpath y libraries** en binaries con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Es la **ruta** al directorio que contiene el **archivo executable principal**.
>
> **`@loader_path`**: Es la **ruta** al **directorio** que contiene el **binary Mach-O** que incluye el load command.
>
> - Cuando se utiliza en un executable, **`@loader_path`** es efectivamente igual que **`@executable_path`**.
> - Cuando se utiliza en una **dylib**, **`@loader_path`** proporciona la **ruta** a la **dylib**.

La forma de **escalar privilegios** abusando de esta funcionalidad se daría en el caso poco frecuente de que una **application** ejecutada **por** **root** esté **buscando** alguna **library en una carpeta donde el attacker tenga permisos de escritura**.

> [!TIP]
> Un buen **scanner** para encontrar **missing libraries** en applications es [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versión CLI**](https://github.com/pandazheng/DylibHijack).\
> Puedes encontrar [**aquí**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) un buen **informe con detalles técnicos** sobre esta técnica.

**Ejemplo**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Recuerda que las **restricciones anteriores de Library Validation también se aplican** para realizar ataques de Dlopen hijacking.

De **`man dlopen`**:

- Cuando la path **no contiene un carácter de barra** (es decir, es solo un leaf name), **dlopen() realizará una búsqueda**. Si **`$DYLD_LIBRARY_PATH`** estaba configurada en el momento del launch, dyld **buscará primero en ese directorio**. A continuación, si el archivo mach-o que realiza la llamada o el executable principal especifica un **`LC_RPATH`**, dyld **buscará en esos** directorios. Después, si el proceso es **unrestricted**, dyld buscará en el **current working directory**. Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** estaba configurada en el momento del launch, dyld buscará en **esos directorios**; de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es unrestricted) y después en **`/usr/lib/`** (esta información se tomó de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Si el name no contiene barras, habría 2 formas de realizar un hijacking:
>
> - Si algún **`LC_RPATH`** es **writable** (pero se comprueba la firma, por lo que también necesitas que el binary sea unrestricted)
> - Si el binary es **unrestricted**, entonces es posible cargar algo desde el CWD (o abusar de una de las variables de entorno mencionadas)

- Cuando la path **parece una path de framework** (por ejemplo, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** estaba configurada en el momento del launch, dyld buscará primero en ese directorio la **partial path del framework** (por ejemplo, `foo.framework/foo`). A continuación, dyld probará la **path proporcionada tal cual** (utilizando el current working directory para las rutas relativas). Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** estaba configurada en el momento del launch, dyld buscará en esos directorios. De lo contrario, buscará en **`/Library/Frameworks`** (en macOS si el proceso es unrestricted) y después en **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Si se trata de una framework path, la forma de realizar el hijacking sería:
>
> - Si el proceso es **unrestricted**, abusar de la **ruta relativa desde CWD** o de las variables de entorno mencionadas (aunque no se indique en la documentación, si el proceso es restricted, las variables de entorno DYLD\_\* se eliminan)

- Cuando la path **contiene una barra pero no es una framework path** (es decir, una path completa o parcial a una dylib), dlopen() busca primero (si está configurada) en **`$DYLD_LIBRARY_PATH`** (utilizando la parte leaf de la path). Después, dyld **prueba la path proporcionada** (utilizando el current working directory para las rutas relativas (pero solo para procesos unrestricted)). Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** estaba configurada en el momento del launch, dyld buscará en esos directorios; de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es unrestricted) y después en **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si el name contiene barras y no es una framework, la forma de realizar el hijacking sería:
>
> - Si el binary es **unrestricted**, entonces es posible cargar algo desde el CWD o `/usr/local/lib` (o abusar de una de las variables de entorno mencionadas)

> [!TIP]
> Nota: **no hay** archivos de configuración para **controlar la búsqueda de dlopen**.
>
> Nota: Si el executable principal es un **binary set\[ug]id o está firmado con entitlements**, entonces **todas las variables de entorno se ignoran** y solo se puede utilizar una path completa ([consulta las restricciones de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para obtener información más detallada).
>
> Nota: Las platforms de Apple utilizan archivos "universal" para combinar libraries de 32 y 64 bits. Esto significa que **no hay rutas de búsqueda separadas para 32 y 64 bits**.
>
> Nota: En las platforms de Apple, la mayoría de las dylibs del sistema operativo están **combinadas en la dyld cache** y no existen en el disco. Por lo tanto, llamar a **`stat()`** para comprobar previamente si existe una dylib del sistema **no funcionará**. Sin embargo, **`dlopen_preflight()`** utiliza los mismos pasos que **`dlopen()`** para encontrar un archivo mach-o compatible.

**Comprobar paths**

Comprobemos todas las opciones con el siguiente código:
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
Si lo compilas y ejecutas, puedes ver **dónde se buscó sin éxito cada library**. También podrías **filtrar los logs del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **binario/app privilegiado** (como un SUID o algún binario con entitlements potentes) está **cargando una librería mediante una ruta relativa** (por ejemplo, usando `@executable_path` o `@loader_path`) y tiene **Library Validation deshabilitado**, podría ser posible mover el binario a una ubicación donde el atacante pudiera **modificar la librería cargada mediante la ruta relativa** y abusar de ello para inyectar código en el proceso.

## Prune `DYLD_*` env variables

Las versiones antiguas de `dyld` (`dyld2.cpp`) tomaban esta decisión dentro del proceso mediante `issetugid()`, `hasRestrictedSegment()` y `csops(CS_OPS_STATUS)`. En el **`dyld` actual, la decisión se delega en AMFI**, y el código se encuentra en `ProcessConfig::Security::Security()` dentro de `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Vale la pena extraer dos aspectos de esto:

- La **poda** solo ocurre en **macOS / Mac Catalyst / DriverKit** — y únicamente cuando AMFI no concedió ninguno de `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La consulta de AMFI recibe las propiedades del propio ejecutable:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
donde `isRestricted()` es literalmente la comprobación del segmento `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` después elimina **todas** las variables cuyo nombre comienza por `DYLD_` y desplaza los parámetros de `apple[]` hacia abajo, por lo que los procesos hijos de un proceso restringido tampoco las heredan:
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
> Consecuencia práctica: **`DYLD_*` se elimina cuando el proceso está restringido** — setuid/setgid, una sección `__RESTRICT/__restrict` o binarios con hardened-runtime/entitlements a los que AMFI se niega a conceder los flags de path/print. Si, en cambio, el proceso solo tiene **library validation** (`CS_REQUIRE_LV`), las variables sobreviven, pero la dylib insertada debe estar firmada por el **mismo Team ID** (o por Apple), por lo que necesitas uno de los entitlements que deshabilitan library validation para que el código llegue a ejecutarse.

Dado que ahora la decisión la toma AMFI, la forma más rápida de saber qué obtendrá un binario concreto es observar en qué se basa AMFI — entitlements y signing flags — en lugar de `dyld` directamente:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Comprobar restricciones

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
### Sección `__RESTRICT` con segmento `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime reforzado

Crea un nuevo certificado en el Keychain y úsalo para firmar el binario:
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
> Ten en cuenta que, aunque haya binarios firmados con flags **`0x0(none)`**, pueden obtener dinámicamente el flag **`CS_RESTRICT`** al ejecutarse y, por lo tanto, esta técnica no funcionará en ellos.
>
> Puedes comprobar si un proc tiene este flag con (obtén [**csops aquí**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> y después comprobar si el flag 0x800 está habilitado.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / comprobación de `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (inicio del proceso e inserción de librerías)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
