# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> El código de **dyld es open source** y se puede encontrar en [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) y descargar como un tar mediante una **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Consulta cómo Dyld carga libraries dentro de los binaries en:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Esto es como [**LD_PRELOAD en Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permite indicar a un proceso que se va a ejecutar que cargue una library específica desde una ruta (si la variable de entorno está habilitada).

Esta técnica también puede **usarse como una técnica ASEP**, ya que cada aplicación instalada tiene un plist llamado "Info.plist" que permite **asignar variables de entorno** mediante una key llamada `LSEnvironmental`.

> [!TIP]
> Desde 2012, **Apple ha reducido drásticamente el poder** de **`DYLD_INSERT_LIBRARIES`**.
>
> Ve al código y **comprueba `src/dyld.cpp`**. En la función **`pruneEnvironmentVariables`** se puede ver que las variables **`DYLD_*`** se eliminan.
>
> En la función **`processRestricted`** se establece el motivo de la restricción. Al comprobar ese código se puede ver que los motivos son:
>
> - El binary es `setuid/setgid`.
> - Existe una sección `__RESTRICT/__restrict` en el binary macho.
> - El software tiene entitlements (hardened runtime) sin el entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).
>  - Comprueba los **entitlements** de un binary con: `codesign -dv --entitlements :- </path/to/bin>`
>
> En versiones más actualizadas puedes encontrar esta lógica en la segunda parte de la función **`configureProcessRestrictions`.** Sin embargo, en las versiones más recientes se ejecutan las comprobaciones iniciales de la función (puedes eliminar los if relacionados con iOS o la simulación, ya que no se usarán en macOS).

### Library Validation

Aunque el binary permita usar la variable de entorno **`DYLD_INSERT_LIBRARIES`**, si el binary comprueba la firma de la library que va a cargar, no cargará una custom.

Para cargar una library custom, el binary necesita tener **uno de los siguientes entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o el binary **no debe tener** el **hardened runtime flag** ni el **library validation flag**.

Puedes comprobar si un binary tiene **hardened runtime** con `codesign --display --verbose <bin>`, comprobando el runtime flag en **`CodeDirectory`**, como en: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

También puedes cargar una library si está **firmada con el mismo certificado que el binary**.

Encuentra un ejemplo de cómo abusar de esto y comprobar las restricciones en:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Recuerda que las **restricciones anteriores de Library Validation también se aplican** para realizar ataques de Dylib hijacking.

Al igual que en Windows, en macOS también puedes **hacer hijacking de dylibs** para que las **applications** **ejecuten** **código** **arbitrario** (en realidad, desde un usuario normal esto podría no ser posible, ya que podrías necesitar un permiso TCC para escribir dentro de un bundle `.app` y hacer hijacking de una library).\
Sin embargo, la forma en que las applications de **macOS** **cargan** libraries está **más restringida** que en Windows. Esto implica que los desarrolladores de **malware** todavía pueden usar esta técnica para obtener **stealth**, pero la probabilidad de poder **abusar de esto para escalar privilegios es mucho menor**.

En primer lugar, es **más habitual** encontrar que los binaries de **macOS indican la ruta completa** de las libraries que deben cargar. En segundo lugar, **macOS nunca busca** libraries en las carpetas de **$PATH**.

La parte **principal** del **código** relacionado con esta funcionalidad se encuentra en **`ImageLoader::recursiveLoadLibraries`**, dentro de `ImageLoader.cpp`.

Hay **4 comandos de header diferentes** que un binary macho puede usar para cargar libraries:

- El comando **`LC_LOAD_DYLIB`** es el comando habitual para cargar una dylib.
- El comando **`LC_LOAD_WEAK_DYLIB`** funciona como el anterior, pero si no se encuentra la dylib, la ejecución continúa sin ningún error.
- El comando **`LC_REEXPORT_DYLIB`** hace proxy (o reexporta) de los símbolos de una library diferente.
- El comando **`LC_LOAD_UPWARD_DYLIB`** se usa cuando dos libraries dependen entre sí (esto se denomina _upward dependency_).

Sin embargo, existen **2 tipos de Dylib hijacking**:

- **Missing weak linked libraries**: significa que la application intentará cargar una library que no existe, configurada con **LC_LOAD_WEAK_DYLIB**. Después, **si un atacante coloca una dylib donde se espera, esta se cargará**.
- El hecho de que el link sea "weak" significa que la application continuará ejecutándose aunque no se encuentre la library.
- El **código relacionado** con esto está en la función `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, donde `lib->required` solo es `false` cuando `LC_LOAD_WEAK_DYLIB` es true.
- **Encuentra libraries weak linked** en binaries con (más adelante tienes un ejemplo sobre cómo crear libraries de hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configuradas con @rpath**: los binaries Mach-O pueden tener los comandos **`LC_RPATH`** y **`LC_LOAD_DYLIB`**. Según los **valores** de esos comandos, las **libraries** se **cargarán** desde **distintos directorios**.
- **`LC_RPATH`** contiene las rutas de algunas carpetas usadas por el binary para cargar libraries.
- **`LC_LOAD_DYLIB`** contiene la ruta de las libraries específicas que se deben cargar. Estas rutas pueden contener **`@rpath`**, que se **reemplazará** por los valores de **`LC_RPATH`**. Si hay varias rutas en **`LC_RPATH`**, todas se usarán para buscar la library que se va a cargar. Ejemplo:
- Si **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` y **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` y `/application/app.app/Contents/Framework/v2/`, ambas carpetas se usarán para cargar `library.dylib`**.** Si la library no existe en `[...]/v1/` y un atacante pudiera colocarla allí, podría hacer hijacking de la carga de la library en `[...]/v2/`, ya que se sigue el orden de las rutas en **`LC_LOAD_DYLIB`**.
- **Encuentra rutas rpath y libraries** en binaries con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Es la **ruta** al directorio que contiene el **archivo ejecutable principal**.
>
> **`@loader_path`**: Es la **ruta** al **directorio** que contiene el **binary Mach-O** que incluye el load command.
>
> - Cuando se usa en un ejecutable, **`@loader_path`** es efectivamente igual que **`@executable_path`**.
> - Cuando se usa en una **dylib**, **`@loader_path`** proporciona la **ruta** a la **dylib**.

La forma de **escalar privilegios** abusando de esta funcionalidad sería en el caso poco frecuente de que una **application** ejecutada **por** **root** esté **buscando** alguna **library en una carpeta donde el atacante tenga permisos de escritura**.

> [!TIP]
> Un buen **scanner** para encontrar **missing libraries** en applications es [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versión CLI**](https://github.com/pandazheng/DylibHijack).\
> Puedes encontrar un buen **informe con detalles técnicos** sobre esta técnica [**aquí**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Recuerda que las **restricciones anteriores de Library Validation también se aplican** para realizar ataques de Dlopen hijacking.

Según **`man dlopen`**:

- Cuando la ruta **no contiene un carácter de barra** (es decir, es solo un nombre leaf), **dlopen() realizará una búsqueda**. Si **`$DYLD_LIBRARY_PATH`** estaba establecido al iniciar el proceso, dyld buscará primero en ese directorio. Después, si el archivo mach-o que realiza la llamada o el ejecutable principal especifican un **`LC_RPATH`**, dyld buscará en esos directorios. A continuación, si el proceso es **unrestricted**, dyld buscará en el directorio de trabajo actual. Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** estaba establecido al iniciar el proceso, dyld buscará en **esos directorios**; de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es unrestricted) y después en **`/usr/lib/`** (esta información se obtuvo de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (si unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Si no hay barras en el nombre, habría 2 formas de hacer hijacking:
>
> - Si algún **`LC_RPATH`** es **writable** (pero se comprueba la firma, por lo que también necesitas que el binary sea unrestricted).
> - Si el binary es **unrestricted**, en cuyo caso es posible cargar algo desde el CWD (o abusar de una de las variables de entorno mencionadas).

- Cuando la ruta **parece una ruta de framework** (por ejemplo, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** estaba establecido al iniciar el proceso, dyld buscará primero en ese directorio la **ruta parcial del framework** (por ejemplo, `foo.framework/foo`). Después, dyld probará la ruta proporcionada tal cual (usando el directorio de trabajo actual para las rutas relativas). Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** estaba establecido al iniciar el proceso, dyld buscará en esos directorios. De lo contrario, buscará en **`/Library/Frameworks`** (en macOS, si el proceso es unrestricted) y después en **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. ruta proporcionada (usando el directorio de trabajo actual para las rutas relativas si es unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Si se trata de una ruta de framework, la forma de hacer hijacking sería:
>
> - Si el proceso es **unrestricted**, abusando de la **ruta relativa desde el CWD** o de las variables de entorno mencionadas (aunque la documentación no lo indique, si el proceso está restringido, las variables de entorno DYLD\_\* se eliminan).

- Cuando la ruta **contiene una barra, pero no es una ruta de framework** (es decir, una ruta completa o parcial a una dylib), dlopen() busca primero (si está establecido) en **`$DYLD_LIBRARY_PATH`** (usando la parte leaf de la ruta). Después, dyld **intenta la ruta proporcionada** (usando el directorio de trabajo actual para las rutas relativas, pero solo para procesos unrestricted). Por último, para binaries antiguos, dyld probará algunos fallbacks. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** estaba establecido al iniciar el proceso, dyld buscará en esos directorios; de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es unrestricted) y después en **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. ruta proporcionada (usando el directorio de trabajo actual para las rutas relativas si es unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Si hay barras en el nombre y no es un framework, la forma de hacer hijacking sería:
>
> - Si el binary es **unrestricted**, en cuyo caso es posible cargar algo desde el CWD o `/usr/local/lib` (o abusar de una de las variables de entorno mencionadas).

> [!TIP]
> Nota: No existen archivos de configuración para **controlar la búsqueda de dlopen**.
>
> Nota: Si el ejecutable principal es un **binary set\[ug]id o está firmado con entitlements**, todas las variables de entorno se ignoran y solo se puede usar una ruta completa ([consulta las restricciones de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para obtener información más detallada).
>
> Nota: Las plataformas Apple utilizan archivos "universal" para combinar libraries de 32 y 64 bits. Esto significa que **no existen rutas de búsqueda separadas para 32 y 64 bits**.
>
> Nota: En las plataformas Apple, la mayoría de las dylibs del sistema operativo están **combinadas en la dyld cache** y no existen en el disco. Por lo tanto, llamar a **`stat()`** como comprobación previa para determinar si existe una dylib del sistema **no funcionará**. Sin embargo, **`dlopen_preflight()`** usa los mismos pasos que **`dlopen()`** para encontrar un archivo mach-o compatible.

**Check paths**

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
Si lo compilas y lo ejecutas, puedes ver **dónde se buscó sin éxito cada library**. También podrías **filtrar los logs del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Si un **privileged binary/app** (como un binario SUID o algún binario con powerful entitlements) está **loading a relative path** library (por ejemplo, usando `@executable_path` o `@loader_path`) y tiene **Library Validation disabled**, podría ser posible mover el binario a una ubicación donde el atacante pudiera **modificar la relative path loaded library** y abusar de ella para inyectar código en el proceso.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

En el archivo `dyld-dyld-832.7.1/src/dyld2.cpp` es posible encontrar la función **`pruneEnvironmentVariables`**, que eliminará cualquier variable de entorno que **empiece con `DYLD_`** y **`LD_LIBRARY_PATH=`**.

También establecerá específicamente como **null** las variables de entorno **`DYLD_FALLBACK_FRAMEWORK_PATH`** y **`DYLD_FALLBACK_LIBRARY_PATH`** para binarios **suid** y **sgid**.

Esta función se llama desde la función **`_main`** del mismo archivo si se apunta a OSX, de la siguiente manera:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
y esas banderas booleanas se establecen en el mismo archivo del código:
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
Lo que básicamente significa que, si el binario es **suid** o **sgid**, tiene un segmento **RESTRICT** en los headers o se firmó con el flag **CS_RESTRICT**, entonces **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** es true y las variables de entorno se eliminan.

Ten en cuenta que, si CS_REQUIRE_LV es true, las variables no se eliminarán, pero la validación de libraries comprobará que utilizan el mismo certificado que el binario original.

## Comprobar restricciones

### SUID y SGID
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
### Hardened runtime

Crea un nuevo certificado en el Keychain y úsalo para firmar el binario:
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
> Ten en cuenta que, aunque haya binaries firmados con flags **`0x0(none)`**, pueden obtener el flag **`CS_RESTRICT`** dinámicamente al ejecutarse y, por lo tanto, esta técnica no funcionará en ellos.
>
> Puedes comprobar si un proc tiene este flag con (obtén [**csops aquí**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> y comprobar después si el flag 0x800 está habilitado.

## Referencias

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
