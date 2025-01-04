# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> El código de **dyld es de código abierto** y se puede encontrar en [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) y se puede descargar un tar usando una **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Proceso Dyld**

Echa un vistazo a cómo Dyld carga bibliotecas dentro de binarios en:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Esto es como el [**LD_PRELOAD en Linux**](../../../../linux-hardening/privilege-escalation/index.html#ld_preload). Permite indicar a un proceso que se va a ejecutar que cargue una biblioteca específica desde una ruta (si la variable de entorno está habilitada).

Esta técnica también puede ser **utilizada como una técnica ASEP** ya que cada aplicación instalada tiene un plist llamado "Info.plist" que permite la **asignación de variables ambientales** usando una clave llamada `LSEnvironmental`.

> [!NOTE]
> Desde 2012, **Apple ha reducido drásticamente el poder** de **`DYLD_INSERT_LIBRARIES`**.
>
> Ve al código y **verifica `src/dyld.cpp`**. En la función **`pruneEnvironmentVariables`** puedes ver que las variables **`DYLD_*`** son eliminadas.
>
> En la función **`processRestricted`** se establece la razón de la restricción. Al revisar ese código puedes ver que las razones son:
>
> - El binario es `setuid/setgid`
> - Existencia de la sección `__RESTRICT/__restrict` en el binario macho.
> - El software tiene derechos (runtime endurecido) sin el derecho [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Verifica los **derechos** de un binario con: `codesign -dv --entitlements :- </path/to/bin>`
>
> En versiones más actualizadas puedes encontrar esta lógica en la segunda parte de la función **`configureProcessRestrictions`**. Sin embargo, lo que se ejecuta en versiones más nuevas son los **chequeos iniciales de la función** (puedes eliminar los ifs relacionados con iOS o simulación ya que esos no se usarán en macOS).

### Validación de Bibliotecas

Incluso si el binario permite usar la variable de entorno **`DYLD_INSERT_LIBRARIES`**, si el binario verifica la firma de la biblioteca para cargarla, no cargará una personalizada.

Para cargar una biblioteca personalizada, el binario necesita tener **uno de los siguientes derechos**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o el binario **no debería** tener la **bandera de runtime endurecido** o la **bandera de validación de bibliotecas**.

Puedes verificar si un binario tiene **runtime endurecido** con `codesign --display --verbose <bin>` verificando la bandera runtime en **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

También puedes cargar una biblioteca si está **firmada con el mismo certificado que el binario**.

Encuentra un ejemplo sobre cómo (ab)usar esto y verifica las restricciones en:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Secuestro de Dylib

> [!CAUTION]
> Recuerda que **las restricciones de Validación de Bibliotecas anteriores también se aplican** para realizar ataques de secuestro de Dylib.

Al igual que en Windows, en MacOS también puedes **secuestro de dylibs** para hacer que **aplicaciones** **ejecuten** **código** **arbitrario** (bueno, en realidad desde un usuario regular esto podría no ser posible ya que podrías necesitar un permiso de TCC para escribir dentro de un paquete `.app` y secuestrar una biblioteca).\
Sin embargo, la forma en que las **aplicaciones de MacOS** **cargan** bibliotecas es **más restringida** que en Windows. Esto implica que los desarrolladores de **malware** aún pueden usar esta técnica para **sigilo**, pero la probabilidad de poder **abusar de esto para escalar privilegios es mucho menor**.

Primero que nada, es **más común** encontrar que los **binarios de MacOS indican la ruta completa** a las bibliotecas a cargar. Y segundo, **MacOS nunca busca** en las carpetas de **$PATH** para bibliotecas.

La **parte principal** del **código** relacionado con esta funcionalidad está en **`ImageLoader::recursiveLoadLibraries`** en `ImageLoader.cpp`.

Hay **4 comandos de encabezado diferentes** que un binario macho puede usar para cargar bibliotecas:

- El comando **`LC_LOAD_DYLIB`** es el comando común para cargar un dylib.
- El comando **`LC_LOAD_WEAK_DYLIB`** funciona como el anterior, pero si el dylib no se encuentra, la ejecución continúa sin ningún error.
- El comando **`LC_REEXPORT_DYLIB`** proxy (o re-exporta) los símbolos de una biblioteca diferente.
- El comando **`LC_LOAD_UPWARD_DYLIB`** se usa cuando dos bibliotecas dependen entre sí (esto se llama una _dependencia ascendente_).

Sin embargo, hay **2 tipos de secuestro de dylib**:

- **Bibliotecas vinculadas débiles faltantes**: Esto significa que la aplicación intentará cargar una biblioteca que no existe configurada con **LC_LOAD_WEAK_DYLIB**. Luego, **si un atacante coloca un dylib donde se espera que se cargue**.
- El hecho de que el enlace sea "débil" significa que la aplicación continuará ejecutándose incluso si la biblioteca no se encuentra.
- El **código relacionado** con esto está en la función `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` donde `lib->required` es solo `false` cuando `LC_LOAD_WEAK_DYLIB` es verdadero.
- **Encuentra bibliotecas vinculadas débiles** en binarios con (tienes más adelante un ejemplo sobre cómo crear bibliotecas de secuestro):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurado con @rpath**: Los binarios Mach-O pueden tener los comandos **`LC_RPATH`** y **`LC_LOAD_DYLIB`**. Basado en los **valores** de esos comandos, las **bibliotecas** se cargarán desde **diferentes directorios**.
- **`LC_RPATH`** contiene las rutas de algunas carpetas utilizadas para cargar bibliotecas por el binario.
- **`LC_LOAD_DYLIB`** contiene la ruta a bibliotecas específicas para cargar. Estas rutas pueden contener **`@rpath`**, que será **reemplazado** por los valores en **`LC_RPATH`**. Si hay varias rutas en **`LC_RPATH`**, todas se utilizarán para buscar la biblioteca a cargar. Ejemplo:
- Si **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` y **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` y `/application/app.app/Contents/Framework/v2/`. Ambas carpetas se utilizarán para cargar `library.dylib`**.** Si la biblioteca no existe en `[...]/v1/` y el atacante podría colocarla allí para secuestrar la carga de la biblioteca en `[...]/v2/` ya que se sigue el orden de rutas en **`LC_LOAD_DYLIB`**.
- **Encuentra rutas y bibliotecas rpath** en binarios con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Es la **ruta** al directorio que contiene el **archivo ejecutable principal**.
>
> **`@loader_path`**: Es la **ruta** al **directorio** que contiene el **binario Mach-O** que contiene el comando de carga.
>
> - Cuando se usa en un ejecutable, **`@loader_path`** es efectivamente lo **mismo** que **`@executable_path`**.
> - Cuando se usa en un **dylib**, **`@loader_path`** da la **ruta** al **dylib**.

La forma de **escalar privilegios** abusando de esta funcionalidad sería en el raro caso de que una **aplicación** que se está ejecutando **por** **root** esté **buscando** alguna **biblioteca en alguna carpeta donde el atacante tiene permisos de escritura.**

> [!TIP]
> Un buen **escáner** para encontrar **bibliotecas faltantes** en aplicaciones es [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versión CLI**](https://github.com/pandazheng/DylibHijack).\
> Un buen **informe con detalles técnicos** sobre esta técnica se puede encontrar [**aquí**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Ejemplo**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Secuestro de Dlopen

> [!CAUTION]
> Recuerda que **las restricciones de Validación de Bibliotecas anteriores también se aplican** para realizar ataques de secuestro de Dlopen.

De **`man dlopen`**:

- Cuando la ruta **no contiene un carácter de barra** (es decir, es solo un nombre de hoja), **dlopen() hará una búsqueda**. Si **`$DYLD_LIBRARY_PATH`** se estableció al inicio, dyld primero **mirará en ese directorio**. Luego, si el archivo mach-o que llama o el ejecutable principal especifican un **`LC_RPATH`**, entonces dyld **mirará en esos** directorios. A continuación, si el proceso es **sin restricciones**, dyld buscará en el **directorio de trabajo actual**. Por último, para binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al inicio, dyld buscará en **esos directorios**, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es sin restricciones), y luego en **`/usr/lib/`** (esta información fue tomada de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(si no está restringido)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si no está restringido)
6. `/usr/lib/`

> [!CAUTION]
> Si no hay barras en el nombre, habría 2 formas de hacer un secuestro:
>
> - Si algún **`LC_RPATH`** es **escribible** (pero se verifica la firma, así que para esto también necesitas que el binario no esté restringido)
> - Si el binario es **sin restricciones** y luego es posible cargar algo desde el CWD (o abusando de una de las variables de entorno mencionadas)

- Cuando la ruta **parece una ruta de framework** (por ejemplo, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** se estableció al inicio, dyld primero buscará en ese directorio la **ruta parcial del framework** (por ejemplo, `foo.framework/foo`). Luego, dyld intentará la **ruta suministrada tal cual** (usando el directorio de trabajo actual para rutas relativas). Por último, para binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** se estableció al inicio, dyld buscará en esos directorios. De lo contrario, buscará en **`/Library/Frameworks`** (en macOS si el proceso es sin restricciones), luego en **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. ruta suministrada (usando el directorio de trabajo actual para rutas relativas si no está restringido)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si no está restringido)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Si es una ruta de framework, la forma de secuestrarla sería:
>
> - Si el proceso es **sin restricciones**, abusando de la **ruta relativa desde CWD** las variables de entorno mencionadas (incluso si no se dice en la documentación si el proceso está restringido, las variables de entorno DYLD\_\* son eliminadas)

- Cuando la ruta **contiene una barra pero no es una ruta de framework** (es decir, una ruta completa o una ruta parcial a un dylib), dlopen() primero busca en (si está establecido) en **`$DYLD_LIBRARY_PATH`** (con la parte de hoja de la ruta). Luego, dyld **intenta la ruta suministrada** (usando el directorio de trabajo actual para rutas relativas (pero solo para procesos sin restricciones)). Por último, para binarios más antiguos, dyld intentará alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al inicio, dyld buscará en esos directorios, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es sin restricciones), y luego en **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. ruta suministrada (usando el directorio de trabajo actual para rutas relativas si no está restringido)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si no está restringido)
5. `/usr/lib/`

> [!CAUTION]
> Si hay barras en el nombre y no es un framework, la forma de secuestrarlo sería:
>
> - Si el binario es **sin restricciones** y luego es posible cargar algo desde el CWD o `/usr/local/lib` (o abusando de una de las variables de entorno mencionadas)

> [!NOTE]
> Nota: No hay **archivos de configuración** para **controlar la búsqueda de dlopen**.
>
> Nota: Si el ejecutable principal es un **binario set\[ug]id o firmado con derechos**, entonces **todas las variables de entorno son ignoradas**, y solo se puede usar una ruta completa ([ver restricciones de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para más información detallada)
>
> Nota: Las plataformas de Apple utilizan archivos "universales" para combinar bibliotecas de 32 bits y 64 bits. Esto significa que no hay **rutas de búsqueda separadas para 32 bits y 64 bits**.
>
> Nota: En las plataformas de Apple, la mayoría de las dylibs del sistema operativo están **combinadas en la caché de dyld** y no existen en el disco. Por lo tanto, llamar a **`stat()`** para preflight si una dylib del sistema operativo existe **no funcionará**. Sin embargo, **`dlopen_preflight()`** utiliza los mismos pasos que **`dlopen()`** para encontrar un archivo mach-o compatible.

**Verificar rutas**

Vamos a verificar todas las opciones con el siguiente código:
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
Si lo compilas y lo ejecutas, puedes ver **dónde se buscó cada biblioteca sin éxito**. También podrías **filtrar los registros del sistema de archivos**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Secuestro de Ruta Relativa

Si un **binario/app privilegiado** (como un SUID o algún binario con privilegios poderosos) está **cargando una biblioteca de ruta relativa** (por ejemplo, usando `@executable_path` o `@loader_path`) y tiene **la Validación de Biblioteca deshabilitada**, podría ser posible mover el binario a una ubicación donde el atacante podría **modificar la biblioteca de ruta relativa cargada**, y abusar de ella para inyectar código en el proceso.

## Podar variables de entorno `DYLD_*` y `LD_LIBRARY_PATH`

En el archivo `dyld-dyld-832.7.1/src/dyld2.cpp` es posible encontrar la función **`pruneEnvironmentVariables`**, que eliminará cualquier variable de entorno que **comience con `DYLD_`** y **`LD_LIBRARY_PATH=`**.

También establecerá en **null** específicamente las variables de entorno **`DYLD_FALLBACK_FRAMEWORK_PATH`** y **`DYLD_FALLBACK_LIBRARY_PATH`** para binarios **suid** y **sgid**.

Esta función se llama desde la función **`_main`** del mismo archivo si se dirige a OSX de esta manera:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
y esos flags booleanos se establecen en el mismo archivo en el código:
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
Lo que básicamente significa que si el binario es **suid** o **sgid**, o tiene un segmento **RESTRICT** en los encabezados o fue firmado con la bandera **CS_RESTRICT**, entonces **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** es verdadero y las variables de entorno son eliminadas.

Tenga en cuenta que si CS_REQUIRE_LV es verdadero, entonces las variables no serán eliminadas, pero la validación de la biblioteca verificará que estén usando el mismo certificado que el binario original.

## Verificar Restricciones

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
### Hardened runtime

Crea un nuevo certificado en el llavero y úsalo para firmar el binario:
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
> Tenga en cuenta que incluso si hay binarios firmados con las banderas **`0x0(none)`**, pueden obtener la bandera **`CS_RESTRICT`** dinámicamente al ejecutarse y, por lo tanto, esta técnica no funcionará en ellos.
>
> Puede verificar si un proceso tiene esta bandera con (consulte [**csops aquí**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> y luego verifique si la bandera 0x800 está habilitada.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
