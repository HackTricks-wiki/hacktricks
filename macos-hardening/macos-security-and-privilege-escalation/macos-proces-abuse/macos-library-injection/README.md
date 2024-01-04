# Inyección de Bibliotecas en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
El código de **dyld es de código abierto** y se puede encontrar en [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) y se puede descargar un tar usando una **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Esta es una **lista separada por dos puntos de bibliotecas dinámicas** para c**argar antes de las especificadas en el programa**. Esto te permite probar nuevos módulos de bibliotecas compartidas dinámicas existentes que se utilizan en imágenes de espacio de nombres plano cargando una biblioteca compartida dinámica temporal con solo los nuevos módulos. Ten en cuenta que esto no tiene efecto en imágenes construidas con imágenes de espacio de nombres de dos niveles utilizando una biblioteca compartida dinámica a menos que también se use DYLD\_FORCE\_FLAT\_NAMESPACE.

Esto es como el [**LD\_PRELOAD en Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

Esta técnica también puede **usarse como una técnica de ASEP** ya que cada aplicación instalada tiene un plist llamado "Info.plist" que permite la **asignación de variables de entorno** usando una clave llamada `LSEnvironmental`.

{% hint style="info" %}
Desde 2012 **Apple ha reducido drásticamente el poder** de **`DYLD_INSERT_LIBRARIES`**.

Ve al código y **revisa `src/dyld.cpp`**. En la función **`pruneEnvironmentVariables`** puedes ver que las variables **`DYLD_*`** se eliminan.

En la función **`processRestricted`** se establece la razón de la restricción. Revisando ese código puedes ver que las razones son:

* El binario es `setuid/setgid`
* Existencia de la sección `__RESTRICT/__restrict` en el binario macho.
* El software tiene derechos (runtime endurecido) sin el derecho [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Revisa los **derechos** de un binario con: `codesign -dv --entitlements :- </path/to/bin>`

En versiones más actualizadas puedes encontrar esta lógica en la segunda parte de la función **`configureProcessRestrictions`.** Sin embargo, lo que se ejecuta en versiones más recientes son las **verificaciones iniciales de la función** (puedes eliminar los ifs relacionados con iOS o simulación ya que esos no se usarán en macOS.
{% endhint %}

### Validación de Bibliotecas

Incluso si el binario permite usar la variable de entorno **`DYLD_INSERT_LIBRARIES`**, si el binario verifica la firma de la biblioteca a cargar, no cargará una personalizada.

Para cargar una biblioteca personalizada, el binario necesita tener **uno de los siguientes derechos**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o el binario **no debería** tener la **bandera de runtime endurecido** o la **bandera de validación de biblioteca**.

Puedes verificar si un binario tiene **runtime endurecido** con `codesign --display --verbose <bin>` revisando la bandera runtime en **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

También puedes cargar una biblioteca si está **firmada con el mismo certificado que el binario**.

Encuentra un ejemplo de cómo (ab)usar esto y revisar las restricciones en:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Secuestro de Dylib

{% hint style="danger" %}
Recuerda que las **restricciones de Validación de Bibliotecas anteriores también aplican** para realizar ataques de secuestro de Dylib.
{% endhint %}

Como en Windows, en MacOS también puedes **secuestrar dylibs** para hacer que las **aplicaciones** **ejecuten** **código arbitrario**.\
Sin embargo, la forma en que las aplicaciones de **MacOS** **cargan** bibliotecas es **más restringida** que en Windows. Esto implica que los desarrolladores de **malware** aún pueden usar esta técnica para **sigilo**, pero la probabilidad de poder **abusar de esto para escalar privilegios es mucho menor**.

Primero que todo, es **más común** encontrar que los binarios de **MacOS indican la ruta completa** a las bibliotecas a cargar. Y segundo, **MacOS nunca busca** en las carpetas del **$PATH** para bibliotecas.

La **parte principal** del **código** relacionado con esta funcionalidad está en **`ImageLoader::recursiveLoadLibraries`** en `ImageLoader.cpp`.

Hay **4 diferentes Comandos de Encabezado** que un binario macho puede usar para cargar bibliotecas:

* El comando **`LC_LOAD_DYLIB`** es el comando común para cargar una dylib.
* El comando **`LC_LOAD_WEAK_DYLIB`** funciona como el anterior, pero si la dylib no se encuentra, la ejecución continúa sin ningún error.
* El comando **`LC_REEXPORT_DYLIB`** reexporta (o reenvía) los símbolos de una biblioteca diferente.
* El comando **`LC_LOAD_UPWARD_DYLIB`** se usa cuando dos bibliotecas dependen una de la otra (esto se llama una _dependencia ascendente_).

Sin embargo, hay **2 tipos de secuestro de dylib**:

* **Bibliotecas vinculadas débiles faltantes**: Esto significa que la aplicación intentará cargar una biblioteca que no existe configurada con **LC\_LOAD\_WEAK\_DYLIB**. Entonces, **si un atacante coloca una dylib donde se espera, será cargada**.
* El hecho de que el enlace sea "débil" significa que la aplicación continuará funcionando incluso si no se encuentra la biblioteca.
* El **código relacionado** con esto está en la función `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` donde `lib->required` es solo `false` cuando `LC_LOAD_WEAK_DYLIB` es verdadero.
* **Encuentra bibliotecas vinculadas débilmente** en binarios con (más adelante tienes un ejemplo de cómo crear bibliotecas de secuestro):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configurado con @rpath**: Los binarios Mach-O pueden tener los comandos **`LC_RPATH`** y **`LC_LOAD_DYLIB`**. Basado en los **valores** de esos comandos, **bibliotecas** se van a **cargar** desde **diferentes directorios**.
* **`LC_RPATH`** contiene las rutas de algunas carpetas utilizadas para cargar bibliotecas por el binario.
* **`LC_LOAD_DYLIB`** contiene la ruta a bibliotecas específicas para cargar. Estas rutas pueden contener **`@rpath`**, que será **reemplazado** por los valores en **`LC_RPATH`**. Si hay varias rutas en **`LC_RPATH`** todas serán utilizadas para buscar la biblioteca a cargar. Ejemplo:
* Si **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` y **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` y `/application/app.app/Contents/Framework/v2/`. Ambas carpetas se van a usar para cargar `library.dylib`**.** Si la biblioteca no existe en `[...]/v1/` y un atacante podría colocarla allí para secuestrar la carga de la biblioteca en `[...]/v2/` ya que se sigue el orden de rutas en **`LC_LOAD_DYLIB`**.
* **Encuentra rutas rpath y bibliotecas** en binarios con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Es la **ruta** al directorio que contiene el **archivo ejecutable principal**.

**`@loader_path`**: Es la **ruta** al **directorio** que contiene el **binario Mach-O** que contiene el comando de carga.

* Cuando se usa en un ejecutable, **`@loader_path`** es efectivamente **lo mismo** que **`@executable_path`**.
* Cuando se usa en una **dylib**, **`@loader_path`** da la **ruta** a la **dylib**.
{% endhint %}

La forma de **escalar privilegios** abusando de esta funcionalidad sería en el raro caso de que una **aplicación** que se ejecuta **por** **root** esté **buscando** alguna **biblioteca en alguna carpeta donde el atacante tiene permisos de escritura.**

{% hint style="success" %}
Un buen **escáner** para encontrar **bibliotecas faltantes** en aplicaciones es [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versión CLI**](https://github.com/pandazheng/DylibHijack).\
Un buen **informe con detalles técnicos** sobre esta técnica se puede encontrar [**aquí**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Ejemplo**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Secuestro de Dlopen

{% hint style="danger" %}
Recuerda que las **restricciones de Validación de Bibliotecas anteriores también aplican** para realizar ataques de secuestro de Dlopen.
{% endhint %}

De **`man dlopen`**:

* Cuando la ruta **no contiene un carácter de barra** (es decir, es solo un nombre de hoja), **dlopen() realizará una búsqueda**. Si **`$DYLD_LIBRARY_PATH`** se estableció al lanzar, dyld primero **buscará en ese directorio**. A continuación, si el archivo mach-o que llama o el ejecutable principal especifican un **`LC_RPATH`**, entonces dyld **buscará en esos directorios**. A continuación, si el proceso es **no restringido**, dyld buscará en el **directorio de trabajo actual**. Por último, para binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al lanzar, dyld buscará en **esos directorios**, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso es no restringido), y luego en **`/usr/lib/`** (esta información se tomó de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(si no restringido)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si no restringido)
6. `/usr/lib/`

{% hint style="danger" %}
Si no hay barras en el nombre, habría 2 formas de realizar un secuestro:

* Si algún **`LC_RPATH`** es **escribible** (pero se verifica la firma, por lo que para esto también se necesita que el binario no esté restringido)
* Si el binario es **no restringido** y luego es posible cargar algo desde el CWD (o abusando de una de las variables de entorno mencionadas)
{% endhint %}

* Cuando la ruta **parece una ruta de framework** (por ejemplo, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** se estableció al lanzar, dyld primero buscará en ese directorio la **ruta parcial del framework** (por ejemplo, `foo.framework/foo`). A continuación, dyld intentará la **ruta suministrada tal cual** (usando el directorio de trabajo actual para rutas relativas). Por último, para binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** se estableció al lanzar, dyld buscará en esos directorios. De lo contrario, buscará en **`/Library/Frameworks`** (en macOS si el proceso no está restringido), luego en **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. ruta suministrada (usando el directorio de trabajo actual para rutas relativas si no restringido)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si no restringido)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Si es una ruta de framework, la forma de secuestrarla sería:

* Si el proceso es **no restringido**, abusando de la **ruta relativa desde CWD** las variables de entorno mencionadas (aunque no se dice en los documentos si el proceso está restringido, se eliminan las variables de entorno DYLD\_\*)
{% endhint %}

* Cuando la ruta **contiene una barra pero no es una ruta de framework** (es decir, una ruta completa o una ruta parcial a una dylib), dlopen() primero busca en (si está establecido) en **`$DYLD_LIBRARY_PATH`** (con la parte de hoja de la ruta). A continuación, dyld **intenta la ruta suministrada** (usando el directorio de trabajo actual para rutas relativas (pero solo para procesos no restringidos)). Por último, para binarios más antiguos, dyld intentará alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al lanzar, dyld buscará en esos directorios, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso no está restringido), y luego en **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. ruta suministrada (usando el directorio de trabajo actual para rutas relativas si no restringido)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si no restringido)
5. `/usr/lib/`

{% hint style="danger" %}
Si hay barras en el nombre y no es un framework, la forma de secuestrarla sería:

* Si el binario es **no restringido** y luego es posible cargar algo desde el CWD o `/usr/local/lib` (o abusando de una de las variables de entorno mencionadas)
{% endhint %}

{% hint style="info" %}
Nota: No hay archivos de configuración para **controlar la búsqueda de dlopen**.

Nota: Si el ejecutable principal es un binario
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
Si lo compilas y ejecutas, puedes ver **dónde se buscó sin éxito cada biblioteca**. Además, podrías **filtrar los registros del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Secuestro de Ruta Relativa

Si un **binario/aplicación privilegiado** (como un SUID o algún binario con permisos poderosos) está **cargando una biblioteca de ruta relativa** (por ejemplo, usando `@executable_path` o `@loader_path`) y tiene **Validación de Biblioteca desactivada**, podría ser posible mover el binario a una ubicación donde el atacante podría **modificar la biblioteca de ruta relativa cargada**, y abusar de ella para inyectar código en el proceso.

## Podar variables de entorno `DYLD_*` y `LD_LIBRARY_PATH`

En el archivo `dyld-dyld-832.7.1/src/dyld2.cpp` es posible encontrar la función **`pruneEnvironmentVariables`**, la cual eliminará cualquier variable de entorno que **comience con `DYLD_`** y **`LD_LIBRARY_PATH=`**.

También establecerá en **nulo** específicamente las variables de entorno **`DYLD_FALLBACK_FRAMEWORK_PATH`** y **`DYLD_FALLBACK_LIBRARY_PATH`** para binarios **suid** y **sgid**.

Esta función es llamada desde la función **`_main`** del mismo archivo si se dirige a OSX de esta manera:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
y esas banderas booleanas se establecen en el mismo archivo en el código:
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
Lo cual básicamente significa que si el binario es **suid** o **sgid**, o tiene un segmento **RESTRICT** en los encabezados o fue firmado con la bandera **CS_RESTRICT**, entonces **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** es verdadero y las variables de entorno son eliminadas.

Ten en cuenta que si CS_REQUIRE_LV es verdadero, entonces las variables no serán eliminadas pero la validación de la biblioteca verificará que estén utilizando el mismo certificado que el binario original.

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
### Entorno de ejecución reforzado

Crea un nuevo certificado en el Llavero y úsalo para firmar el binario:

{% code overflow="wrap" %}
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
{% endcode %}

{% hint style="danger" %}
Tenga en cuenta que incluso si hay binarios firmados con las banderas **`0x0(none)`**, pueden obtener la bandera **`CS_RESTRICT`** dinámicamente cuando se ejecutan y, por lo tanto, esta técnica no funcionará en ellos.

Puede verificar si un proceso tiene esta bandera con (obtenga [**csops aquí**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
y luego verifica si la bandera 0x800 está habilitada.
{% endhint %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al grupo de [**telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
