# Inyección de Bibliotecas en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
El código de **dyld es de código abierto** y se puede encontrar en [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) y se puede descargar un archivo tar usando una **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Esta es una lista separada por dos puntos de **bibliotecas dinámicas** para cargar antes de las especificadas en el programa. Esto te permite probar nuevos módulos de bibliotecas compartidas dinámicas existentes que se utilizan en imágenes de espacio de nombres plano cargando una biblioteca compartida dinámica temporal con solo los nuevos módulos. Ten en cuenta que esto no tiene efecto en imágenes construidas con un espacio de nombres de dos niveles utilizando una biblioteca compartida dinámica a menos que también se utilice DYLD\_FORCE\_FLAT\_NAMESPACE.

Esto es similar a **LD\_PRELOAD en Linux**.

Esta técnica también se puede **utilizar como una técnica ASEP** ya que cada aplicación instalada tiene un archivo plist llamado "Info.plist" que permite la **asignación de variables de entorno** utilizando una clave llamada `LSEnvironmental`.

{% hint style="info" %}
Desde 2012, **Apple ha reducido drásticamente el poder** de **`DYLD_INSERT_LIBRARIES`**.

Ve al código y **verifica `src/dyld.cpp`**. En la función **`pruneEnvironmentVariables`** puedes ver que las variables **`DYLD_*`** se eliminan.

En la función **`processRestricted`** se establece la razón de la restricción. Al verificar ese código, puedes ver que las razones son:

* El binario es `setuid/setgid`
* Existe la sección `__RESTRICT/__restrict` en el binario macho.
* El software tiene permisos (tiempo de ejecución endurecido) sin el permiso [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Verifica los **permisos** de un binario con: `codesign -dv --entitlements :- </ruta/al/binario>`

En versiones más actualizadas, puedes encontrar esta lógica en la segunda parte de la función **`configureProcessRestrictions`**. Sin embargo, lo que se ejecuta en versiones más nuevas son las **verificaciones iniciales de la función** (puedes eliminar los ifs relacionados con iOS o simulación, ya que no se utilizarán en macOS).
{% endhint %}

### Validación de Bibliotecas

Incluso si el binario permite el uso de la variable de entorno **`DYLD_INSERT_LIBRARIES`**, si el binario verifica la firma de la biblioteca para cargarla, no cargará una biblioteca personalizada.

Para cargar una biblioteca personalizada, el binario debe tener **uno de los siguientes permisos**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o el binario **no debe tener** la **bandera de tiempo de ejecución endurecido** o la **bandera de validación de biblioteca**.

Puedes verificar si un binario tiene **tiempo de ejecución endurecido** con `codesign --display --verbose <bin>` verificando la bandera de tiempo de ejecución en **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

También puedes cargar una biblioteca si está **firmada con el mismo certificado que el binario**.

Encuentra un ejemplo de cómo (ab)usar esto y verificar las restricciones en:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}
## Secuestro de Dylib

{% hint style="danger" %}
Recuerda que también se aplican las restricciones de **Validación de Bibliotecas anteriores** para realizar ataques de secuestro de Dylib.
{% endhint %}

Al igual que en Windows, en MacOS también puedes **secuestrar dylibs** para hacer que las **aplicaciones** ejecuten **código arbitrario**. Sin embargo, la forma en que las aplicaciones de **MacOS** cargan bibliotecas es **más restrictiva** que en Windows. Esto implica que los desarrolladores de malware aún pueden usar esta técnica para **ocultarse**, pero la probabilidad de poder **abusar de esto para escalar privilegios es mucho menor**.

En primer lugar, es **más común** encontrar que los binarios de MacOS indican la **ruta completa** de las bibliotecas a cargar. Y en segundo lugar, **MacOS nunca busca** en las carpetas de **$PATH** las bibliotecas.

La **parte principal** del **código** relacionado con esta funcionalidad se encuentra en **`ImageLoader::recursiveLoadLibraries`** en `ImageLoader.cpp`.

Hay **4 comandos diferentes de encabezado** que un binario macho puede usar para cargar bibliotecas:

* El comando **`LC_LOAD_DYLIB`** es el comando común para cargar una dylib.
* El comando **`LC_LOAD_WEAK_DYLIB`** funciona como el anterior, pero si no se encuentra la dylib, la ejecución continúa sin ningún error.
* El comando **`LC_REEXPORT_DYLIB`** se utiliza para hacer de intermediario (o reexportar) los símbolos de una biblioteca diferente.
* El comando **`LC_LOAD_UPWARD_DYLIB`** se utiliza cuando dos bibliotecas dependen una de la otra (esto se llama una _dependencia ascendente_).

Sin embargo, hay **2 tipos de secuestro de dylib**:

* **Bibliotecas débilmente vinculadas que faltan**: Esto significa que la aplicación intentará cargar una biblioteca que no existe configurada con **LC\_LOAD\_WEAK\_DYLIB**. Entonces, **si un atacante coloca una dylib donde se espera que se cargue**.
* El hecho de que el enlace sea "débil" significa que la aplicación seguirá funcionando incluso si no se encuentra la biblioteca.
* El **código relacionado** con esto se encuentra en la función `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, donde `lib->required` es `false` solo cuando `LC_LOAD_WEAK_DYLIB` es verdadero.
* **Encontrar bibliotecas débilmente vinculadas** en binarios con (más adelante tienes un ejemplo de cómo crear bibliotecas de secuestro):
* ```bash
otool -l </ruta/al/binario> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configurado con @rpath**: Los binarios Mach-O pueden tener los comandos **`LC_RPATH`** y **`LC_LOAD_DYLIB`**. Según los **valores** de esos comandos, las **bibliotecas** se cargarán desde **directorios diferentes**.
* **`LC_RPATH`** contiene las rutas de algunas carpetas utilizadas para cargar bibliotecas por el binario.
* **`LC_LOAD_DYLIB`** contiene la ruta de bibliotecas específicas para cargar. Estas rutas pueden contener **`@rpath`**, que será **reemplazado** por los valores en **`LC_RPATH`**. Si hay varias rutas en **`LC_RPATH`**, se utilizarán todas para buscar la biblioteca a cargar. Ejemplo:
* Si **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` y **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` y `/application/app.app/Contents/Framework/v2/`. Ambas carpetas se utilizarán para cargar `library.dylib`**.** Si la biblioteca no existe en `[...]/v1/` y el atacante podría colocarla allí para secuestrar la carga de la biblioteca en `[...]/v2/` ya que se sigue el orden de las rutas en **`LC_LOAD_DYLIB`**.
* **Encontrar rutas y bibliotecas rpath** en binarios con: `otool -l </ruta/al/binario> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Es la **ruta** al directorio que contiene el **archivo ejecutable principal**.

**`@loader_path`**: Es la **ruta** al **directorio** que contiene el **binario Mach-O** que contiene el comando de carga.

* Cuando se usa en un ejecutable, **`@loader_path`** es efectivamente lo **mismo** que **`@executable_path`**.
* Cuando se usa en una **dylib**, **`@loader_path`** proporciona la **ruta** a la **dylib**.
{% endhint %}

La forma de **escalar privilegios** abusando de esta funcionalidad sería en el caso raro de que una **aplicación** que se ejecuta **como** **root** esté **buscando** alguna **biblioteca en alguna carpeta donde el atacante tenga permisos de escritura**.

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
Recuerda que también se aplican las restricciones de **Validación de Bibliotecas anteriores** para realizar ataques de secuestro de Dlopen.
{% endhint %}

De **`man dlopen`**:

* Cuando la ruta **no contiene el carácter de barra diagonal** (es decir, es solo un nombre de archivo), **dlopen() buscará**. Si **`$DYLD_LIBRARY_PATH`** se estableció al inicio, dyld buscará primero en ese directorio. A continuación, si el archivo mach-o que llama o el ejecutable principal especifican un **`LC_RPATH`**, entonces dyld buscará en esos directorios. A continuación, si el proceso no tiene restricciones, dyld buscará en el **directorio de trabajo actual**. Por último, para los binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al inicio, dyld buscará en **esos directorios**, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso no tiene restricciones), y luego en **`/usr/lib/`** (esta información se obtuvo de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (si no tiene restricciones)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si no tiene restricciones)
6. `/usr/lib/`

{% hint style="danger" %}
Si no hay barras diagonales en el nombre, habría 2 formas de hacer un secuestro:

* Si algún **`LC_RPATH`** es **editable** (pero se verifica la firma, por lo que también necesitas que el binario no tenga restricciones)
* Si el binario no tiene restricciones y luego es posible cargar algo desde el CWD (o abusando de una de las variables de entorno mencionadas)
{% endhint %}
* Cuando la ruta **se parece a una ruta de framework** (por ejemplo, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** se estableció al inicio, dyld buscará primero en ese directorio la **ruta parcial del framework** (por ejemplo, `foo.framework/foo`). A continuación, dyld intentará la **ruta proporcionada tal cual** (usando el directorio de trabajo actual para rutas relativas). Por último, para binarios antiguos, dyld intentará algunas alternativas. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** se estableció al inicio, dyld buscará en esos directorios. De lo contrario, buscará en **`/Library/Frameworks`** (en macOS si el proceso no tiene restricciones), luego en **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. ruta proporcionada (usando el directorio de trabajo actual para rutas relativas si no hay restricciones)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si no hay restricciones)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Si es una ruta de framework, la forma de secuestrarla sería:

* Si el proceso no tiene restricciones, abusando de la **ruta relativa desde el directorio de trabajo actual** y las variables de entorno mencionadas (aunque no se menciona en la documentación si el proceso tiene restricciones, las variables de entorno DYLD\_\* se eliminan)
{% endhint %}

* Cuando la ruta **contiene una barra pero no es una ruta de framework** (es decir, una ruta completa o una ruta parcial a un dylib), dlopen() primero busca (si está configurado) en **`$DYLD_LIBRARY_PATH`** (con la parte final de la ruta). A continuación, dyld **intenta la ruta proporcionada** (usando el directorio de trabajo actual para rutas relativas, pero solo para procesos sin restricciones). Por último, para binarios antiguos, dyld intentará alternativas. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** se estableció al inicio, dyld buscará en esos directorios, de lo contrario, dyld buscará en **`/usr/local/lib/`** (si el proceso no tiene restricciones), y luego en **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. ruta proporcionada (usando el directorio de trabajo actual para rutas relativas si no hay restricciones)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si no hay restricciones)
5. `/usr/lib/`

{% hint style="danger" %}
Si hay barras en el nombre y no es un framework, la forma de secuestrarlo sería:

* Si el binario no tiene restricciones y luego es posible cargar algo desde el directorio de trabajo actual o `/usr/local/lib` (o abusando de una de las variables de entorno mencionadas)
{% endhint %}

{% hint style="info" %}
Nota: No hay archivos de configuración para **controlar la búsqueda de dlopen**.

Nota: Si el ejecutable principal es un binario **set\[ug]id o firmado con entitlements**, entonces **se ignoran todas las variables de entorno**, y solo se puede usar una ruta completa (consulte las restricciones de DYLD\_INSERT\_LIBRARIES para obtener información más detallada).

Nota: Las plataformas de Apple utilizan archivos "universales" para combinar bibliotecas de 32 bits y 64 bits. Esto significa que no hay **rutas de búsqueda separadas para 32 bits y 64 bits**.

Nota: En las plataformas de Apple, la mayoría de las bibliotecas del sistema operativo se **combinan en la caché de dyld** y no existen en el disco. Por lo tanto, llamar a **`stat()`** para verificar si una biblioteca del sistema operativo existe **no funcionará**. Sin embargo, **`dlopen_preflight()`** utiliza los mismos pasos que **`dlopen()`** para encontrar un archivo mach-o compatible.
{% endhint %}

**Verificar rutas**

Veamos todas las opciones con el siguiente código:
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
Si lo compilas y ejecutas, podrás ver **dónde se buscó sin éxito cada biblioteca**. Además, podrías **filtrar los registros del sistema de archivos**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Podar variables de entorno `DYLD_*` y `LD_LIBRARY_PATH`

En el archivo `dyld-dyld-832.7.1/src/dyld2.cpp` es posible encontrar la función **`pruneEnvironmentVariables`**, la cual eliminará cualquier variable de entorno que **comience con `DYLD_`** y **`LD_LIBRARY_PATH=`**.

También establecerá específicamente a **null** las variables de entorno **`DYLD_FALLBACK_FRAMEWORK_PATH`** y **`DYLD_FALLBACK_LIBRARY_PATH`** para binarios **suid** y **sgid**.

Esta función es llamada desde la función **`_main`** del mismo archivo si se está apuntando a OSX de la siguiente manera:
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
Lo cual significa básicamente que si el binario es **suid** o **sgid**, o tiene un segmento **RESTRICT** en los encabezados o fue firmado con la bandera **CS\_RESTRICT**, entonces **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** es verdadero y las variables de entorno son eliminadas.

Tenga en cuenta que si CS\_REQUIRE\_LV es verdadero, entonces las variables no serán eliminadas, pero la validación de la biblioteca verificará que estén utilizando el mismo certificado que el binario original.

## Verificar Restricciones

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

The `__RESTRICT` section is a segment in macOS that is used to restrict the execution of certain processes. This section is designed to prevent unauthorized access and privilege escalation by limiting the actions that can be performed by a process.

When a process is placed in the `__RESTRICT` section, it is restricted from executing certain operations, such as loading dynamic libraries or injecting code into other processes. This helps to protect the integrity and security of the system.

By leveraging the `__RESTRICT` section, an attacker can bypass these restrictions and inject malicious code into a process. This technique is known as library injection and can be used to escalate privileges and gain unauthorized access to sensitive information.

To perform library injection, the attacker needs to identify a vulnerable process and find a way to inject their malicious code into it. This can be done by exploiting vulnerabilities in the target process or by using techniques such as code injection or DLL hijacking.

Once the malicious code is injected into the target process, the attacker can execute arbitrary commands, access sensitive data, or perform other malicious activities. This can lead to a complete compromise of the system and the leakage of sensitive information.

To protect against library injection attacks, it is important to implement proper security measures, such as keeping the system and applications up to date with the latest patches, using strong authentication mechanisms, and implementing access controls to limit the privileges of processes.

By understanding the `__RESTRICT` section and the risks associated with library injection, system administrators and security professionals can take proactive steps to secure their macOS systems and prevent unauthorized access and privilege escalation.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Entorno de ejecución fortificado

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
Ten en cuenta que incluso si hay binarios firmados con la bandera **`0x0(none)`**, pueden obtener la bandera **`CS_RESTRICT`** dinámicamente cuando se ejecutan y, por lo tanto, esta técnica no funcionará en ellos.

Puedes verificar si un proceso tiene esta bandera con (obtén [**csops aquí**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
y luego verifica si la bandera 0x800 está habilitada.
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
