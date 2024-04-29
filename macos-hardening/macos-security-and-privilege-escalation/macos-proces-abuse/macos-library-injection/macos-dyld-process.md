# Proceso Dyld de macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

El verdadero **punto de entrada** de un binario Mach-o es el enlazador dinámico, definido en `LC_LOAD_DYLINKER`, que generalmente es `/usr/lib/dyld`.

Este enlazador necesitará localizar todas las bibliotecas ejecutables, mapearlas en memoria y enlazar todas las bibliotecas no perezosas. Solo después de este proceso se ejecutará el punto de entrada del binario.

Por supuesto, **`dyld`** no tiene dependencias (utiliza llamadas al sistema y fragmentos de libSystem).

{% hint style="danger" %}
Si este enlazador contiene alguna vulnerabilidad, al ejecutarse antes de ejecutar cualquier binario (incluso los altamente privilegiados), sería posible **escalar privilegios**.
{% endhint %}

### Flujo

Dyld será cargado por **`dyldboostrap::start`**, que también cargará cosas como el **canario de pila**. Esto se debe a que esta función recibirá en su argumento **`apple`** este y otros **valores** **sensibles**.

**`dyls::_main()`** es el punto de entrada de dyld y su primera tarea es ejecutar `configureProcessRestrictions()`, que generalmente restringe las variables de entorno **`DYLD_*`** explicadas en:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Luego, mapea la caché compartida de dyld que preenlaza todas las bibliotecas del sistema importantes y luego mapea las bibliotecas en las que depende el binario y continúa de forma recursiva hasta que se cargan todas las bibliotecas necesarias. Por lo tanto:

1. comienza a cargar bibliotecas insertadas con `DYLD_INSERT_LIBRARIES` (si se permite)
2. Luego las compartidas en caché
3. Luego las importadas
4. Luego continúa importando bibliotecas de forma recursiva

Una vez que todas están cargadas, se ejecutan los **inicializadores** de estas bibliotecas. Estos están codificados usando **`__attribute__((constructor))`** definidos en `LC_ROUTINES[_64]` (ahora obsoletos) o mediante un puntero en una sección marcada con `S_MOD_INIT_FUNC_POINTERS` (generalmente: **`__DATA.__MOD_INIT_FUNC`**).

Los terminadores están codificados con **`__attribute__((destructor))`** y se encuentran en una sección marcada con `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Todos los binarios en macOS están enlazados dinámicamente. Por lo tanto, contienen algunas secciones de stubs que ayudan al binario a saltar al código correcto en diferentes máquinas y contextos. Es dyld cuando se ejecuta el binario el cerebro que necesita resolver estas direcciones (al menos las no perezosas).

Algunas secciones de stubs en el binario:

* **`__TEXT.__[auth_]stubs`**: Punteros de secciones `__DATA`
* **`__TEXT.__stub_helper`**: Pequeño código que invoca el enlace dinámico con información sobre la función a llamar
* **`__DATA.__[auth_]got`**: Tabla de desplazamiento global (direcciones a funciones importadas, cuando se resuelven, (vinculadas durante el tiempo de carga ya que está marcada con la bandera `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Punteros de símbolos no perezosos (vinculados durante el tiempo de carga ya que está marcada con la bandera `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Punteros de símbolos perezosos (vinculados en el primer acceso)

{% hint style="warning" %}
Ten en cuenta que los punteros con el prefijo "auth\_" utilizan una clave de cifrado en proceso para protegerlo (PAC). Además, es posible utilizar la instrucción arm64 `BLRA[A/B]` para verificar el puntero antes de seguirlo. Y el RETA\[A/B\] se puede utilizar en lugar de una dirección RET.\
De hecho, el código en **`__TEXT.__auth_stubs`** utilizará **`braa`** en lugar de **`bl`** para llamar a la función solicitada para autenticar el puntero.

También ten en cuenta que las versiones actuales de dyld cargan **todo como no perezoso**.
{% endhint %}

### Encontrar símbolos perezosos
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Parte interesante del desensamblaje:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Es posible ver que el salto para llamar a printf va a **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
En el desensamblaje de la sección **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Puedes ver que estamos **saltando a la dirección de la GOT**, que en este caso se resuelve de forma no perezosa y contendrá la dirección de la función printf.

En otras situaciones, en lugar de saltar directamente a la GOT, podría saltar a **`__DATA.__la_symbol_ptr`** que cargará un valor que representa la función que está intentando cargar, luego saltar a **`__TEXT.__stub_helper`** que salta al **`__DATA.__nl_symbol_ptr`** que contiene la dirección de **`dyld_stub_binder`** que toma como parámetros el número de la función y una dirección.\
Esta última función, después de encontrar la dirección de la función buscada, la escribe en la ubicación correspondiente en **`__TEXT.__stub_helper`** para evitar búsquedas en el futuro.

{% hint style="success" %}
Sin embargo, ten en cuenta que las versiones actuales de dyld cargan todo como no perezoso.
{% endhint %}

#### Opcodes de Dyld

Finalmente, **`dyld_stub_binder`** necesita encontrar la función indicada y escribirla en la dirección adecuada para no buscarla nuevamente. Para hacerlo, utiliza opcodes (una máquina de estados finitos) dentro de dyld.

## Vector de argumentos de apple\[]

En macOS, la función principal recibe en realidad 4 argumentos en lugar de 3. El cuarto se llama apple y cada entrada está en forma de `clave=valor`. Por ejemplo:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
El proceso de inyección de bibliotecas en macOS implica cargar una biblioteca dinámica en un proceso en ejecución. Esto se logra manipulando el cargador dinámico del sistema, `dyld`, para forzar la carga de una biblioteca maliciosa. Una vez cargada la biblioteca, puede utilizarse para realizar diversas acciones, como el secuestro de funciones del sistema o la escalada de privilegios.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Para el momento en que estos valores llegan a la función principal, la información sensible ya ha sido eliminada de ellos o podría haber sido una fuga de datos.
{% endhint %}

es posible ver todos estos valores interesantes depurando antes de llegar a la función principal con:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Executable actual establecido en '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Esta es una estructura exportada por dyld con información sobre el estado de dyld que se puede encontrar en el [**código fuente**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) con información como la versión, puntero a la matriz dyld\_image_info, a dyld\_image_notifier, si el proceso está separado de la caché compartida, si se llamó al inicializador de libSystem, puntero al encabezado Mach propio de dyls, puntero a la cadena de versión de dyld...

## Variables de entorno de dyld

### depurar dyld

Variables de entorno interesantes que ayudan a comprender qué está haciendo dyld:

* **DYLD\_PRINT\_LIBRARIES**

Verifica cada biblioteca que se carga:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Verifique cómo se carga cada biblioteca:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Imprime cuándo se está ejecutando cada inicializador de biblioteca:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Otros

* `DYLD_BIND_AT_LAUNCH`: Las vinculaciones perezosas se resuelven con las no perezosas
* `DYLD_DISABLE_PREFETCH`: Deshabilita la precarga de contenido \_\_DATA y \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Vinculaciones de un solo nivel
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Rutas de resolución
* `DYLD_INSERT_LIBRARIES`: Carga una biblioteca específica
* `DYLD_PRINT_TO_FILE`: Escribe la depuración de dyld en un archivo
* `DYLD_PRINT_APIS`: Imprime llamadas de API de libdyld
* `DYLD_PRINT_APIS_APP`: Imprime llamadas de API de libdyld realizadas por main
* `DYLD_PRINT_BINDINGS`: Imprime símbolos cuando se vinculan
* `DYLD_WEAK_BINDINGS`: Solo imprime símbolos débiles cuando se vinculan
* `DYLD_PRINT_CODE_SIGNATURES`: Imprime operaciones de registro de firma de código
* `DYLD_PRINT_DOFS`: Imprime secciones de formato de objeto D-Trace cargadas
* `DYLD_PRINT_ENV`: Imprime env visto por dyld
* `DYLD_PRINT_INTERPOSTING`: Imprime operaciones de interposición
* `DYLD_PRINT_LIBRARIES`: Imprime bibliotecas cargadas
* `DYLD_PRINT_OPTS`: Imprime opciones de carga
* `DYLD_REBASING`: Imprime operaciones de reubicación de símbolos
* `DYLD_RPATHS`: Imprime expansiones de @rpath
* `DYLD_PRINT_SEGMENTS`: Imprime mapeos de segmentos Mach-O
* `DYLD_PRINT_STATISTICS`: Imprime estadísticas de tiempo
* `DYLD_PRINT_STATISTICS_DETAILS`: Imprime estadísticas detalladas de tiempo
* `DYLD_PRINT_WARNINGS`: Imprime mensajes de advertencia
* `DYLD_SHARED_CACHE_DIR`: Ruta a utilizar para la caché de bibliotecas compartidas
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Habilita los cierres

Es posible encontrar más con algo como:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
O descargando el proyecto dyld desde [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) y ejecutando dentro de la carpeta:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referencias

* [**\*OS Internals, Volumen I: Modo Usuario. Por Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
