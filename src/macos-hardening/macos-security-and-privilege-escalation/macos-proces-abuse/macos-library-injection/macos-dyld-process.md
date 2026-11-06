# Proceso Dyld de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

El **entrypoint** real de un binario Mach-o es el enlazador dinámico, definido en `LC_LOAD_DYLINKER`, que suele ser `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Este enlazador debe localizar todas las bibliotecas ejecutables, cargarlas en memoria y enlazar todas las bibliotecas no lazy. Solo después de este proceso se ejecutará el punto de entrada del binario.

Por supuesto, **`dyld`** no tiene dependencias (usa syscalls y fragmentos de libSystem).

> [!CAUTION]
> Si este enlazador contiene alguna vulnerabilidad, como se ejecuta antes que cualquier binario (incluso los altamente privilegiados), sería posible **escalar privilegios**.

### Flujo

Dyld se carga mediante **`dyldboostrap::start`**, que también carga elementos como el **stack canary**. Esto se debe a que esta función recibe en su vector de argumentos **`apple`** este y otros **valores** **sensibles**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** es el punto de entrada de dyld y su primera tarea es ejecutar `configureProcessRestrictions()`, que normalmente restringe las variables de entorno **`DYLD_*`** explicadas en:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Después, mapea la caché compartida de dyld, que preenlaza todas las bibliotecas importantes del sistema, y luego mapea las bibliotecas de las que depende el binario y continúa de forma recursiva hasta que se cargan todas las bibliotecas necesarias. Por lo tanto:

1. empieza cargando las bibliotecas insertadas con `DYLD_INSERT_LIBRARIES` (si está permitido)
2. Luego, las de la caché compartida
3. Luego, las importadas
   1. Después continúa importando bibliotecas de forma recursiva

Una vez cargadas todas, se ejecutan los **initialisers** de estas bibliotecas. Se codifican mediante **`__attribute__((constructor))`**, definido en `LC_ROUTINES[_64]` (ahora obsoleto), o mediante un puntero en una sección marcada con `S_MOD_INIT_FUNC_POINTERS` (normalmente: **`__DATA.__MOD_INIT_FUNC`**).

Los terminadores se codifican con **`__attribute__((destructor))`** y se encuentran en una sección marcada con `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Consulta también: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Todos los binarios de macOS están enlazados dinámicamente. Por lo tanto, contienen algunas secciones de stubs que ayudan al binario a saltar al código correcto en distintas máquinas y contextos. Cuando se ejecuta el binario, dyld es quien debe resolver estas direcciones (al menos las no lazy).

Algunas secciones de stubs del binario:

- **`__TEXT.__[auth_]stubs`**: Punteros desde secciones `__DATA`
- **`__TEXT.__stub_helper`**: Pequeño fragmento de código que invoca el enlazado dinámico con información sobre la función que se debe llamar
- **`__DATA.__[auth_]got`**: Global Offset Table (direcciones de funciones importadas; una vez resueltas, se enlazan durante la carga porque están marcadas con el flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Punteros a símbolos no lazy (se enlazan durante la carga porque están marcados con el flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Punteros a símbolos lazy (se enlazan en el primer acceso)

> [!WARNING]
> Ten en cuenta que los punteros con el prefijo "auth\_" usan una clave de cifrado en el proceso para protegerlos (PAC). Además, es posible usar la instrucción arm64 `BLRA[A/B]` para verificar el puntero antes de seguirlo. También se puede usar RETA\[A/B] en lugar de una dirección RET.\
> De hecho, el código de **`__TEXT.__auth_stubs`** usa **`braa`** en lugar de **`bl`** para llamar a la función solicitada y autenticar el puntero.
>
> Ten en cuenta también que las versiones actuales de dyld cargan **todo como no lazy**.

### Encontrar símbolos lazy

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Parte interesante del desensamblado:

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

En el desensamblado de la sección **`__stubs`**:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

puedes ver que estamos **saltando a la dirección de la GOT**, que en este caso se resuelve de forma no lazy y contendrá la dirección de la función printf.

En otras situaciones, en lugar de saltar directamente a la GOT, podría saltar a **`__DATA.__la_symbol_ptr`**, que cargará un valor que representa la función que intenta cargar; luego saltará a **`__TEXT.__stub_helper`**, que salta a **`__DATA.__nl_symbol_ptr`**, que contiene la dirección de **`dyld_stub_binder`**, que recibe como parámetros el número de la función y una dirección.\
El binder resuelve el símbolo y actualiza su slot en **`__DATA.__la_symbol_ptr`**. En llamadas posteriores, el stub usa ese puntero resuelto; no se vuelve a escribir en **`__TEXT.__stub_helper`**.<sup>[[5]](#references)</sup>

> [!TIP]
> Sin embargo, ten en cuenta que las versiones actuales de dyld cargan todo como non-lazy.

#### Opcodes de Dyld

Por último, **`dyld_stub_binder`** necesita encontrar la función indicada y escribirla en la dirección correcta para no tener que buscarla de nuevo. Para ello, usa opcodes (una máquina de estados finitos) dentro de dyld.

## Vector de argumentos apple\[]

En macOS, la función principal recibe en realidad 4 argumentos en lugar de 3. El cuarto se llama apple y cada entrada tiene el formato `key=value`. Por ejemplo:

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

Resultado:

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

> [!TIP]
> Para cuando estos valores llegan a la función principal, ya se ha eliminado de ellos la información sensible; de lo contrario, habría ocurrido una filtración de datos.

Es posible ver todos estos valores interesantes depurando antes de entrar en `main` con:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
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

## dyld_all_image_infos

Esta es una estructura exportada por dyld con información sobre su estado. Se puede consultar en el [**código fuente**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) e incluye información como la versión, un puntero al array dyld_image_info, a dyld_image_notifier, si el proceso está separado de la shared cache, si se llamó al inicializador de libSystem, un puntero a la propia cabecera Mach de dyld, un puntero a la cadena de versión de dyld...<sup>[[4]](#references)</sup>

## Variables de entorno de dyld

### Depurar dyld

Variables de entorno interesantes que ayudan a entender qué está haciendo dyld:

- **DYLD_PRINT_LIBRARIES**

Comprueba cada biblioteca que se carga:

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

- **DYLD_PRINT_SEGMENTS**

Comprueba cómo se carga cada biblioteca:

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

- **DYLD_PRINT_INITIALIZERS**

Imprime cuándo se ejecuta el inicializador de cada biblioteca:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Rastrear la resolución de bibliotecas en tiempo de ejecución

Para un lanzamiento que puedas controlar, rastrea un candidato `@rpath` o de biblioteca débil antes de colocar una dylib de reemplazo. `DYLD_PRINT_SEARCHING` informa de las rutas que dyld considera, mientras que `DYLD_PRINT_LIBRARIES` muestra las imágenes que se cargan realmente. `DYLD_PRINT_LOADERS` distingue un `JustInTimeLoader` de un `PrebuiltLoader` e informa del uso de un conjunto de loaders precompilado.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Busca la línea `LC_RPATH` que identifica la imagen que proporcionó una ruta de búsqueda y, luego, compara los candidatos `possible path(...)` con `found: dylib-from-disk`, `found: dylib-from-cache` o un rechazo. Una ruta candidata **no** demuestra que se haya cargado la dylib. La primera ruta de disco utilizable antes de la biblioteca esperada es la que debes comprobar para verificar el acceso de escritura y las [restricciones de library validation](./#library-validation).<sup>[[7]](#references)</sup>

Un loader precompilado puede reutilizar la información de dependencias registrada en lugar de repetir una búsqueda completa de rutas. Por lo tanto, una salida de búsqueda escasa no demuestra que una imagen no tenga dependencias; inspecciona sus comandos de carga con `otool -l` y compara la lista de bibliotecas.<sup>[[8]](#references)</sup> Estos diagnósticos también requieren que dyld tenga permiso para imprimir variables, por lo que un destino protegido podría ignorarlos por completo.<sup>[[2]](#references)</sup> Consulta [Dylib Hijacking](./#dylib-hijacking) para conocer los requisitos de la biblioteca de reemplazo.

### Otros

Algunas opciones siguientes son específicas de versiones anteriores de dyld. Comprueba si son compatibles con la versión de destino en lugar de asumir que todas las variables siguen funcionando.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Las vinculaciones lazy se resuelven junto con las no lazy
- `DYLD_DISABLE_PREFETCH`: Desactiva la precarga del contenido de \_\_DATA y \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Vinculaciones de nivel único
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Rutas de resolución
- `DYLD_INSERT_LIBRARIES`: Carga una biblioteca específica
- `DYLD_PRINT_TO_FILE`: Escribe la depuración de dyld en un archivo
- `DYLD_PRINT_APIS`: Imprime las llamadas a la API de libdyld
- `DYLD_PRINT_APIS_APP`: Imprime las llamadas a la API de libdyld realizadas por el proceso principal
- `DYLD_PRINT_BINDINGS`: Imprime los símbolos cuando se vinculan
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Imprime las vinculaciones de símbolos débiles
- `DYLD_PRINT_CODE_SIGNATURES`: Imprime las operaciones de registro de firmas de código
- `DYLD_PRINT_DOFS`: Imprime las secciones de formato de objeto de D-Trace a medida que se cargan
- `DYLD_PRINT_ENV`: Imprime las variables de entorno que ve dyld
- `DYLD_PRINT_INTERPOSING`: Imprime las operaciones de interposición
- `DYLD_PRINT_LIBRARIES`: Imprime las bibliotecas cargadas
- `DYLD_PRINT_OPTS`: Imprime las opciones de carga
- `DYLD_PRINT_REBASINGS` (dyld2): Imprime las operaciones de rebaseo de símbolos
- `DYLD_PRINT_RPATHS` (dyld2): Imprime las expansiones de `@rpath`
- `DYLD_PRINT_SEGMENTS`: Imprime las asignaciones de segmentos Mach-O
- `DYLD_PRINT_STATISTICS`: Imprime estadísticas de tiempo
- `DYLD_PRINT_STATISTICS_DETAILS`: Imprime estadísticas detalladas de tiempo
- `DYLD_PRINT_WARNINGS`: Imprime mensajes de advertencia
- `DYLD_SHARED_CACHE_DIR`: Ruta que se usará para la caché de bibliotecas compartidas
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Habilita las closures

Es posible encontrar más opciones con algo como:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

O descargando el proyecto dyld desde [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) y ejecutándolo dentro de la carpeta:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (ruta de inicio del proceso)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (configuración del proceso y de seguridad)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (lado del kernel de `execve`, carga de dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (estructura `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — enlace de punteros a símbolos lazy y non-lazy](https://github.com/meta/fishhook)
- [6] [dyld(1) — diagnósticos del enlazador dinámico](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — búsqueda de rutas de bibliotecas en tiempo de ejecución](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — cargadores precompilados y just-in-time](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — nombres de variables de diagnóstico heredados](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
