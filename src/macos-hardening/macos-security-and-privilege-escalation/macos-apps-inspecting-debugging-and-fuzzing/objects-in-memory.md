# Objetos en memoria

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Los objetos CF* provienen de CoreFoundation, que proporciona más de 50 clases de objetos como `CFString`, `CFNumber` o `CFAllocator`.

Todas estas clases son instancias de la clase `CFRuntimeClass`, que al invocarse devuelve un índice en la `__CFRuntimeClassTable`. La CFRuntimeClass está definida en [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
```objectivec
// Some comments were added to the original code

enum { // Version field constants
_kCFRuntimeScannedObject =     (1UL << 0),
_kCFRuntimeResourcefulObject = (1UL << 2),  // tells CFRuntime to make use of the reclaim field
_kCFRuntimeCustomRefCount =    (1UL << 3),  // tells CFRuntime to make use of the refcount field
_kCFRuntimeRequiresAlignment = (1UL << 4),  // tells CFRuntime to make use of the requiredAlignment field
};

typedef struct __CFRuntimeClass {
CFIndex version;  // This is made a bitwise OR with the relevant previous flags

const char *className; // must be a pure ASCII string, nul-terminated
void (*init)(CFTypeRef cf);  // Initializer function
CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf); // Copy function, taking CFAllocatorRef and CFTypeRef to copy
void (*finalize)(CFTypeRef cf); // Finalizer function
Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2); // Function to be called by CFEqual()
CFHashCode (*hash)(CFTypeRef cf); // Function to be called by CFHash()
CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions); // Provides a CFStringRef with a textual description of the object// return str with retain
CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// CFStringRed with textual description of the object for CFCopyDescription

#define CF_RECLAIM_AVAILABLE 1
void (*reclaim)(CFTypeRef cf); // Or in _kCFRuntimeResourcefulObject in the .version to indicate this field should be used
// It not null, it's called when the last reference to the object is released

#define CF_REFCOUNT_AVAILABLE 1
// If not null, the following is called when incrementing or decrementing reference count
uint32_t (*refcount)(intptr_t op, CFTypeRef cf); // Or in _kCFRuntimeCustomRefCount in the .version to indicate this field should be used
// this field must be non-NULL when _kCFRuntimeCustomRefCount is in the .version field
// - if the callback is passed 1 in 'op' it should increment the 'cf's reference count and return 0
// - if the callback is passed 0 in 'op' it should return the 'cf's reference count, up to 32 bits
// - if the callback is passed -1 in 'op' it should decrement the 'cf's reference count; if it is now zero, 'cf' should be cleaned up and deallocated (the finalize callback above will NOT be called unless the process is running under GC, and CF does not deallocate the memory for you; if running under GC, finalize should do the object tear-down and free the object memory); then return 0
// remember to use saturation arithmetic logic and stop incrementing and decrementing when the ref count hits UINT32_MAX, or you will have a security bug
// remember that reference count incrementing/decrementing must be done thread-safely/atomically
// objects should be created/initialized with a custom ref-count of 1 by the class creation functions
// do not attempt to use any bits within the CFRuntimeBase for your reference count; store that in some additional field in your CF object

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define CF_REQUIRED_ALIGNMENT_AVAILABLE 1
// If not 0, allocation of object must be on this boundary
uintptr_t requiredAlignment; // Or in _kCFRuntimeRequiresAlignment in the .version field to indicate this field should be used; the allocator to _CFRuntimeCreateInstance() will be ignored in this case; if this is less than the minimum alignment the system supports, you'll get higher alignment; if this is not an alignment the system supports (e.g., most systems will only support powers of two, or if it is too high), the result (consequences) will be up to CF or the system to decide

} CFRuntimeClass;
```
## Objective-C

### Secciones de memoria usadas

La mayor parte de los datos usados por el runtime de Objective‑C cambian durante la ejecución, por lo que utiliza varias secciones de la familia de segmentos Mach‑O `__DATA` en memoria. Históricamente estas incluían:

- `__objc_msgrefs` (`message_ref_t`): Referencias de mensaje
- `__objc_ivar` (`ivar`): Variables de instancia
- `__objc_data` (`...`): Datos mutables
- `__objc_classrefs` (`Class`): Referencias a clases
- `__objc_superrefs` (`Class`): Referencias a superclases
- `__objc_protorefs` (`protocol_t *`): Referencias a protocolos
- `__objc_selrefs` (`SEL`): Referencias a selectores
- `__objc_const` (`...`): Datos r/o de clase y otros datos (con suerte) constantes
- `__objc_imageinfo` (`version, flags`): Usado durante la carga de la imagen: Versión actualmente `0`; Flags especifican soporte GC preoptimizado, etc.
- `__objc_protolist` (`protocol_t *`): Lista de protocolos
- `__objc_nlcatlist` (`category_t`): Puntero a Non-Lazy Categories definidas en este binario
- `__objc_catlist` (`category_t`): Puntero a Categories definidas en este binario
- `__objc_nlclslist` (`classref_t`): Puntero a Non-Lazy Objective‑C classes definidas en este binario
- `__objc_classlist` (`classref_t`): Punteros a todas las Objective‑C classes definidas en este binario

También usa algunas secciones en el segmento `__TEXT` para almacenar constantes:

- `__objc_methname` (C‑String): Nombres de métodos
- `__objc_classname` (C‑String): Nombres de clases
- `__objc_methtype` (C‑String): Tipos de método

Los macOS/iOS modernos (especialmente en Apple Silicon) también colocan metadatos Objective‑C/Swift en:

- `__DATA_CONST`: metadatos Objective‑C inmutables que pueden compartirse como solo‑lectura entre procesos (por ejemplo, muchas listas `__objc_*` ahora viven aquí).
- `__AUTH` / `__AUTH_CONST`: segmentos que contienen punteros que deben autenticarse en carga o en tiempo de uso en arm64e (Pointer Authentication). También verás `__auth_got` en `__AUTH_CONST` en lugar del legado `__la_symbol_ptr`/`__got` solamente. When instrumenting or hooking, recuerda tener en cuenta tanto las entradas `__got` como `__auth_got` en binarios modernos.

Para contexto sobre la pre‑optimización de dyld (p. ej., selector uniquing y precomputation de clase/protocolo) y por qué muchas de estas secciones ya están "arregladas" cuando provienen del shared cache, revisa las fuentes Apple `objc-opt` y las notas del dyld shared cache. Esto afecta dónde y cómo puedes parchear metadatos en tiempo de ejecución.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Codificación de tipos

Objective‑C utiliza mangling para codificar los tipos de selectores y variables de tipos simples y complejos:

- Los tipos primitivos usan la primera letra del tipo: `i` para `int`, `c` para `char`, `l` para `long`... y usan la letra mayúscula en caso de que sea unsigned (`L` para `unsigned long`).
- Otros tipos de datos usan otras letras o símbolos como `q` para `long long`, `b` para bitfields, `B` para booleanos, `#` para clases, `@` para `id`, `*` para `char *`, `^` para punteros genéricos y `?` para indefinido.
- Arrays, estructuras y unions usan `[` , `{` y `(` respectivamente.

#### Ejemplo de declaración de método
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
El selector sería `processString:withOptions:andError:`

#### Codificación de tipos

- `id` se codifica como `@`
- `char *` se codifica como `*`

La codificación completa de tipos para el método es:
```less
@24@0:8@16*20^@24
```
#### Desglose detallado

1. Tipo de retorno (`NSString *`): Codificado como `@` con longitud 24
2. `self` (instancia del objeto): Codificado como `@`, en el offset 0
3. `_cmd` (selector): Codificado como `:`, en el offset 8
4. Primer argumento (`char * input`): Codificado como `*`, en el offset 16
5. Segundo argumento (`NSDictionary * options`): Codificado como `@`, en el offset 20
6. Tercer argumento (`NSError ** error`): Codificado como `^@`, en el offset 24

Con el selector + la codificación puedes reconstruir el método.

### Clases

Las clases en Objective‑C son C structs con propiedades, punteros a métodos, etc. Es posible encontrar la struct `objc_class` en el [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
```objectivec
struct objc_class : objc_object {
// Class ISA;
Class superclass;
cache_t cache;             // formerly cache pointer and vtable
class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags

class_rw_t *data() {
return bits.data();
}
void setData(class_rw_t *newData) {
bits.setData(newData);
}

void setInfo(uint32_t set) {
assert(isFuture()  ||  isRealized());
data()->setFlags(set);
}
[...]
```
Esta clase usa algunos bits del campo `isa` para indicar información sobre la clase.

Además, el struct tiene un puntero al struct `class_ro_t` almacenado en disco que contiene atributos de la clase como su nombre, métodos base, propiedades y variables de instancia. En tiempo de ejecución se utiliza una estructura adicional `class_rw_t` que contiene punteros que pueden modificarse, como métodos, protocolos y propiedades.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Representaciones modernas de objetos en memoria (arm64e, punteros etiquetados, Swift)

### isa no puntero y Pointer Authentication (arm64e)

En Apple Silicon y en runtimes recientes el `isa` de Objective‑C no siempre es un puntero de clase sin procesar. En arm64e es una estructura empaquetada que también puede llevar un Pointer Authentication Code (PAC). Dependiendo de la plataforma puede incluir campos como `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` y el propio puntero de clase (desplazado o con signo). Esto significa que desreferenciar a ciegas los primeros 8 bytes de un objeto Objective‑C no siempre devolverá un puntero `Class` válido.

Notas prácticas al depurar en arm64e:

- LLDB normalmente eliminará los bits PAC por ti al imprimir objetos Objective‑C con `po`, pero al trabajar con punteros crudos puede que necesites quitar la autenticación manualmente:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Muchos punteros a funciones/datos en Mach‑O residirán en `__AUTH`/`__AUTH_CONST` y requieren autenticación antes de usarlos. Si estás interponiendo o re‑binding (p. ej., estilo fishhook), asegúrate de manejar también `__auth_got` además del antiguo `__got`.

Para una inmersión profunda en las garantías del lenguaje/ABI y los intrínsecos de `<ptrauth.h>` disponibles en Clang/LLVM, consulta la referencia al final de esta página.

### Objetos con punteros etiquetados

Algunas clases de Foundation evitan la asignación en el heap codificando la carga útil del objeto directamente en el valor del puntero (tagged pointers). La detección difiere según la plataforma (p. ej., el bit más significativo en arm64, el menos significativo en macOS x86_64). Los objetos tagged no tienen un `isa` regular almacenado en memoria; el runtime resuelve la clase a partir de los bits de etiqueta. Al inspeccionar valores arbitrarios de `id`:

- Usa las APIs del runtime en lugar de inspeccionar el campo `isa`: `object_getClass(obj)` / `[obj class]`.
- En LLDB, simplemente `po (id)0xADDR` imprimirá instancias con tagged pointers correctamente porque se consulta al runtime para resolver la clase.

### Objetos en el heap de Swift y metadatos

Las clases puras de Swift también son objetos con un encabezado que apunta a los metadatos de Swift (no al `isa` de Objective‑C). Para inspeccionar procesos Swift en vivo sin modificarlos puedes usar `swift-inspect` del toolchain de Swift, que aprovecha la librería Remote Mirror para leer los metadatos del runtime:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Esto es muy útil para mapear objetos del heap de Swift y las conformancias a protocolos al hacer reversing de apps mixtas Swift/ObjC.

---

## Resumen rápido de inspección en tiempo de ejecución (LLDB / Frida)

### LLDB

- Imprimir objeto o clase desde un puntero crudo:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspeccionar Objective‑C class desde un pointer a un object method’s `self` en un breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Volcar secciones que contienen metadatos de Objective‑C (nota: muchas ahora están en `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Leer la memoria de un objeto de clase conocido para pivotar a `class_ro_t` / `class_rw_t` al hacer ingeniería inversa de las listas de métodos:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida proporciona puentes de alto nivel en tiempo de ejecución que son muy útiles para descubrir e instrumentar objetos vivos sin símbolos:

- Enumerar clases y métodos, resolver los nombres reales de las clases en tiempo de ejecución e interceptar selectores de Objective‑C:
```js
if (ObjC.available) {
// List a class' methods
console.log(ObjC.classes.NSFileManager.$ownMethods);

// Intercept and inspect arguments/return values
const impl = ObjC.classes.NSFileManager['- fileExistsAtPath:isDirectory:'].implementation;
Interceptor.attach(impl, {
onEnter(args) {
this.path = new ObjC.Object(args[2]).toString();
},
onLeave(retval) {
console.log('fileExistsAtPath:', this.path, '=>', retval);
}
});
}
```
- Puente Swift: enumerar tipos Swift e interactuar con instancias Swift (requiere Frida reciente; muy útil en objetivos con Apple Silicon).

---

## Referencias

- Clang/LLVM: Autenticación de punteros y las intrínsecas `<ptrauth.h>` (ABI arm64e). https://clang.llvm.org/docs/PointerAuthentication.html
- Encabezados del runtime objc de Apple (punteros etiquetados, `isa` no puntero, etc.), p. ej., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
