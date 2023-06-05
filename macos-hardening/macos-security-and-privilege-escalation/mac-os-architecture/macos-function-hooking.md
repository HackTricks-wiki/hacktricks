## Hooking de Funciones en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue la [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Interposición de Funciones

Crea una **dylib** con una sección **`__interpose`** (o una sección marcada con **`S_INTERPOSING`**) que contenga tuplas de **punteros a funciones** que se refieran a las funciones **originales** y a las funciones **de reemplazo**.

Luego, **inyecta** la dylib con **`DYLD_INSERT_LIBRARIES`** (la interposición debe ocurrir antes de que la aplicación principal se cargue). Obviamente, esta restricción tiene las **restricciones** aplicadas al uso de DYLD\_INSERT\_LIBRARIES.&#x20;

### Interponer printf

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
    //va_list args;
    //va_start(args, format);
    //int ret = vprintf(format, args);
    //va_end(args);

    int ret = printf("[+] Hello from interpose\n");
    return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}

```c
#include <stdio.h>

void hello() {
    printf("Hello, world!\n");
}

int main() {
    hello();
    return 0;
}
```

{% endtab %}
{% endtabs %}

En este ejemplo, `hello()` es una función que imprime "Hello, world!" en la consola. La función `main()` llama a `hello()` y luego devuelve 0.
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
{% endtab %}
{% endtabs %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
[+] Hello from interpose
```
## Método Swizzling

En ObjectiveC así es como se llama a un método: `[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`

Se necesita el **objeto**, el **método** y los **parámetros**. Y cuando se llama a un método, se envía un **mensaje** utilizando la función **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

El objeto es **`someObject`**, el método es **`@selector(method1p1:p2:)`** y los argumentos son **value1**, **value2**.

Siguiendo las estructuras de objetos, es posible llegar a un **array de métodos** donde se encuentran **los nombres** y **punteros** al código del método.

{% hint style="danger" %}
Tenga en cuenta que debido a que los métodos y las clases se acceden en función de sus nombres, esta información se almacena en el binario, por lo que es posible recuperarla con `otool -ov </path/bin>` o [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accediendo a los métodos en bruto

Es posible acceder a la información de los métodos, como el nombre, el número de parámetros o la dirección, como en el siguiente ejemplo:
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
### Swizzling de métodos con method\_exchangeImplementations

La función method\_exchangeImplementations permite cambiar la dirección de una función por la de otra. Por lo tanto, cuando se llama a una función, lo que se ejecuta es la otra.
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
    // Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
    // And when swizzledSubstringFromIndex is called, substringFromIndex is really colled
    
    // Example usage
    NSString *myString = @"Hello, World!";
    NSString *subString = [myString substringFromIndex:7];
    NSLog(@"Substring: %@", subString);
    
    return 0;
}
```
### Cambio de método con method\_setImplementation

El formato anterior es extraño porque estás cambiando la implementación de 2 métodos uno por el otro. Usando la función **`method_setImplementation`** puedes **cambiar** la **implementación** de un **método por la de otro**.

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
## Metodología de Ataque de Hooking

En esta página se discutieron diferentes formas de enganchar funciones. Sin embargo, todas implican **ejecutar código dentro del proceso para atacar**.

Para hacer esto, la técnica más fácil de usar es inyectar un [Dyld a través de variables de entorno o secuestro](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Sin embargo, supongo que esto también se podría hacer a través de [inyección de proceso Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Sin embargo, ambas opciones están **limitadas** a binarios/procesos **no protegidos**. Consulte cada técnica para obtener más información sobre las limitaciones.

Sin embargo, un ataque de enganche de función es muy específico, un atacante hará esto para **robar información confidencial desde dentro de un proceso** (si no, simplemente haría un ataque de inyección de proceso). Y esta información confidencial podría estar ubicada en aplicaciones descargadas por el usuario, como MacPass.

Por lo tanto, el vector de ataque del atacante sería encontrar una vulnerabilidad o eliminar la firma de la aplicación, inyectar la variable de entorno **`DYLD_INSERT_LIBRARIES`** a través del archivo Info.plist de la aplicación agregando algo como:
```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key> 
    <string>/Applications/MacPass.app/Contents/malicious.dylib</string>
</dict>
```
Agregue en esa biblioteca el código de hooking para filtrar la información: contraseñas, mensajes...

## Referencias

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
