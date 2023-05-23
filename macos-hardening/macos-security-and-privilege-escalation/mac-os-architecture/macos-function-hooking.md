# macOS Function Hooking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Function Interposing

Create a **dylib** with an **`__interpose`** section (or a section flagged with **`S_INTERPOSING`**) containing tuples of **function pointers** that refer to the **original** and the **replacement** functions.

Then, **inject** the dylib with **`DYLD_INSERT_LIBRARIES`** (the interposing needs occur before the main app lodas). Obviously this restriction has the **restrictions** applied to the use of DYLD\_INSERT\_LIBRARIES.&#x20;

### Interpose printf

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
    //va_list args;
    //va_start(args, format);
    //int ret = vprintf(format, args);
    //va_end(args);

    int ret = printf("[+] Hello from interpose\n");
    return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
{% endtab %}
{% endtabs %}

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
[+] Hello from interpose
```

## Method Swizzling

In ObjectiveC this is how a method is called: `[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`

It's needed the **object**, the **method** and the **params**. And when a method is called a **msg is sent** using the function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

The object is **`someObject`**, the method is **`@selector(method1p1:p2:)`** and the arguments are **value1**, **value2**.

Following the object structures, it's possible to reach an **array of methods** where the **names** and **pointers** to the method code are **located**.

{% hint style="danger" %}
Note that because methods and classes are accessed based on their names, this information is store in the binary, so it's possible to retrieve it with `otool -ov </path/bin>` or [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accessing the raw methods

It's possible to access the information of the methods such as name, number of params or address like in the following example:

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

### Method Swizzling with method\_exchangeImplementations

The function method\_exchangeImplementations allows to change the address of one function for the other. So when a function is called what is executed is the other one.

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
    // Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
    // And when swizzledSubstringFromIndex is called, substringFromIndex is really colled
    
    // Example usage
    NSString *myString = @"Hello, World!";
    NSString *subString = [myString substringFromIndex:7];
    NSLog(@"Substring: %@", subString);
    
    return 0;
}
```

### Method Swizzling with method\_setImplementation

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

In this page different ways to hook functions were discussed. However, they involved **running code inside the process to attack**.

In order to do that the easiest technique to use is to inject a [Dyld via environment variables or hijacking](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). However, I guess this could also be done via [Dylib process injection](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

However, both options are **limited** to **unprotected** binaries/processes. Check each technique to learn more about the limitations.

However, a function hooking attack is very specific, an attacker will do this to **steal sensitive information from inside a process** (if not you would just do a process injection attack). And this sensitive information might be located in user downloaded Apps such as MacPass.

So the attacker vector would be to either find a vulnerability or strip the signature of the application, inject the **`DYLD_INSERT_LIBRARIES`** env variable through the Info.plist of the application adding something like:

```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key> 
    <string>/Applications/MacPass.app/Contents/malicious.dylib</string>
</dict>
```

Add in that library the hooking code to exfiltrate the information: Passwords, messages...

## References

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
