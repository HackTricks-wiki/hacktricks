## Hooking de Funções do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Interposição de Funções

Crie um **dylib** com uma seção **`__interpose`** (ou uma seção marcada com **`S_INTERPOSING`**) contendo tuplas de **ponteiros de função** que se referem às funções **originais** e às funções **de substituição**.

Em seguida, **injete** a dylib com **`DYLD_INSERT_LIBRARIES`** (a interposição precisa ocorrer antes do carregamento do aplicativo principal). Obviamente, essa restrição tem as **restrições** aplicadas ao uso de DYLD\_INSERT\_LIBRARIES.&#x20;

### Interpor printf

{% tabs %}
{% tab title="interpose.c" %}
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

    int ret = printf("[+] Hello from interpose\n");
    return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}

```c
#include <stdio.h>

void hello() {
    printf("Hello, world!\n");
}

int main() {
    hello();
    return 0;
}
```

{% endtab %}
{% endtabs %}

O código acima é um exemplo simples de um programa em C que imprime "Hello, world!" na tela. A função `hello()` é definida e chamada na função `main()`.
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
{% endtab %}
{% endtabs %} 

{% endtab %}
{% endtabs %}

Neste artigo, discutiremos a técnica de hooking de função no macOS. O hooking de função é uma técnica usada para interceptar e modificar o comportamento de uma função em tempo de execução. Isso pode ser usado para uma variedade de propósitos, incluindo depuração, monitoramento de sistema e, infelizmente, também para fins maliciosos, como a escalada de privilégios.

O macOS usa uma arquitetura de kernel híbrida, que combina elementos de um kernel monolítico e um kernel baseado em microkernel. O kernel do macOS é baseado no kernel XNU, que é um kernel híbrido desenvolvido pela Apple. O kernel XNU é composto por três componentes principais: o kernel Mach, o subsistema BSD e o subsistema I/O.

O kernel Mach é responsável por gerenciar a memória, os threads e a comunicação entre processos. O subsistema BSD fornece a funcionalidade do sistema operacional, como o sistema de arquivos, a rede e a segurança. O subsistema I/O é responsável por gerenciar a entrada e saída de dados.

O macOS usa o System Integrity Protection (SIP) para proteger o sistema contra modificações não autorizadas. O SIP impede que os usuários modifiquem arquivos do sistema, mesmo que tenham privilégios de root. O SIP também impede que os usuários carreguem extensões de kernel não assinadas.

Existem várias ferramentas disponíveis para o hooking de função no macOS, incluindo o Frida, o Cycript e o MachInject. O Frida é uma ferramenta de análise dinâmica que permite injetar código em processos em execução. O Cycript é uma ferramenta de depuração interativa que permite inspecionar e modificar o comportamento de aplicativos em tempo de execução. O MachInject é uma ferramenta que permite injetar código em processos em execução usando o subsistema Mach.

Os hooks de função podem ser usados para uma variedade de propósitos, incluindo a interceptação de chamadas de sistema, a monitoração de chamadas de API e a interceptação de chamadas de biblioteca. Os hooks de função também podem ser usados para a escalada de privilégios, permitindo que um usuário com privilégios limitados execute código com privilégios de root.
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
[+] Hello from interpose
```
## Método Swizzling

Em ObjectiveC, é assim que um método é chamado: `[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`

É necessário o **objeto**, o **método** e os **parâmetros**. E quando um método é chamado, uma **mensagem é enviada** usando a função **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

O objeto é **`someObject`**, o método é **`@selector(method1p1:p2:)`** e os argumentos são **value1**, **value2**.

Seguindo as estruturas do objeto, é possível chegar a um **array de métodos** onde os **nomes** e **ponteiros** para o código do método estão **localizados**.

{% hint style="danger" %}
Observe que, como os métodos e classes são acessados com base em seus nomes, essas informações são armazenadas no binário, portanto, é possível recuperá-las com `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Acessando os métodos brutos

É possível acessar as informações dos métodos, como nome, número de parâmetros ou endereço, como no exemplo a seguir:
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
### Troca de Método com method\_exchangeImplementations

A função method\_exchangeImplementations permite alterar o endereço de uma função por outra. Assim, quando uma função é chamada, o que é executado é a outra função.
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
    // Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
    // And when swizzledSubstringFromIndex is called, substringFromIndex is really colled
    
    // Example usage
    NSString *myString = @"Hello, World!";
    NSString *subString = [myString substringFromIndex:7];
    NSLog(@"Substring: %@", subString);
    
    return 0;
}
```
### Method Swizzling com method\_setImplementation

O formato anterior é estranho porque você está mudando a implementação de 2 métodos um para o outro. Usando a função **`method_setImplementation`** você pode **mudar** a **implementação** de um **método para o outro**.

Apenas lembre-se de **armazenar o endereço da implementação do original** se você for chamá-lo da nova implementação antes de sobrescrevê-lo, porque mais tarde será muito complicado localizar esse endereço.
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
## Metodologia de Ataque de Hooking

Nesta página, foram discutidas diferentes maneiras de fazer hooking em funções. No entanto, elas envolviam **executar código dentro do processo para atacar**.

Para fazer isso, a técnica mais fácil de usar é injetar um [Dyld via variáveis de ambiente ou hijacking](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). No entanto, acredito que isso também possa ser feito por meio de [injeção de processo Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

No entanto, ambas as opções são **limitadas** a binários/processos **não protegidos**. Verifique cada técnica para saber mais sobre as limitações.

No entanto, um ataque de hooking de função é muito específico, um invasor fará isso para **roubar informações sensíveis de dentro de um processo** (se não, você apenas faria um ataque de injeção de processo). E essas informações sensíveis podem estar localizadas em aplicativos baixados pelo usuário, como o MacPass.

Portanto, o vetor do atacante seria encontrar uma vulnerabilidade ou remover a assinatura do aplicativo, injetar a variável de ambiente **`DYLD_INSERT_LIBRARIES`** por meio do Info.plist do aplicativo adicionando algo como:
```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key> 
    <string>/Applications/MacPass.app/Contents/malicious.dylib</string>
</dict>
```
Adicione na biblioteca o código de hooking para exfiltrar as informações: senhas, mensagens...

## Referências

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
