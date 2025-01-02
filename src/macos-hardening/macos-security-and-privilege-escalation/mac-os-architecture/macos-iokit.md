# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

O I/O Kit é um **framework de driver de dispositivo** orientado a objetos e de código aberto no kernel XNU, que lida com **drivers de dispositivo carregados dinamicamente**. Ele permite que código modular seja adicionado ao kernel em tempo real, suportando hardware diversificado.

Os drivers do IOKit basicamente **exportam funções do kernel**. Os **tipos** de **parâmetros** dessas funções são **pré-definidos** e verificados. Além disso, semelhante ao XPC, o IOKit é apenas mais uma camada **sobre as mensagens Mach**.

O **código do kernel IOKit XNU** é de código aberto pela Apple em [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Além disso, os componentes do IOKit no espaço do usuário também são de código aberto [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

No entanto, **nenhum driver IOKit** é de código aberto. De qualquer forma, de tempos em tempos, um lançamento de um driver pode vir com símbolos que facilitam a depuração. Confira como [**obter as extensões do driver do firmware aqui**](./#ipsw)**.**

Está escrito em **C++**. Você pode obter símbolos C++ demangled com:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Funções **expostas** do IOKit podem realizar **verificações de segurança adicionais** quando um cliente tenta chamar uma função, mas note que os aplicativos geralmente são **limitados** pelo **sandbox** com o qual as funções do IOKit podem interagir.

## Drivers

No macOS, eles estão localizados em:

- **`/System/Library/Extensions`**
- Arquivos KEXT incorporados no sistema operacional OS X.
- **`/Library/Extensions`**
- Arquivos KEXT instalados por software de terceiros

No iOS, eles estão localizados em:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Até o número 9, os drivers listados estão **carregados no endereço 0**. Isso significa que não são drivers reais, mas **parte do kernel e não podem ser descarregados**.

Para encontrar extensões específicas, você pode usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para carregar e descarregar extensões do kernel, faça:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

O **IORegistry** é uma parte crucial do framework IOKit no macOS e iOS, que serve como um banco de dados para representar a configuração e o estado do hardware do sistema. É uma **coleção hierárquica de objetos que representam todo o hardware e drivers** carregados no sistema, e suas relações entre si.

Você pode obter o IORegistry usando o cli **`ioreg`** para inspecioná-lo a partir do console (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Você pode baixar **`IORegistryExplorer`** das **Xcode Additional Tools** em [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspecionar o **macOS IORegistry** através de uma interface **gráfica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

No IORegistryExplorer, "planos" são usados para organizar e exibir os relacionamentos entre diferentes objetos no IORegistry. Cada plano representa um tipo específico de relacionamento ou uma visão particular da configuração de hardware e drivers do sistema. Aqui estão alguns dos planos comuns que você pode encontrar no IORegistryExplorer:

1. **IOService Plane**: Este é o plano mais geral, exibindo os objetos de serviço que representam drivers e nubs (canais de comunicação entre drivers). Ele mostra os relacionamentos de provedor-cliente entre esses objetos.
2. **IODeviceTree Plane**: Este plano representa as conexões físicas entre dispositivos à medida que estão conectados ao sistema. É frequentemente usado para visualizar a hierarquia de dispositivos conectados via barramentos como USB ou PCI.
3. **IOPower Plane**: Exibe objetos e seus relacionamentos em termos de gerenciamento de energia. Pode mostrar quais objetos estão afetando o estado de energia de outros, útil para depurar problemas relacionados à energia.
4. **IOUSB Plane**: Focado especificamente em dispositivos USB e seus relacionamentos, mostrando a hierarquia de hubs USB e dispositivos conectados.
5. **IOAudio Plane**: Este plano é para representar dispositivos de áudio e seus relacionamentos dentro do sistema.
6. ...

## Exemplo de Código de Comunicação de Driver

O seguinte código conecta-se ao serviço IOKit `"YourServiceNameHere"` e chama a função dentro do seletor 0. Para isso:

- primeiro chama **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** para obter o serviço.
- Em seguida, estabelece uma conexão chamando **`IOServiceOpen`**.
- E finalmente chama uma função com **`IOConnectCallScalarMethod`** indicando o seletor 0 (o seletor é o número que a função que você deseja chamar recebeu).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Existem **outras** funções que podem ser usadas para chamar funções do IOKit além de **`IOConnectCallScalarMethod`**, como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversão do ponto de entrada do driver

Você pode obter esses, por exemplo, de uma [**imagem de firmware (ipsw)**](./#ipsw). Em seguida, carregue-a em seu descompilador favorito.

Você pode começar a descompilar a função **`externalMethod`**, pois esta é a função do driver que receberá a chamada e chamará a função correta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Aquela chamada horrível demangled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Observe como na definição anterior o parâmetro **`self`** está ausente, a boa definição seria:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Na verdade, você pode encontrar a definição real em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Com essas informações, você pode reescrever Ctrl+Right -> `Edit function signature` e definir os tipos conhecidos:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

O novo código decompilado ficará assim:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Para o próximo passo, precisamos ter definida a struct **`IOExternalMethodDispatch2022`**. É open source em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), você pode defini-la:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Agora, seguindo o `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, você pode ver muitos dados:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Mude o Tipo de Dados para **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

após a mudança:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E como sabemos, lá temos um **array de 7 elementos** (verifique o código decompilado final), clique para criar um array de 7 elementos:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Após o array ser criado, você pode ver todas as funções exportadas:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você se lembrar, para **chamar** uma função **exportada** do espaço do usuário, não precisamos chamar o nome da função, mas o **número do seletor**. Aqui você pode ver que o seletor **0** é a função **`initializeDecoder`**, o seletor **1** é **`startDecoder`**, o seletor **2** **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
