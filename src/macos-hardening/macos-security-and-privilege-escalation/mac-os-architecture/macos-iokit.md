# IOKit no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informação Básica

O I/O Kit é um framework de driver de dispositivo orientado a objetos e open-source no kernel XNU, que lida com **drivers de dispositivo carregados dinamicamente**. Ele permite que código modular seja adicionado ao kernel dinamicamente, suportando hardware diverso.

Drivers do IOKit basicamente **exportam funções do kernel**. Os **tipos** dos parâmetros dessas funções são **predefinidos** e verificados. Além disso, similar ao XPC, o IOKit é apenas outra camada por **cima das mensagens Mach**.

**O código do kernel XNU do IOKit** é disponibilizado como open-source pela Apple em [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Além disso, os componentes do IOKit em espaço de usuário também são open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Entretanto, **nenhum driver do IOKit** é open-source. De qualquer forma, ocasionalmente uma release de um driver pode vir com símbolos que facilitam seu debug. Veja como [**obter as extensões do driver a partir do firmware aqui**](#ipsw)**.**

É escrito em **C++**. Você pode obter símbolos C++ demangled com:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> As **funções expostas** do IOKit podem executar **verificações de segurança adicionais** quando um cliente tenta chamar uma função, mas observe que os apps normalmente são **limitados** pelo **sandbox** às funções IOKit com as quais podem interagir.

## Drivers

No macOS eles estão localizados em:

- **`/System/Library/Extensions`**
- Arquivos KEXT incorporados no sistema operacional OS X.
- **`/Library/Extensions`**
- Arquivos KEXT instalados por software de terceiros

No iOS eles estão localizados em:

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
Até o número 9 os drivers listados estão **carregados no address 0**. Isso significa que estes não são drivers reais, mas **parte do kernel e não podem ser descarregados**.

Para encontrar extensões específicas você pode usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para carregar e descarregar extensões do kernel, execute:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** é uma parte crucial do framework IOKit no macOS e iOS que serve como um banco de dados para representar a configuração e o estado do hardware do sistema. É uma **coleção hierárquica de objetos que representam todo o hardware e os drivers** carregados no sistema, e seus relacionamentos entre si.

You can get the IORegistry using the cli **`ioreg`** to inspect it from the console (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Você pode baixar **`IORegistryExplorer`** a partir de **Xcode Additional Tools** em [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspecionar o **macOS IORegistry** através de uma interface **gráfica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

No IORegistryExplorer, "planes" são usados para organizar e exibir os relacionamentos entre diferentes objetos no IORegistry. Cada plane representa um tipo específico de relacionamento ou uma vista particular da configuração de hardware e drivers do sistema. Aqui estão alguns dos planes comuns que você pode encontrar no IORegistryExplorer:

1. **IOService Plane**: Este é o plano mais geral, exibindo os objetos de serviço que representam drivers e nubs (canais de comunicação entre drivers). Ele mostra as relações provider-client entre esses objetos.
2. **IODeviceTree Plane**: Este plano representa as conexões físicas entre dispositivos conforme são conectados ao sistema. É frequentemente usado para visualizar a hierarquia de dispositivos conectados via barramentos como USB ou PCI.
3. **IOPower Plane**: Exibe objetos e suas relações em termos de gerenciamento de energia. Pode mostrar quais objetos estão afetando o estado de energia de outros, útil para depurar problemas relacionados à energia.
4. **IOUSB Plane**: Focado especificamente em dispositivos USB e suas relações, mostrando a hierarquia de hubs USB e dispositivos conectados.
5. **IOAudio Plane**: Este plano representa dispositivos de áudio e suas relações dentro do sistema.
6. ...

## Exemplo de código de comunicação com driver

O código a seguir conecta-se ao serviço IOKit `YourServiceNameHere` e chama o selector 0:

- Primeiro chama **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** para obter o serviço.
- Em seguida estabelece uma conexão chamando **`IOServiceOpen`**.
- E finalmente chama uma função com **`IOConnectCallScalarMethod`** indicando o selector 0 (o selector é o número atribuído à função que você quer chamar).

<details>
<summary>Exemplo de chamada em espaço do usuário para um selector de driver</summary>
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
</details>

Existem **outras** funções que podem ser usadas para chamar funções do IOKit além de **`IOConnectCallScalarMethod`**, como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Análise reversa do ponto de entrada do driver

Você pode obter estes, por exemplo, de uma [**firmware image (ipsw)**](#ipsw). Em seguida, carregue-o no seu descompilador favorito.

Você pode começar a descompilar a função **`externalMethod`**, pois essa é a função do driver que receberá a chamada e invocará a função correta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Essa chamada demagled horrível significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Observe que na definição anterior o parâmetro **`self`** está ausente; a definição correta seria:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Na verdade, você pode encontrar a definição real em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Com essas informações você pode reescrever Ctrl+Right -> `Edit function signature` e definir os tipos conhecidos:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

O novo código decompilado ficará assim:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Para o próximo passo precisamos ter definida a struct **`IOExternalMethodDispatch2022`**. Ela é open-source em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), você pode defini-la:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Agora, seguindo o `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` você pode ver muitos dados:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Altere o Tipo de Dados para **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

após a mudança:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E agora que estamos ali temos um **array de 7 elementos** (verifique o código decompilado final), clique para criar um array de 7 elementos:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Após o array ser criado você pode ver todas as funções exportadas:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você lembra, para **chamar** uma **exportada** função do espaço do usuário não precisamos chamar o nome da função, mas o **selector number**. Aqui você pode ver que o selector **0** é a função **`initializeDecoder`**, o selector **1** é **`startDecoder`**, o selector **2** **`initializeEncoder`**...

## Superfície de ataque recente do IOKit (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) mostrou que um client permissivo `IOHIDSystem` poderia capturar eventos HID mesmo com secure input; assegure que os handlers `externalMethod` apliquem entitlements em vez de checar apenas o tipo do user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 and CVE-2025-24257 corrigiram OOB writes acessíveis por apps sandboxed que passam dados de comprimento variável malformados para GPU user clients; o bug habitual é falta de limites ao redor dos argumentos de `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) confirmou que HID user clients continuam sendo um vetor de escape do sandbox; fuzz qualquer driver que exponha filas de teclado/eventos.

### Dicas rápidas de triagem e fuzzing

- Enumere todos os external methods para um user client a partir do userland para semear um fuzzer:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Ao realizar engenharia reversa, preste atenção às contagens de `IOExternalMethodDispatch2022`. Um padrão comum de bug em CVEs recentes é a inconsistência entre `structureInputSize`/`structureOutputSize` e o comprimento real do `copyin`, levando a heap OOB em `IOConnectCallStructMethod`.
- A acessibilidade do Sandbox ainda depende de entitlements. Antes de gastar tempo em um alvo, verifique se o cliente é permitido a partir de um third‑party app:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Para bugs de GPU/iomfb, passar arrays de tamanho excessivo através de `IOConnectCallMethod` costuma ser suficiente para provocar limites incorretos. Harness mínimo (selector X) para provocar size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Referências

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
