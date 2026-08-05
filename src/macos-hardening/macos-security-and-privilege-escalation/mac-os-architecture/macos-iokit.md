# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

O I/O Kit é um **framework de drivers de dispositivos** open-source e orientado a objetos no kernel XNU, responsável por **drivers de dispositivos carregados dinamicamente**. Ele permite adicionar código modular ao kernel em tempo de execução, oferecendo suporte a diversos tipos de hardware.

Os drivers do IOKit basicamente **exportam funções do kernel**. Os **tipos** dos parâmetros dessas funções são **predefinidos** e verificados. Além disso, assim como o XPC, o IOKit é apenas outra camada **sobre as mensagens Mach**.

O **código do kernel XNU do IOKit** é disponibilizado como open-source pela Apple em [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Além disso, os componentes do IOKit no user space também são open-source em [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

No entanto, **nenhum driver do IOKit** é open-source. Ainda assim, ocasionalmente uma versão de um driver pode vir com símbolos que facilitam sua depuração. Veja como [**obter as extensões do driver a partir do firmware aqui**](#ipsw)**.**

Ele é escrito em **C++**. Você pode obter símbolos C++ demangled com:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> As **funções expostas** do IOKit podem realizar **verificações de segurança adicionais** quando um cliente tenta chamar uma função, mas observe que os aplicativos geralmente são **limitados** pelo **sandbox** quanto às funções do IOKit com as quais podem interagir.

## Drivers

No macOS, eles estão localizados em:

- **`/System/Library/Extensions`**
- Arquivos KEXT integrados ao sistema operacional OS X.
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
Até o número 9, os drivers listados são **carregados no endereço 0**. Isso significa que não são drivers reais, mas **parte do kernel e não podem ser descarregados**.

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

O **IORegistry** é uma parte crucial do framework IOKit no macOS e iOS, que funciona como um banco de dados para representar a configuração e o estado do hardware do sistema. É uma **coleção hierárquica de objetos que representam todo o hardware e os drivers** carregados no sistema, bem como seus relacionamentos entre si.

Você pode obter o IORegistry usando a CLI **`ioreg`** para inspecioná-lo pelo console (especialmente útil no iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Você pode baixar o **`IORegistryExplorer`** em **Xcode Additional Tools**, disponível em [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/), e inspecionar o **macOS IORegistry** por meio de uma interface **gráfica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

No IORegistryExplorer, os "planes" são usados para organizar e exibir os relacionamentos entre diferentes objetos no IORegistry. Cada plane representa um tipo específico de relacionamento ou uma visualização específica da configuração de hardware e dos drivers do sistema. Estes são alguns dos planes comuns que você pode encontrar no IORegistryExplorer:

1. **IOService Plane**: Este é o plane mais geral, exibindo os objetos de serviço que representam drivers e nubs (canais de comunicação entre drivers). Ele mostra os relacionamentos provider-client entre esses objetos.
2. **IODeviceTree Plane**: Este plane representa as conexões físicas entre os dispositivos conforme eles são conectados ao sistema. Ele é frequentemente usado para visualizar a hierarquia de dispositivos conectados por meio de barramentos como USB ou PCI.
3. **IOPower Plane**: Exibe objetos e seus relacionamentos em termos de gerenciamento de energia. Ele pode mostrar quais objetos estão afetando o estado de energia de outros, sendo útil para depurar problemas relacionados à energia.
4. **IOUSB Plane**: Concentrado especificamente em dispositivos USB e seus relacionamentos, mostrando a hierarquia de hubs USB e dispositivos conectados.
5. **IOAudio Plane**: Este plane representa dispositivos de áudio e seus relacionamentos dentro do sistema.
6. ...

## Exemplo de código de comunicação com Driver

O código a seguir se conecta ao serviço IOKit `YourServiceNameHere` e chama o selector 0:

- Primeiro, ele chama **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** para obter o serviço.
- Em seguida, estabelece uma conexão chamando **`IOServiceOpen`**.
- Por fim, chama uma função com **`IOConnectCallScalarMethod`**, indicando o selector 0 (o selector é o número atribuído à função que você deseja chamar).

<details>
<summary>Exemplo de chamada em user-space para um selector de driver</summary>
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

## Revertendo o entrypoint do driver

Você pode obtê-los, por exemplo, de uma [**imagem de firmware (ipsw)**](#ipsw). Em seguida, carregue-a no seu decompiler favorito.

Você pode começar a decompilar a função **`externalMethod`**, pois essa é a função do driver que receberá a chamada e chamará a função correta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Essa chamada horrível e desmagificada significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Observe que, na definição anterior, o parâmetro **`self`** foi omitido. A definição correta seria:
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

Para a próxima etapa, precisamos ter a struct **`IOExternalMethodDispatch2022`** definida. Ela é opensource em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176); você pode defini-la:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Agora, seguindo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, você pode ver muitos dados:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Altere o Data Type para **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

após a alteração:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E, como sabemos que há um **array de 7 elementos** (verifique o código decompilado final), clique para criar um array de 7 elementos:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Depois que o array for criado, você poderá ver todas as funções exportadas:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você se lembra, para **chamar** uma função **exportada** a partir do user space, não precisamos chamar o nome da função, mas sim o **número do selector**. Aqui você pode ver que o selector **0** é a função **`initializeDecoder`**, o selector **1** é **`startDecoder`**, o selector **2** é **`initializeEncoder`**...

## Superfície de ataque recente do IOKit (2023–2025)

- **Captura de keystrokes via IOHIDFamily** – CVE-2024-27799 (14.5) mostrou que um client permissivo de `IOHIDSystem` poderia capturar eventos HID mesmo com secure input; certifique-se de que os handlers de `externalMethod` imponham entitlements, em vez de dependerem apenas do tipo de user-client.<sup>[[2]](#references)</sup>
- **Corrupção de memória no IOGPUFamily** – CVE-2024-44197 e CVE-2025-24257 corrigiram escritas OOB alcançáveis a partir de apps sandboxed que passam dados de tamanho variável malformados para GPU user clients; o bug comum é a falta de validações adequadas de limites nos argumentos de `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Monitoramento legado de keystrokes** – CVE-2023-42891 (14.2) confirmou que HID user clients continuam sendo um vetor de sandbox escape; faça fuzzing em qualquer driver que exponha filas de teclado/eventos.<sup>[[3]](#references)</sup>

### Dicas rápidas de triagem e fuzzing

- Enumere todos os external methods de um user client a partir do userland para alimentar um fuzzer:
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
- Ao fazer reverse engineering, preste atenção às contagens de `IOExternalMethodDispatch2022`. Um padrão comum de bug em CVEs recentes é a inconsistência entre `structureInputSize`/`structureOutputSize` e o tamanho real de `copyin`, levando a um heap OOB em `IOConnectCallStructMethod`.
- A acessibilidade do Sandbox ainda depende de entitlements. Antes de investir tempo em um target, verifique se o client pode ser acessado a partir de um app de terceiros:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Para bugs de GPU/iomfb, passar arrays grandes demais por `IOConnectCallMethod` geralmente é suficiente para acionar limites incorretos. Harness mínimo (selector X) para acionar confusão de tamanho:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Drivers em User-Space

### Informações básicas

**DriverKit** é a substituição da Apple, em user-space, para extensões do kernel (kexts), introduzida no macOS 10.15. Os binários do DriverKit (bundles `.dext`) são executados como processos em user-space, mas se comunicam diretamente com o kernel por meio de uma interface IOKit privilegiada.

As extensões do DriverKit gerenciam hardware:
- Controladores e dispositivos **USB**
- Dispositivos **Thunderbolt** / PCIe
- **HID** (teclados, mouses e game controllers)
- Hardware de **áudio**
- Interfaces de **rede**
- Dispositivos **seriais** e de **armazenamento em bloco**

Diferentemente dos kexts (que exigiam a inicialização com o SIP desativado ou notarização), as extensões do DriverKit são instaladas por meio do `SystemExtensions.framework` e exigem apenas **uma aprovação única do usuário**.

### Discovery e Enumeração
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Implicações de Segurança

> [!WARNING]
> Binários do DriverKit têm um **canal de comunicação direto com o kernel**. O envio de mensagens malformadas por esse canal pode acionar vulnerabilidades no kernel. Cada driver registra classes específicas de user-client, e chamadas `IOConnectCallMethod` malformadas podem causar corrupção de memória do kernel.

**Superfície de ataque:**
1. **Fuzzing de mensagens do kernel IOKit** — Cada user-client do DriverKit expõe selectors que podem ser chamados a partir do espaço do usuário. Argumentos malformados acionam bugs no kernel.
2. **Spoofing de dispositivos USB** — Um binário comprometido do USB DriverKit pode apresentar um perfil de dispositivo USB malicioso (por exemplo, emular um teclado para injeção HID).
3. **Ataques DMA** — Extensões DriverKit PCIe/Thunderbolt podem ter acesso potencial via DMA à memória física.
4. **Persistência** — Depois de instalado como uma system extension, os binários do DriverKit persistem entre reinicializações e atualizações de apps.

### Fuzzing de User-Client IOKit do DriverKit
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### CVEs do DriverKit

| CVE | Descrição |
|---|---|
| CVE-2022-26766 | Vulnerabilidade na pilha USB do DriverKit — execução de código no kernel |
| CVE-2021-30838 | Confusão de tipos no user-client do IOKit em drivers gráficos |
| CVE-2024-44197 | Escrita OOB no IOGPUFamily por meio de argumentos malformados do DriverKit |

## Referências

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
