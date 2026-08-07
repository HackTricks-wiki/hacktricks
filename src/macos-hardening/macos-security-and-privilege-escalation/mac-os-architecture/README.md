# Kernel e Extensões do Sistema do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X is Not Unix". Esse kernel é composto fundamentalmente pelo **microkernel Mach** (que será discutido mais adiante) **e** por elementos do Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **kernel drivers por meio de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto open source Darwin, o que significa que **seu código-fonte está disponível gratuitamente**.

Do ponto de vista de um security researcher ou de um desenvolvedor Unix, o **macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD**, com uma GUI elegante e diversos aplicativos personalizados. A maioria dos aplicativos desenvolvidos para BSD será compilada e executada no macOS sem necessidade de modificações, pois as ferramentas de linha de comando familiares aos usuários Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora o Mach, existem algumas diferenças significativas entre um sistema tradicional semelhante ao Unix e o macOS, e essas diferenças podem causar possíveis problemas ou oferecer vantagens exclusivas.

Versão open source do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **microkernel** projetado para ser **compatível com UNIX**. Um de seus principais princípios de design era **minimizar** a quantidade de **código** executado no espaço do **kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, networking e I/O, **fossem executadas como user-level tasks**.

No XNU, o Mach é **responsável por muitas das operações críticas de baixo nível** normalmente gerenciadas por um kernel, como escalonamento do processador, multitasking e gerenciamento de memória virtual.

### BSD

O **kernel** XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Esse código **é executado como parte do kernel junto com o Mach**, no mesmo espaço de endereçamento. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD, pois foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações do kernel, incluindo:

- Gerenciamento de processos
- Tratamento de sinais
- Mecanismos básicos de segurança, incluindo gerenciamento de usuários e grupos
- Infraestrutura de system calls
- Stack TCP/IP e sockets
- Firewall e filtragem de pacotes

Entender a interação entre BSD e Mach pode ser complexo devido aos seus diferentes modelos conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto o Mach opera com base em threads. Essa discrepância é resolvida no XNU **associando cada processo BSD a uma task Mach** que contém exatamente uma thread Mach. Quando a system call fork() do BSD é utilizada, o código BSD dentro do kernel usa funções do Mach para criar uma task e uma estrutura de thread.

Além disso, **Mach e BSD mantêm modelos de segurança diferentes**: o modelo de segurança do **Mach** é baseado em **port rights**, enquanto o modelo de segurança do BSD opera com base na **propriedade dos processos**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades locais de privilege escalation. Além das system calls típicas, também existem **Mach traps que permitem que programas em user space interajam com o kernel**. Esses diferentes elementos juntos formam a arquitetura multifacetada e híbrida do kernel do macOS.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

O I/O Kit é um **framework de device drivers** open source e orientado a objetos no kernel XNU, que gerencia **device drivers carregados dinamicamente**. Ele permite adicionar código modular ao kernel on-the-fly, oferecendo suporte a diversos hardwares.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessadores na Arquitetura do macOS

As plataformas da Apple dependem de vários coprocessadores para manter o trabalho sensível à latência fora dos cores principais e isolar funções críticas de segurança.

- **Secure Enclave Processor (SEP)**: Um core ARM dedicado com seu próprio microkernel e cadeia de secure boot, normalmente executado em **EL3/secure world**. A interação ocorre por meio de mailbox drivers no macOS em EL1.
- Attack surface: atualizações do firmware do SEP e os daemons em user space (`seputil`, `securityd`) que fazem proxy das solicitações.
- Impacto do compromise: fazer leak de chaves de longo prazo, contornar o bloqueio biométrico e quebrar as proteções do FileVault ou do Apple Pay.
- **System Management Controller (SMC)**: Executa firmware proprietário em um microcontrolador fora dos níveis de exceção ARM. O macOS (EL1) o acessa por meio de user clients do I/O Kit.
- Attack surface: mensagens de fornecimento de energia USB-C, interfaces de gerenciamento de ventoinhas/bateria e caminhos de atualização de firmware.
- Impacto do compromise: substituir limites térmicos, injetar dados falsos de sensores, cortar a energia ou implantar backdoors persistentes no NVRAM.
- **T1/T2 Security Chips**: Executam o bridgeOS (derivado do watchOS), em grande parte em EL1/EL3, em seus próprios cores ARM. O macOS se comunica por canais semelhantes a PCIe/USB mediados pelo IOKit.
- Attack surface: caminhos de DFU/restore, endpoints de IPC expostos por serviços como `tccd` e pipelines de mídia conectados ao T2.
- Impacto do compromise: desabilitar o secure boot, descriptografar o conteúdo do SSD, assumir o controle do bloqueio da câmera/microfone ou emular entradas HID para persistência furtiva.
- **Display Coprocessor (DCP)**: Executa firmware em EL1 dentro de um espaço de endereçamento isolado protegido pelo DART (IOMMU da Apple).
- Attack surface: interfaces `DCPAVService`, buffers de descritores compartilhados e parsing de imagens de firmware.
- Impacto do compromise: injetar frames arbitrários, espionar framebuffers ou inutilizar o pipeline de display para causar DoS.
- **Apple Neural Engine (ANE)**: Executa microcode em um cluster ML dedicado (sem níveis EL ARM). O macOS agenda o trabalho por meio do `ANECompilerService` e do IOKit.
- Attack surface: binários de modelos compilados (`.ane`), APIs do Core ML que alimentam kernels customizados e loaders de firmware.
- Impacto do compromise: adulterar ou exfiltrar modelos ML, fazer leak de dados de áudio/visão processados ou sabotar a inferência on-device.
- **AGX GPU**: O firmware é executado em cores GPU customizados com um scheduler; EL0 envia comandos Metal que EL1 valida.
- Attack surface: compilador de shaders Metal, APIs de mapeamento de buffers compartilhados e interfaces ioctl `com.apple.AGXFirmware`.
- Impacto do compromise: obter acesso DMA à memória do sistema, escapar do sandbox por meio de GPU drivers ou implantar implants persistentes no firmware.
- **Apple Video Encoder (AVE)**: O firmware é executado no Media Engine em um sandbox semelhante a EL1. O macOS interage por meio do VideoToolbox e do `AppleAVE2`.
- Attack surface: bitstreams de codecs, conjuntos de parâmetros, buffers fornecidos pelo usuário e blobs de atualização de firmware.
- Impacto do compromise: fazer leak de frames não comprimidos, contornar DRM ou obter code execution com acesso aos mecanismos DMA.
- **Image Signal Processor (ISP)**: Executa firmware seguro no cluster Media Engine; os drivers de câmera do macOS operam em EL1.
- Attack surface: HALs de câmera, descritores de frames RAW, filas de configuração do ISP e atualizações de firmware.
- Impacto do compromise: capturar feeds brutos da câmera silenciosamente, desabilitar indicadores de privacidade ou injetar imagens fabricadas.
- **AMX Matrix cores**: Operam como unidades coprocessadoras expostas em EL0/EL1 por meio de novas instruções.
- Attack surface: virtualização do estado do AMX pelo kernel (`thread_set_state`, context switches) e geração de código em user space.
- Impacto do compromise: fazer leak dos tile registers de outros processos, identificar workloads ou escalar privilégios por meio de corrupção de memória do kernel.

O macOS moderno trata esses coprocessadores como componentes confiáveis na chain of trust. O firmware do SEP, SMC e T2 é assinado pela Apple, e os protocolos de handshake (frequentemente implementados por meio de mailboxes ou de famílias do I/O Kit) incluem verificações de challenge-response para que somente firmware autenticado possa atender às solicitações.

### IPC - Comunicação entre Processos

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Extensões do Kernel do macOS

O macOS é **extremamente restritivo para carregar Kernel Extensions** (.kext), devido aos altos privilégios com os quais esse código será executado. Na prática, por padrão, isso é praticamente impossível (a menos que seja encontrado um bypass).

Na página a seguir, você também pode ver como recuperar o `.kext` que o macOS carrega dentro do seu **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions do macOS

Em vez de usar Kernel Extensions, o macOS criou as System Extensions, que oferecem APIs em user level para interagir com o kernel. Dessa forma, os desenvolvedores podem evitar o uso de kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes e RSR (Rapid Security Response)

- **Cryptex** significa **CRYPTographically-sealed EXtension**. É uma imagem de disco selada (container) usada pela Apple para hospedar partes do OS (frameworks, shared libraries, apps) que têm maior probabilidade de mudar entre grandes atualizações do OS.
- No macOS e no iOS, os componentes colocados dentro de cryptexes podem ser **patched ou substituídos** por meio do RSR sem resealar todo o volume do sistema.
- Os cryptexes ficam no volume **Preboot**, junto ao firmware de boot, e são integrados ao sistema de arquivos do OS em runtime.
- O carregamento do conteúdo de um cryptex envolve validação: o sistema verifica os file seals, manifests e root hashes e, em seguida, monta ou “integra” o conteúdo do cryptex para que, em runtime, os apps usem as versões do cryptex quando presentes.
- Nos logs de boot, o carregamento do cryptex ocorre após a inicialização do kernel, mas antes que os serviços completos do sistema estejam ativos.


#### Rapid Security Response (RSR)

- **RSR** é o mecanismo da Apple para distribuir **security patches entre atualizações regulares do OS**. Ele direciona o conteúdo dos cryptexes para atualizar partes vulneráveis (por exemplo, libraries e frameworks) sem modificar o volume principal do sistema.
- Ao aplicar uma atualização RSR, o dispositivo solicita ao signing server da Apple um **manifest Cryptex1 Image4**. Esse manifest é vinculado criptograficamente ao dispositivo e ao novo conteúdo do cryptex.
- O AP boot ticket existente do sistema-base **não é modificado** pelo RSR. O patch funciona de forma aditiva sobre o OS-base selado.
- No macOS, determinados componentes patched (por exemplo, o Safari) tornam-se ativos assim que o app é relançado; nem sempre é necessário reiniciar completamente o sistema.
- Os RSRs são **removíveis**: cada um inclui um patch e um “antipatch” que pode retornar à versão-base do OS. Na remoção, o conteúdo do cryptex é revertido.
- As atualizações RSR geralmente são muito menores que atualizações completas do OS e exigem um nível de bateria mais baixo para serem instaladas.


## Referências

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
