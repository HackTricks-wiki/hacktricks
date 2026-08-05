# Kernel do macOS e Extensões do Sistema

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X is Not Unix". Esse kernel é fundamentalmente composto pelo **microkernel Mach** (que será discutido posteriormente) **e** por elementos do Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel por meio de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto open source Darwin, o que significa que **seu código-fonte é livremente acessível**.

Do ponto de vista de um security researcher ou desenvolvedor Unix, o **macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD**, com uma GUI elegante e diversas aplicações personalizadas. A maioria das aplicações desenvolvidas para BSD será compilada e executada no macOS sem precisar de modificações, pois as ferramentas de linha de comando conhecidas pelos usuários Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora o Mach, existem algumas diferenças significativas entre um sistema tradicional semelhante ao Unix e o macOS, e essas diferenças podem causar possíveis problemas ou oferecer vantagens únicas.

Versão open source do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **microkernel** projetado para ser **compatível com UNIX**. Um de seus principais princípios de design era **minimizar** a quantidade de **código** executado no espaço do **kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, networking e I/O, **executassem como tarefas no nível do usuário**.

No XNU, o Mach é **responsável por muitas das operações críticas de baixo nível** normalmente realizadas por um kernel, como escalonamento de processadores, multitarefa e gerenciamento de memória virtual.

### BSD

O **kernel** XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Esse código **é executado como parte do kernel junto com o Mach**, no mesmo espaço de endereçamento. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD, pois foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações do kernel, incluindo:

- Gerenciamento de processos
- Tratamento de sinais
- Mecanismos básicos de segurança, incluindo gerenciamento de usuários e grupos
- Infraestrutura de system calls
- Stack TCP/IP e sockets
- Firewall e filtragem de pacotes

Entender a interação entre BSD e Mach pode ser complexo devido às suas diferentes estruturas conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto o Mach opera com base em threads. Essa discrepância é reconciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a system call fork() do BSD é usada, o código BSD dentro do kernel usa funções do Mach para criar uma tarefa e uma estrutura de thread.

Além disso, **Mach e BSD mantêm modelos de segurança diferentes**: o modelo de segurança do **Mach** é baseado em **port rights**, enquanto o modelo de segurança do BSD opera com base na **propriedade dos processos**. As disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades locais de privilege-escalation. Além das system calls típicas, também existem **Mach traps que permitem que programas no espaço do usuário interajam com o kernel**. Esses diferentes elementos formam, em conjunto, a arquitetura multifacetada e híbrida do kernel do macOS.

### I/O Kit - Drivers

O I/O Kit é um **framework de device drivers** open source e orientado a objetos no kernel XNU, que gerencia **device drivers carregados dinamicamente**. Ele permite que código modular seja adicionado ao kernel on-the-fly, oferecendo suporte a diversos hardwares.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessadores na Arquitetura do macOS

As plataformas Apple dependem de vários coprocessadores para manter o trabalho sensível à latência fora dos cores principais e isolar funções críticas de segurança.

- **Secure Enclave Processor (SEP)**: Um core ARM dedicado com seu próprio microkernel e cadeia de secure boot, normalmente executando em **EL3/secure world**. A interação ocorre por meio de mailbox drivers no macOS, em EL1.
- Attack surface: Atualizações do firmware do SEP e os daemons em user-space (`seputil`, `securityd`) que fazem proxy das requisições.
- Impacto de um comprometimento: Expor long-term keys, contornar o bloqueio biométrico e quebrar as proteções do FileVault ou Apple Pay.
- **System Management Controller (SMC)**: Executa firmware proprietário em um microcontrolador fora dos níveis de exceção ARM. O macOS (EL1) o acessa por meio de user clients do I/O Kit.
- Attack surface: Mensagens de USB-C power delivery, interfaces de gerenciamento de ventoinhas/bateria e caminhos de atualização de firmware.
- Impacto de um comprometimento: Substituir limites térmicos, injetar dados falsos de sensores, desligar o dispositivo ou implantar backdoors persistentes no NVRAM.
- **T1/T2 Security Chips**: Executam o bridgeOS (derivado do watchOS), em grande parte em EL1/EL3, em seus próprios cores ARM. O macOS se comunica por canais semelhantes a PCIe/USB mediados pelo IOKit.
- Attack surface: Caminhos de DFU/restore, endpoints de IPC expostos por serviços como `tccd` e pipelines de mídia conectados ao T2.
- Impacto de um comprometimento: Desabilitar o secure boot, descriptografar o conteúdo do SSD, assumir o controle do bloqueio da câmera/microfone ou emular entrada HID para persistência furtiva.
- **Display Coprocessor (DCP)**: Executa firmware em EL1 dentro de um espaço de endereçamento isolado protegido pelo DART (IOMMU da Apple).
- Attack surface: Interfaces `DCPAVService`, buffers de descritores compartilhados e parsing de imagens de firmware.
- Impacto de um comprometimento: Injetar frames arbitrários, espionar framebuffers ou inutilizar o pipeline de display para causar DoS.
- **Apple Neural Engine (ANE)**: Executa microcode em um cluster ML dedicado (sem níveis EL ARM). O macOS agenda o trabalho por meio do `ANECompilerService` e do IOKit.
- Attack surface: Binários de modelos compilados (`.ane`), APIs do Core ML que alimentam kernels personalizados e loaders de firmware.
- Impacto de um comprometimento: Adulterar ou exfiltrar modelos ML, expor dados processados de áudio/visão ou sabotar a inferência no dispositivo.
- **AGX GPU**: O firmware é executado em cores GPU personalizados com um scheduler; EL0 envia comandos Metal que EL1 valida.
- Attack surface: Compilador de shaders Metal, APIs de mapeamento de buffers compartilhados e interfaces ioctl `com.apple.AGXFirmware`.
- Impacto de um comprometimento: Acesso DMA à memória do sistema, escapes do sandbox por meio de GPU drivers ou implantes persistentes de firmware.
- **Apple Video Encoder (AVE)**: O firmware é executado no Media Engine em um sandbox semelhante a EL1. O macOS interage por meio do VideoToolbox e do `AppleAVE2`.
- Attack surface: Bitstreams de codecs, conjuntos de parâmetros, buffers fornecidos pelo usuário e blobs de atualização de firmware.
- Impacto de um comprometimento: Expor frames não comprimidos, contornar DRM ou obter execução de código com acesso aos mecanismos DMA.
- **Image Signal Processor (ISP)**: Executa firmware seguro no cluster Media Engine; os drivers de câmera do macOS operam em EL1.
- Attack surface: HALs de câmera, descritores de frames RAW, filas de configuração do ISP e atualizações de firmware.
- Impacto de um comprometimento: Capturar feeds brutos da câmera silenciosamente, desabilitar indicadores de privacidade ou injetar imagens fabricadas.
- **AMX Matrix cores**: Operam como unidades coprocessadoras expostas em EL0/EL1 por meio de novas instruções.
- Attack surface: Virtualização do estado AMX pelo kernel (`thread_set_state`, trocas de contexto) e geração de código em user-space.
- Impacto de um comprometimento: Expor os tile registers de outros processos, fingerprint workloads ou realizar escalation por meio de corrupção de memória do kernel.

O macOS moderno trata esses coprocessadores como componentes confiáveis na chain of trust. O firmware do SEP, SMC e T2 é assinado pela Apple, e os protocolos de handshake (frequentemente implementados por mailboxes ou famílias do I/O Kit) incluem verificações challenge-response para que somente firmware autenticado possa atender às requisições.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Kernel Extensions do macOS

O macOS é **extremamente restritivo para carregar Kernel Extensions** (.kext), devido aos altos privilégios com os quais o código será executado. Na prática, por padrão, isso é praticamente impossível (a menos que seja encontrado um bypass).

Na página a seguir, você também pode ver como recuperar a `.kext` que o macOS carrega dentro de seu **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions do macOS

Em vez de usar Kernel Extensions, o macOS criou as System Extensions, que oferecem APIs no nível do usuário para interagir com o kernel. Dessa forma, os desenvolvedores podem evitar o uso de kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes e RSR (Rapid Security Response)

- **Cryptex** significa **CRYPTographically-sealed EXtension**. É uma imagem de disco selada (container) usada pela Apple para hospedar partes do OS (frameworks, shared libraries, apps) que têm maior probabilidade de mudar entre grandes atualizações do OS.
- No macOS e no iOS, componentes colocados dentro de cryptexes podem ser **corrigidos ou substituídos** por meio do RSR sem selar novamente todo o volume do sistema.
- Os Cryptexes ficam no volume **Preboot**, junto ao boot firmware, e são grafted no sistema de arquivos do OS em runtime.
- O carregamento do conteúdo do cryptex envolve validação: o sistema verifica seals de arquivos, manifests e root hashes; depois monta ou faz “graft” do conteúdo do cryptex para que, em runtime, os apps usem as versões do cryptex quando presentes.
- Nos boot logs, o carregamento do cryptex ocorre após a inicialização do kernel, mas antes que todos os system services estejam ativos.


#### Rapid Security Response (RSR)

- **RSR** é o mecanismo da Apple para entregar **security patches entre atualizações regulares do OS**. Ele tem como alvo o conteúdo dos cryptexes para atualizar partes vulneráveis (por exemplo, libraries e frameworks) sem modificar o volume principal do sistema.
- Ao aplicar uma atualização RSR, o dispositivo solicita ao signing server da Apple um manifesto **Cryptex1 Image4**. Esse manifesto é vinculado criptograficamente ao dispositivo e ao novo conteúdo do cryptex.
- O AP boot ticket existente do sistema base **não é modificado** pelo RSR. O patch funciona de forma aditiva sobre o OS base selado.
- No macOS, determinados componentes corrigidos (por exemplo, o Safari) tornam-se ativos assim que o app é relançado; nem sempre é necessário reiniciar completamente o sistema.
- Os RSRs são **removíveis**: cada um inclui um patch e um “antipatch” que pode reverter para a versão do OS base. Ao remover, o conteúdo do cryptex é revertido.
- As atualizações RSR geralmente são muito menores que as atualizações completas do OS e exigem um nível de bateria menor para serem instaladas.


## Referências

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
