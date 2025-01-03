# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

O **núcleo do macOS é o XNU**, que significa "X is Not Unix". Este núcleo é fundamentalmente composto pelo **microkernel Mach** (que será discutido mais adiante), **e** elementos da Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel através de um sistema chamado I/O Kit**. O núcleo XNU é parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é acessível livremente**.

Do ponto de vista de um pesquisador de segurança ou desenvolvedor Unix, **macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD** com uma GUI elegante e uma série de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para BSD será compilada e executada no macOS sem precisar de modificações, já que as ferramentas de linha de comando familiares aos usuários de Unix estão todas presentes no macOS. No entanto, como o núcleo XNU incorpora Mach, existem algumas diferenças significativas entre um sistema tradicional semelhante ao Unix e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

Versão de código aberto do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **microkernel** projetado para ser **compatível com UNIX**. Um de seus princípios de design chave era **minimizar** a quantidade de **código** executando no espaço do **núcleo** e, em vez disso, permitir que muitas funções típicas do núcleo, como sistema de arquivos, rede e I/O, **executem como tarefas de nível de usuário**.

No XNU, Mach é **responsável por muitas das operações críticas de baixo nível** que um núcleo normalmente lida, como agendamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O **núcleo** XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Este código **executa como parte do núcleo junto com Mach**, no mesmo espaço de endereço. No entanto, o código FreeBSD dentro do XNU pode diferir substancialmente do código FreeBSD original porque modificações foram necessárias para garantir sua compatibilidade com Mach. O FreeBSD contribui para muitas operações do núcleo, incluindo:

- Gerenciamento de processos
- Manipulação de sinais
- Mecanismos básicos de segurança, incluindo gerenciamento de usuários e grupos
- Infraestrutura de chamadas de sistema
- Pilha TCP/IP e sockets
- Firewall e filtragem de pacotes

Entender a interação entre BSD e Mach pode ser complexo, devido aos seus diferentes frameworks conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto Mach opera com base em threads. Essa discrepância é reconciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada de sistema fork() do BSD é usada, o código BSD dentro do núcleo utiliza funções Mach para criar uma estrutura de tarefa e thread.

Além disso, **Mach e BSD mantêm diferentes modelos de segurança**: o modelo de segurança do **Mach** é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base em **propriedade de processos**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas de sistema típicas, também existem **traps Mach que permitem que programas de espaço de usuário interajam com o núcleo**. Esses diferentes elementos juntos formam a arquitetura híbrida multifacetada do núcleo do macOS.

### I/O Kit - Drivers

O I/O Kit é um framework de **driver de dispositivo** orientado a objetos e de código aberto no núcleo XNU, que lida com **drivers de dispositivo carregados dinamicamente**. Ele permite que código modular seja adicionado ao núcleo em tempo real, suportando hardware diversificado.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

O macOS é **super restritivo para carregar Extensões de Núcleo** (.kext) devido aos altos privilégios com que o código será executado. Na verdade, por padrão, é virtualmente impossível (a menos que um bypass seja encontrado).

Na página seguinte, você também pode ver como recuperar o `.kext` que o macOS carrega dentro de seu **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Em vez de usar Extensões de Núcleo, o macOS criou as Extensões de Sistema, que oferecem APIs em nível de usuário para interagir com o núcleo. Dessa forma, os desenvolvedores podem evitar o uso de extensões de núcleo.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
