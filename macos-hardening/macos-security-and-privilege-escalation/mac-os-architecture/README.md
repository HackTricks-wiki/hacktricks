# Kernel do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X não é Unix". Este kernel é fundamentalmente composto pelo **microkernel Mach** (a ser discutido posteriormente), **e** elementos do Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel por meio de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é livremente acessível**.

Do ponto de vista de um pesquisador de segurança ou de um desenvolvedor Unix, **o macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD** com uma GUI elegante e uma série de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para o BSD irá compilar e executar no macOS sem precisar de modificações, já que as ferramentas de linha de comando familiares aos usuários do Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora o Mach, existem algumas diferenças significativas entre um sistema semelhante ao Unix tradicional e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

### Mach

Mach é um **microkernel** projetado para ser **compatível com o UNIX**. Um de seus principais princípios de design foi **minimizar** a quantidade de **código** em execução no **espaço do kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, rede e E/S, **sejam executadas como tarefas de nível de usuário**.

No XNU, o Mach é **responsável por muitas das operações críticas de baixo nível** que um kernel normalmente manipula, como escalonamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O **kernel XNU** também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Este código **é executado como parte do kernel junto com o Mach**, no mesmo espaço de endereço. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD porque foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações do kernel, incluindo:

* Gerenciamento de processos
* Manipulação de sinais
* Mecanismos básicos de segurança, incluindo gerenciamento de usuários e grupos
* Infraestrutura de chamada do sistema
* Pilha TCP/IP e soquetes
* Firewall e filtragem de pacotes

Compreender a interação entre BSD e Mach pode ser complexo, devido aos seus diferentes quadros conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto o Mach opera com base em threads. Essa discrepância é reconciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada do sistema fork() do BSD é usada, o código do BSD dentro do kernel usa funções do Mach para criar uma tarefa e uma estrutura de thread.

Além disso, **o Mach e o BSD mantêm modelos de segurança diferentes**: o modelo de segurança do **Mach** é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base na **propriedade do processo**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas do sistema típicas, também existem **armadilhas do Mach que permitem que programas de espaço do usuário interajam com o kernel**. Esses diferentes elementos juntos formam a arquitetura multifacetada e híbrida do kernel do macOS.

### I/O Kit - Drivers

O I/O Kit é o framework de **driver de dispositivo orientado a objetos** de código aberto no kernel XNU e é responsável pela adição e gerenciamento de **drivers de dispositivo carregados dinamicamente**. Esses drivers permitem que o código modular seja adicionado ao kernel dinamicamente para uso com diferentes hardwares, por exemplo. Eles estão localizados em:

* `/System/Library/Extensions`
  * Arquivos KEXT incorporados ao sistema operacional OS X.
* `/Library/Extensions`
  * Arquivos KEXT instalados por software de terceiros.
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
Até o número 9, os drivers listados são **carregados no endereço 0**. Isso significa que eles não são drivers reais, mas **parte do kernel e não podem ser descarregados**.

Para encontrar extensões específicas, você pode usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para carregar e descarregar extensões de kernel, faça:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
### IPC - Comunicação Interprocesso

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## Extensões de Kernel do macOS

O macOS é **super restritivo para carregar Extensões de Kernel** (.kext) devido aos altos privilégios que o código executará. Na verdade, por padrão, é virtualmente impossível (a menos que seja encontrada uma forma de contornar isso).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
