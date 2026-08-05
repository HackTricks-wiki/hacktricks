# Extensões do Sistema macOS

{{#include ../../../banners/hacktricks-training.md}}

## Extensões do Sistema / Endpoint Security Framework

Ao contrário das Kernel Extensions, as **System Extensions são executadas no user space** em vez do kernel space, reduzindo o risco de um crash do sistema devido a falhas na extensão.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existem três tipos de system extensions: extensões **DriverKit**, extensões de **Network** e extensões de **Endpoint Security**.

### **DriverKit Extensions**

O DriverKit é um substituto para kernel extensions que **fornecem suporte a hardware**. Ele permite que device drivers (como drivers USB, Serial, NIC e HID) sejam executados no user space, em vez do kernel space. O framework DriverKit inclui **versões em user space de determinadas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o user space, oferecendo um ambiente mais seguro para a execução desses drivers.<sup>[[2]](#references)</sup>

### **Network Extensions**

As Network Extensions permitem personalizar comportamentos de rede. Existem vários tipos de Network Extensions:

- **App Proxy**: usado para criar um cliente VPN que implementa um protocolo VPN customizado e orientado a fluxos. Isso significa que ele trata o tráfego de rede com base em conexões (ou fluxos), em vez de pacotes individuais.
- **Packet Tunnel**: usado para criar um cliente VPN que implementa um protocolo VPN customizado e orientado a pacotes. Isso significa que ele trata o tráfego de rede com base em pacotes individuais.
- **Filter Data**: usado para filtrar "fluxos" de rede. Ele pode monitorar ou modificar dados de rede no nível do fluxo.
- **Filter Packet**: usado para filtrar pacotes de rede individuais. Ele pode monitorar ou modificar dados de rede no nível do pacote.
- **DNS Proxy**: usado para criar um provedor DNS customizado. Ele pode ser usado para monitorar ou modificar solicitações e respostas DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

O Endpoint Security é um framework fornecido pela Apple no macOS que disponibiliza um conjunto de APIs para a segurança do sistema. Ele foi desenvolvido para que **security vendors e developers criem produtos capazes de monitorar e controlar a atividade do sistema**, a fim de identificar e proteger contra atividades maliciosas.

Esse framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos e eventos de rede e do kernel.

O núcleo desse framework é implementado no kernel, como uma Kernel Extension (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Essa KEXT é composta por vários componentes importantes:

- **EndpointSecurityDriver**: atua como o "ponto de entrada" da kernel extension. É o principal ponto de interação entre o OS e o Endpoint Security framework.
- **EndpointSecurityEventManager**: esse componente é responsável por implementar kernel hooks. Os kernel hooks permitem que o framework monitore eventos do sistema interceptando system calls.
- **EndpointSecurityClientManager**: gerencia a comunicação com clientes no user space, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
- **EndpointSecurityMessageManager**: envia mensagens e notificações de eventos para clientes no user space.

Os eventos que o Endpoint Security framework pode monitorar são categorizados em:

- Eventos de arquivos
- Eventos de processos
- Eventos de sockets
- Eventos do kernel (como carregar/descarregar uma kernel extension ou abrir um dispositivo do I/O Kit)

### Arquitetura do Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

A **comunicação no user space** com o Endpoint Security framework ocorre por meio da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de caller:

- **EndpointSecurityDriverClient**: requer o entitlement `com.apple.private.endpoint-security.manager`, que é mantido exclusivamente pelo processo do sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: requer o entitlement `com.apple.developer.endpoint-security.client`. Normalmente, ele seria usado por software de segurança de terceiros que precisa interagir com o Endpoint Security framework.<sup>[[1]](#references)</sup>

As extensões do Endpoint Security:**`libEndpointSecurity.dylib`** é a biblioteca C que as system extensions usam para se comunicar com o kernel. Essa biblioteca usa o I/O Kit (`IOKit`) para se comunicar com a Endpoint Security KEXT.<sup>[[2]](#references)</sup>

O **`endpointsecurityd`** é um daemon importante do sistema envolvido no gerenciamento e no lançamento de system extensions de endpoint security, especialmente durante o processo de early boot. **Somente system extensions** marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem esse tratamento de early boot.<sup>[[2]](#references)</sup>

Outro daemon do sistema, o **`sysextd`**, **valida as system extensions** e as move para os locais apropriados do sistema. Em seguida, ele solicita ao daemon relevante que carregue a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

O ESF é usado por security tools que tentarão detectar um red teamer, portanto qualquer informação sobre como isso poderia ser evitado parece interessante.

### CVE-2021-30965

O problema é que a security application precisa ter permissões de **Full Disk Access**. Portanto, se um attacker conseguisse removê-las, poderia impedir a execução do software:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Para obter **mais informações** sobre este bypass e outros relacionados, consulte a palestra [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido concedendo a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado pelo **`tccd`**, para que o **`tccutil`** não limpe suas permissões, impedindo-o de ser executado.<sup>[[3]](#references)</sup>

## Referências

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
