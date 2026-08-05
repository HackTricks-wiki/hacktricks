# Extensões do sistema macOS

{{#include ../../../banners/hacktricks-training.md}}

## Extensões do sistema / Endpoint Security Framework

Ao contrário das Kernel Extensions, as **System Extensions são executadas no espaço do usuário** em vez do espaço do kernel, reduzindo o risco de uma falha do sistema devido ao mau funcionamento da extensão.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existem três tipos de extensões do sistema: extensões **DriverKit**, extensões de **Network** e extensões de **Endpoint Security**.

### **Extensões DriverKit**

O DriverKit substitui as Kernel Extensions que **fornecem suporte de hardware**. Ele permite que drivers de dispositivos (como drivers USB, Serial, NIC e HID) sejam executados no espaço do usuário em vez do espaço do kernel. O framework DriverKit inclui **versões no espaço do usuário de determinadas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o espaço do usuário, oferecendo um ambiente mais seguro para a execução desses drivers.<sup>[2]</sup>

### **Network Extensions**

As Network Extensions permitem personalizar comportamentos de rede. Existem vários tipos de Network Extensions:

- **App Proxy**: usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a fluxos. Isso significa que ele trata o tráfego de rede com base em conexões (ou fluxos), em vez de pacotes individuais.
- **Packet Tunnel**: usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a pacotes. Isso significa que ele trata o tráfego de rede com base em pacotes individuais.
- **Filter Data**: usado para filtrar "fluxos" de rede. Ele pode monitorar ou modificar dados de rede no nível do fluxo.
- **Filter Packet**: usado para filtrar pacotes de rede individuais. Ele pode monitorar ou modificar dados de rede no nível do pacote.
- **DNS Proxy**: usado para criar um provedor DNS personalizado. Ele pode ser usado para monitorar ou modificar solicitações e respostas DNS.<sup>[2]</sup>

## Endpoint Security Framework

O Endpoint Security é um framework fornecido pela Apple no macOS que disponibiliza um conjunto de APIs para a segurança do sistema. Ele se destina ao uso por **fornecedores e desenvolvedores de soluções de segurança para criar produtos capazes de monitorar e controlar a atividade do sistema**, a fim de identificar e proteger contra atividades maliciosas.

Esse framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos, eventos de rede e do kernel.

O núcleo desse framework é implementado no kernel, como uma Kernel Extension (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Essa KEXT é composta por vários componentes importantes:

- **EndpointSecurityDriver**: atua como o "ponto de entrada" da Kernel Extension. É o principal ponto de interação entre o sistema operacional e o Endpoint Security framework.
- **EndpointSecurityEventManager**: esse componente é responsável por implementar hooks do kernel. Os hooks do kernel permitem que o framework monitore eventos do sistema interceptando chamadas do sistema.
- **EndpointSecurityClientManager**: gerencia a comunicação com clientes no espaço do usuário, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
- **EndpointSecurityMessageManager**: envia mensagens e notificações de eventos aos clientes no espaço do usuário.

Os eventos que o Endpoint Security framework pode monitorar são categorizados em:

- Eventos de arquivos
- Eventos de processos
- Eventos de sockets
- Eventos do kernel (como carregar/descarregar uma Kernel Extension ou abrir um dispositivo do I/O Kit)

### Arquitetura do Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

A **comunicação no espaço do usuário** com o Endpoint Security framework ocorre por meio da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de chamador:

- **EndpointSecurityDriverClient**: requer o entitlement `com.apple.private.endpoint-security.manager`, que é mantido exclusivamente pelo processo do sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: requer o entitlement `com.apple.developer.endpoint-security.client`. Normalmente, ele seria usado por software de segurança de terceiros que precisa interagir com o Endpoint Security framework.<sup>[1]</sup>

As Endpoint Security Extensions:**`libEndpointSecurity.dylib`** é a biblioteca C que as system extensions usam para se comunicar com o kernel. Essa biblioteca usa o I/O Kit (`IOKit`) para se comunicar com a KEXT do Endpoint Security.<sup>[2]</sup>

**`endpointsecurityd`** é um daemon importante do sistema envolvido no gerenciamento e no lançamento de system extensions de segurança de endpoint, especialmente durante o processo de inicialização antecipada. **Somente system extensions** marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem esse tratamento de inicialização antecipada.<sup>[2]</sup>

Outro daemon do sistema, **`sysextd`**, **valida as system extensions** e as move para os locais apropriados do sistema. Em seguida, solicita ao daemon relevante que carregue a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar as system extensions.<sup>[2]</sup>

## Bypassing ESF

O ESF é usado por ferramentas de segurança que tentarão detectar um red teamer, portanto, qualquer informação sobre como isso poderia ser evitado parece interessante.

### CVE-2021-30965

A questão é que o aplicativo de segurança precisa ter **permissões de Full Disk Access**. Portanto, se um atacante conseguisse removê-las, poderia impedir a execução do software:<sup>[3]</sup>
```bash
tccutil reset All
```
Para **mais informações** sobre este bypass e outros relacionados, confira a palestra [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido concedendo a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado pelo **`tccd`**, para que o `tccutil` não limpe suas permissões, impedindo sua execução.<sup>[3]</sup>

## Referências

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
