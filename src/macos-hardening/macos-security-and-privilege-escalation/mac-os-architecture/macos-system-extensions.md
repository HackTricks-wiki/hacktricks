# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Ao contrário das Kernel Extensions, **as System Extensions são executadas no espaço do usuário** em vez do espaço do kernel, reduzindo o risco de uma falha do sistema devido a mau funcionamento da extensão.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existem três tipos de system extensions: **DriverKit** Extensions, **Network** Extensions e **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit é um substituto para kernel extensions que **fornecem suporte de hardware**. Ele permite que drivers de dispositivo (como drivers USB, Serial, NIC e HID) sejam executados no espaço do usuário em vez do espaço do kernel. O framework DriverKit inclui **versões de espaço do usuário de certas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o espaço do usuário, oferecendo um ambiente mais seguro para esses drivers serem executados.

### **Network Extensions**

Network Extensions fornecem a capacidade de personalizar comportamentos de rede. Existem vários tipos de Network Extensions:

- **App Proxy**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a fluxo. Isso significa que ele lida com o tráfego de rede com base em conexões (ou fluxos) em vez de pacotes individuais.
- **Packet Tunnel**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a pacotes. Isso significa que ele lida com o tráfego de rede com base em pacotes individuais.
- **Filter Data**: Isso é usado para filtrar "fluxos" de rede. Ele pode monitorar ou modificar dados de rede no nível do fluxo.
- **Filter Packet**: Isso é usado para filtrar pacotes de rede individuais. Ele pode monitorar ou modificar dados de rede no nível do pacote.
- **DNS Proxy**: Isso é usado para criar um provedor DNS personalizado. Ele pode ser usado para monitorar ou modificar solicitações e respostas DNS.

## Endpoint Security Framework

Endpoint Security é um framework fornecido pela Apple no macOS que oferece um conjunto de APIs para segurança do sistema. É destinado ao uso por **fornecedores de segurança e desenvolvedores para construir produtos que podem monitorar e controlar a atividade do sistema** para identificar e proteger contra atividades maliciosas.

Este framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos, eventos de rede e do kernel.

O núcleo deste framework é implementado no kernel, como uma Kernel Extension (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**. Este KEXT é composto por vários componentes-chave:

- **EndpointSecurityDriver**: Isso atua como o "ponto de entrada" para a extensão do kernel. É o principal ponto de interação entre o OS e o framework de Endpoint Security.
- **EndpointSecurityEventManager**: Este componente é responsável por implementar hooks do kernel. Hooks do kernel permitem que o framework monitore eventos do sistema interceptando chamadas de sistema.
- **EndpointSecurityClientManager**: Isso gerencia a comunicação com clientes do espaço do usuário, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
- **EndpointSecurityMessageManager**: Isso envia mensagens e notificações de eventos para clientes do espaço do usuário.

Os eventos que o framework de Endpoint Security pode monitorar são categorizados em:

- Eventos de arquivo
- Eventos de processo
- Eventos de socket
- Eventos do kernel (como carregar/descarregar uma extensão do kernel ou abrir um dispositivo do I/O Kit)

### Arquitetura do Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

A **comunicação no espaço do usuário** com o framework de Endpoint Security acontece através da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de chamador:

- **EndpointSecurityDriverClient**: Isso requer a permissão `com.apple.private.endpoint-security.manager`, que é mantida apenas pelo processo do sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Isso requer a permissão `com.apple.developer.endpoint-security.client`. Isso seria tipicamente usado por software de segurança de terceiros que precisa interagir com o framework de Endpoint Security.

As Endpoint Security Extensions:**`libEndpointSecurity.dylib`** é a biblioteca C que as system extensions usam para se comunicar com o kernel. Esta biblioteca usa o I/O Kit (`IOKit`) para se comunicar com o KEXT de Endpoint Security.

**`endpointsecurityd`** é um daemon do sistema chave envolvido na gestão e lançamento de system extensions de segurança de endpoint, particularmente durante o processo de inicialização inicial. **Apenas as system extensions** marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem esse tratamento de inicialização antecipada.

Outro daemon do sistema, **`sysextd`**, **valida as system extensions** e as move para os locais apropriados do sistema. Em seguida, ele pede ao daemon relevante para carregar a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar system extensions.

## Bypassing ESF

ESF é usado por ferramentas de segurança que tentarão detectar um red teamer, então qualquer informação sobre como isso poderia ser evitado soa interessante.

### CVE-2021-30965

A questão é que o aplicativo de segurança precisa ter **permissões de Acesso Completo ao Disco**. Portanto, se um atacante pudesse remover isso, ele poderia impedir que o software fosse executado:
```bash
tccutil reset All
```
Para **mais informações** sobre este bypass e relacionados, confira a palestra [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido ao conceder a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado por **`tccd`**, de modo que `tccutil` não limpe suas permissões, impedindo-o de ser executado.

## Referências

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
