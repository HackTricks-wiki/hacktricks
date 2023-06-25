## Extensões do Sistema macOS

Ao contrário das extensões do kernel, as **extensões do sistema são executadas no espaço do usuário** em vez do espaço do kernel, reduzindo o risco de falha do sistema devido a mau funcionamento da extensão.

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

Existem três tipos de extensões do sistema: extensões do **DriverKit**, extensões de **rede** e extensões de **segurança de endpoint**.

### **Extensões do DriverKit**

O DriverKit é um substituto para extensões do kernel que **fornecem suporte de hardware**. Ele permite que drivers de dispositivos (como drivers USB, Serial, NIC e HID) sejam executados no espaço do usuário em vez do espaço do kernel. O framework DriverKit inclui **versões do espaço do usuário de certas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o espaço do usuário, oferecendo um ambiente mais seguro para esses drivers serem executados.

### **Extensões de Rede**

As extensões de rede fornecem a capacidade de personalizar os comportamentos de rede. Existem vários tipos de extensões de rede:

* **Proxy de Aplicativo**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a fluxo. Isso significa que ele lida com o tráfego de rede com base em conexões (ou fluxos) em vez de pacotes individuais.
* **Túnel de Pacote**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a pacote. Isso significa que ele lida com o tráfego de rede com base em pacotes individuais.
* **Filtro de Dados**: Isso é usado para filtrar "fluxos" de rede. Ele pode monitorar ou modificar dados de rede no nível do fluxo.
* **Filtro de Pacote**: Isso é usado para filtrar pacotes de rede individuais. Ele pode monitorar ou modificar dados de rede no nível do pacote.
* **Proxy DNS**: Isso é usado para criar um provedor DNS personalizado. Ele pode ser usado para monitorar ou modificar solicitações e respostas DNS.

## Framework de Segurança de Endpoint

A Segurança de Endpoint é um framework fornecido pela Apple no macOS que fornece um conjunto de APIs para segurança do sistema. É destinado ao uso por **fornecedores de segurança e desenvolvedores para construir produtos que possam monitorar e controlar a atividade do sistema** para identificar e proteger contra atividades maliciosas.

Este framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos, eventos de rede e kernel.

O núcleo deste framework é implementado no kernel, como uma extensão do kernel (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**. Esta KEXT é composta por vários componentes principais:

* **EndpointSecurityDriver**: Isso atua como o "ponto de entrada" para a extensão do kernel. É o principal ponto de interação entre o sistema operacional e o framework de segurança de endpoint.
* **EndpointSecurityEventManager**: Este componente é responsável por implementar hooks do kernel. Hooks do kernel permitem que o framework monitore eventos do sistema interceptando chamadas do sistema.
* **EndpointSecurityClientManager**: Isso gerencia a comunicação com clientes do espaço do usuário, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
* **EndpointSecurityMessageManager**: Isso envia mensagens e notificações de eventos para clientes do espaço do usuário.

Os eventos que o framework de segurança de endpoint pode monitorar são categorizados em:

* Eventos de arquivo
* Eventos de processo
* Eventos de soquete
* Eventos do kernel (como carregar/descarregar uma extensão do kernel ou abrir um dispositivo I/O Kit)

### Arquitetura do Framework de Segurança de Endpoint

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

A **comunicação do espaço do usuário** com o framework de segurança de endpoint ocorre por meio da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de chamador:

* **EndpointSecurityDriverClient**: Isso requer a concessão `com.apple.private.endpoint-security.manager`, que é mantida apenas pelo processo do sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Isso requer a concessão `com.apple.developer.endpoint-security.client`. Isso seria usado normalmente por software de segurança de terceiros que precisa interagir com o framework de segurança de endpoint.

As Extensões de Segurança de Endpoint: **`libEndpointSecurity.dylib`** é a biblioteca C que as extensões do sistema usam para se comunicar com o kernel. Esta biblioteca usa o I/O Kit (`IOKit`) para se comunicar com a extensão do kernel de segurança de endpoint.

**`endpointsecurityd`** é um daemon do sistema chave envolvido na gestão e lançamento de extensões do sistema de segurança de endpoint, particularmente durante o processo de inicialização inicial. Somente as extensões do sistema marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem este tratamento de inicialização inicial.

Outro daemon do sistema, **`sysextd`**, **valida as extensões do sistema** e as move para as localizações apropriadas do sistema. Em seguida, ele pede ao daemon relevante para carregar a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar as extensões do sistema.
## Bypassando o ESF

O ESF é usado por ferramentas de segurança que tentarão detectar um red teamer, então qualquer informação sobre como isso poderia ser evitado soa interessante.

### CVE-2021-30965

A questão é que o aplicativo de segurança precisa ter **permissões de acesso total ao disco**. Portanto, se um invasor pudesse remover isso, ele poderia impedir que o software fosse executado:
```bash
tccutil reset All
```
Para **mais informações** sobre essa falha e outras relacionadas, confira a palestra [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido dando a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado por **`tccd`** para que o `tccutil` não limpe suas permissões, impedindo-o de ser executado.

## Referências

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
