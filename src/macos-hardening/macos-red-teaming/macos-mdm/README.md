# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para saber mais sobre MDMs do macOS, consulte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Noções básicas

### **Visão geral do MDM (Mobile Device Management)**

O [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) é utilizado para supervisionar vários dispositivos de usuários finais, como smartphones, laptops e tablets. Especificamente para as plataformas da Apple (iOS, macOS, tvOS), ele envolve um conjunto de recursos, APIs e práticas especializadas. A operação do MDM depende de um servidor MDM compatível, que pode ser comercial ou open-source, e deve oferecer suporte ao [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Os pontos principais incluem:

- Controle centralizado sobre os dispositivos.
- Dependência de um servidor MDM que siga o protocolo MDM.
- Capacidade do servidor MDM de enviar vários comandos aos dispositivos, como apagar dados remotamente ou instalar configurações.

### **Noções básicas do DEP (Device Enrollment Program)**

O [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), oferecido pela Apple, simplifica a integração do Mobile Device Management (MDM) ao permitir a configuração zero-touch de dispositivos iOS, macOS e tvOS. O DEP automatiza o processo de enrollment, permitindo que os dispositivos estejam operacionais assim que saem da caixa, com mínima intervenção do usuário ou do administrador. Os aspectos essenciais incluem:

- Permite que os dispositivos se registrem automaticamente em um servidor MDM predefinido durante a ativação inicial.
- É principalmente benéfico para dispositivos novos, mas também pode ser aplicado a dispositivos em processo de reconfiguração.
- Facilita uma configuração simples, deixando os dispositivos prontos rapidamente para uso organizacional.

### **Consideração de segurança**

É importante observar que a facilidade de enrollment proporcionada pelo DEP, embora benéfica, também pode representar riscos de segurança. Se as medidas de proteção não forem aplicadas adequadamente ao enrollment do MDM, atacantes poderão explorar esse processo simplificado para registrar seu dispositivo no servidor MDM da organização, fazendo-o passar por um dispositivo corporativo.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerta de segurança**: O enrollment simplificado do DEP pode permitir potencialmente o registro não autorizado de dispositivos no servidor MDM da organização caso as proteções adequadas não estejam implementadas.

### Noções básicas: o que é SCEP (Simple Certificate Enrolment Protocol)?

- Um protocolo relativamente antigo, criado antes que TLS e HTTPS fossem amplamente utilizados.
- Fornece aos clientes uma forma padronizada de enviar uma **Certificate Signing Request** (CSR) com o objetivo de receber um certificado. O cliente solicitará ao servidor um certificado assinado.

### O que são Configuration Profiles (também conhecidos como mobileconfigs)?

- A forma oficial da Apple de **definir/aplicar configurações do sistema**.
- Formato de arquivo que pode conter múltiplos payloads.
- Baseado em property lists (do tipo XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocolos

### MDM

- Combinação de APNs (**servidores da Apple**) + RESTful API (servidores do **vendor** de **MDM**)
- A **comunicação** ocorre entre um **dispositivo** e um servidor associado a um **produto** de **gerenciamento** de **dispositivos**
- **Comandos** enviados do MDM para o dispositivo em **dicionários codificados em plist**
- Tudo por **HTTPS**. Os servidores MDM podem usar (e normalmente usam) pinning.
- A Apple concede ao vendor de MDM um **certificado APNs** para autenticação

### DEP

- **3 APIs**: 1 para revendedores, 1 para vendors de MDM e 1 para identidade do dispositivo (não documentada):
- A chamada API de [DEP "cloud service"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). É utilizada pelos servidores MDM para associar perfis DEP a dispositivos específicos.
- A [DEP API usada pelos Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para fazer enrollment de dispositivos, verificar o status do enrollment e verificar o status das transações.
- A API privada DEP não documentada. É utilizada pelos Apple Devices para solicitar seu perfil DEP. No macOS, o binário `cloudconfigurationd` é responsável pela comunicação por meio dessa API.
- Mais moderna e baseada em **JSON** (em comparação com plist)
- A Apple concede um **OAuth token** ao vendor de MDM

**DEP "cloud service" API**

- RESTful
- sincroniza os registros de dispositivos da Apple com o servidor MDM
- sincroniza “perfis DEP” do servidor MDM com a Apple (posteriormente enviados pela Apple ao dispositivo)
- Um “perfil” DEP contém:
- URL do servidor do vendor de MDM
- Certificados confiáveis adicionais para a URL do servidor (pinning opcional)
- Configurações extras (por exemplo, quais telas devem ser ignoradas no Setup Assistant)

## Número de série

Os dispositivos Apple fabricados após 2010 geralmente possuem números de série **alfanuméricos de 12 caracteres**, sendo que os **três primeiros dígitos representam o local de fabricação**, os **dois seguintes** indicam o **ano** e a **semana** de fabricação, os **três dígitos seguintes** fornecem um **identificador** **único**, e os **últimos** **quatro** dígitos representam o **número do modelo**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapas de enrollment e gerenciamento

1. Criação do registro do dispositivo (Revendedor, Apple): O registro do novo dispositivo é criado
2. Atribuição do registro do dispositivo (Cliente): O dispositivo é atribuído a um servidor MDM
3. Sincronização do registro do dispositivo (vendor de MDM): O MDM sincroniza os registros dos dispositivos e envia os perfis DEP para a Apple
4. DEP check-in (Dispositivo): O dispositivo recebe seu perfil DEP
5. Recuperação do perfil (Dispositivo)
6. Instalação do perfil (Dispositivo) a. incluindo payloads de MDM, SCEP e root CA
7. Emissão de comandos MDM (Dispositivo)

![Número de série - Etapas de enrollment e gerenciamento: 7. Emissão de comandos MDM (Dispositivo)](<../../../images/image (694).png>)

O arquivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funções que podem ser consideradas **"etapas" de alto nível** do processo de enrollment.

### Etapa 4: DEP check-in - Obtendo o Activation Record

Esta parte do processo ocorre quando um **usuário inicializa um Mac pela primeira vez** (ou após uma limpeza completa)

![Etapas de enrollment e gerenciamento - Etapa 4: DEP check-in - Obtendo o Activation Record: Esta parte do processo ocorre quando um usuário inicializa um Mac pela primeira vez (ou após uma...](<../../../images/image (1044).png>)

ou ao executar `sudo profiles show -type enrollment`

- Determina **se o dispositivo está habilitado para DEP**
- Activation Record é o nome interno do **“perfil” DEP**
- Começa assim que o dispositivo é conectado à Internet
- Conduzido por **`CPFetchActivationRecord`**
- Implementado pelo **`cloudconfigurationd`** via XPC. O **"Setup Assistant**" (quando o dispositivo é inicializado pela primeira vez) ou o comando **`profiles`** entrará em contato com esse daemon para recuperar o activation record.
- LaunchDaemon (sempre executado como root)

O processo segue algumas etapas para obter o Activation Record, realizadas pelo **`MCTeslaConfigurationFetcher`**. Esse processo utiliza uma criptografia chamada **Absinthe**<sup>[[1]](#references)</sup>

1. Recuperar **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** o estado a partir do certificado (**`NACInit`**)
1. Usa vários dados específicos do dispositivo (ou seja, **Serial Number via `IOKit`**)
3. Recuperar **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Estabelecer a sessão (**`NACKeyEstablishment`**)
5. Fazer a solicitação
1. POST para [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando os dados `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. O payload JSON é criptografado usando Absinthe (**`NACSign`**)
3. Todas as solicitações usam HTTPs, com certificados raiz integrados

![Etapas de enrollment e gerenciamento - Etapa 4: DEP check-in - Obtendo o Activation Record: 3. Todas as solicitações usam HTTPs, com certificados raiz integrados](<../../../images/image (566) (1).png>)

A resposta é um dicionário JSON com alguns dados importantes, como:

- **url**: URL do host do vendor de MDM para o activation profile
- **anchor-certs**: Array de certificados DER utilizados como âncoras confiáveis

### **Etapa 5: Recuperação do perfil**

![Etapa 4: DEP check-in - Obtendo o Activation Record - Etapa 5: Recuperação do perfil: Etapa 5: Recuperação do perfil](<../../../images/image (444).png>)

- Solicitação enviada para a **url fornecida no perfil DEP**.
- **Certificados de âncora** são utilizados para **avaliar a confiança**, quando fornecidos.
- Lembrete: a propriedade **anchor_certs** do perfil DEP
- **A solicitação é um .plist simples** com a identificação do dispositivo
- Exemplos: **UDID, versão do sistema operacional**.
- Assinado por CMS, codificado em DER
- Assinado usando o **certificado de identidade do dispositivo (do APNS)**
- A **cadeia de certificados** inclui o **Apple iPhone Device CA** expirado

![Etapa 4: DEP check-in - Obtendo o Activation Record - Etapa 5: Recuperação do perfil: Assinado usando o certificado de identidade do dispositivo (do APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Etapa 6: Instalação do perfil

- Depois de recuperado, o **perfil é armazenado no sistema**
- Esta etapa começa automaticamente (se estiver no **setup assistant**)
- Conduzida por **`CPInstallActivationProfile`**
- Implementada pelo mdmclient via XPC
- LaunchDaemon (como root) ou LaunchAgent (como usuário), dependendo do contexto
- Configuration profiles possuem múltiplos payloads para instalar
- O framework possui uma arquitetura baseada em plugins para instalar perfis
- Cada tipo de payload é associado a um plugin
- Pode ser XPC (no framework) ou Cocoa clássico (no ManagedClient.app)
- Exemplo:
- Certificate Payloads usam CertificateService.xpc

Normalmente, o **activation profile** fornecido por um vendor de MDM **incluirá os seguintes payloads**:

- `com.apple.mdm`: para fazer **enrollment** do dispositivo no MDM
- `com.apple.security.scep`: para fornecer com segurança um **certificado de cliente** ao dispositivo.
- `com.apple.security.pem`: para **instalar certificados CA confiáveis** no System Keychain do dispositivo.
- A instalação do payload MDM equivale ao **MDM check-in na documentação**
- O payload **contém propriedades importantes**:
- - URL de MDM Check-In (**`CheckInURL`**)
- URL de MDM Command Polling (**`ServerURL`**) + tópico APNs para acioná-la
- Para instalar o payload MDM, uma solicitação é enviada para **`CheckInURL`**
- Implementado em **`mdmclient`**
- O payload MDM pode depender de outros payloads
- Permite que as **solicitações sejam fixadas a certificados específicos**:
- Propriedade: **`CheckInURLPinningCertificateUUIDs`**
- Propriedade: **`ServerURLPinningCertificateUUIDs`**
- Entregue por meio de um payload PEM
- Permite atribuir ao dispositivo um certificado de identidade:
- Propriedade: IdentityCertificateUUID
- Entregue por meio de um payload SCEP

### **Etapa 7: Escutando comandos MDM**

- Após a conclusão do MDM check-in, o vendor pode **emitir notificações push usando APNs**
- Ao serem recebidas, são tratadas pelo **`mdmclient`**
- Para consultar comandos MDM, uma solicitação é enviada para ServerURL
- Utiliza o payload MDM instalado anteriormente:
- **`ServerURLPinningCertificateUUIDs`** para pinning da solicitação
- **`IdentityCertificateUUID`** para o certificado de cliente TLS

## Ataques

### Fazendo enrollment de dispositivos em outras organizações

Como comentado anteriormente, para tentar fazer enrollment de um dispositivo em uma organização, **é necessário apenas um Serial Number pertencente a essa organização**. Depois que o dispositivo é registrado, várias organizações instalam dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, esse pode ser um ponto de entrada perigoso para atacantes se o processo de enrollment não estiver protegido corretamente:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referências

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
