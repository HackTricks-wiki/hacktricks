# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para aprender sobre MDMs do macOS, consulte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Noções básicas

### **Visão geral do MDM (Mobile Device Management)**

O [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) é utilizado para supervisionar vários dispositivos de usuários finais, como smartphones, laptops e tablets. Especificamente para as plataformas da Apple (iOS, macOS, tvOS), ele envolve um conjunto de recursos, APIs e práticas especializadas. O funcionamento do MDM depende de um servidor MDM compatível, que pode estar disponível comercialmente ou ser open-source, e deve oferecer suporte ao [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Os principais pontos incluem:

- Controle centralizado sobre os dispositivos.
- Dependência de um servidor MDM que segue o protocolo MDM.
- Capacidade do servidor MDM de enviar vários comandos aos dispositivos, como apagar dados remotamente ou instalar configurações.

### **Noções básicas do DEP (Device Enrollment Program)**

O [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) oferecido pela Apple simplifica a integração do Mobile Device Management (MDM), facilitando a configuração zero-touch de dispositivos iOS, macOS e tvOS. O DEP automatiza o processo de enrollment, permitindo que os dispositivos estejam operacionais assim que saem da caixa, com mínima intervenção do usuário ou do administrador. Os aspectos essenciais incluem:

- Permite que os dispositivos se registrem autonomamente em um servidor MDM predefinido durante a ativação inicial.
- É principalmente útil para dispositivos novos, mas também pode ser aplicado a dispositivos que estejam passando por reconfiguração.
- Facilita uma configuração simples, deixando os dispositivos rapidamente prontos para uso na organização.

### **Consideração de segurança**

É importante observar que a facilidade de enrollment proporcionada pelo DEP, embora benéfica, também pode apresentar riscos de segurança. Se as medidas de proteção não forem aplicadas adequadamente ao enrollment no MDM, os atacantes poderão explorar esse processo simplificado para registrar seu dispositivo no servidor MDM da organização, fazendo-o passar por um dispositivo corporativo.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerta de segurança**: o enrollment simplificado do DEP pode permitir potencialmente o registro não autorizado de dispositivos no servidor MDM da organização se as proteções adequadas não estiverem implementadas.

### Noções básicas: o que é SCEP (Simple Certificate Enrolment Protocol)?

- Um protocolo relativamente antigo, criado antes que TLS e HTTPS fossem amplamente utilizados.
- Oferece aos clientes uma forma padronizada de enviar uma **Certificate Signing Request** (CSR) com o objetivo de receber um certificado. O cliente solicitará ao servidor um certificado assinado.

### O que são Configuration Profiles (também conhecidos como mobileconfigs)?

- A forma oficial da Apple de **definir/aplicar configurações do sistema**.
- Formato de arquivo que pode conter vários payloads.
- Baseado em property lists (do tipo XML).
- “pode ser assinado e criptografado para validar sua origem, garantir sua integridade e proteger seu conteúdo.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocolos

### MDM

- Combinação de APNs (**servidores da Apple**) + RESTful API (servidores do **vendor** de **MDM**)
- A **comunicação** ocorre entre um **dispositivo** e um servidor associado a um **produto** de **gerenciamento** de **dispositivos**
- **Comandos** enviados do MDM para o dispositivo em **dicionários codificados em plist**
- Tudo por **HTTPS**. Os servidores MDM podem (e geralmente são) pinned.
- A Apple concede ao vendor de MDM um **certificado APNs** para autenticação

### DEP

- **3 APIs**: 1 para revendedores, 1 para vendors de MDM e 1 para identidade do dispositivo (não documentada):
- A chamada [API de “cloud service” do DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ela é utilizada pelos servidores MDM para associar perfis DEP a dispositivos específicos.
- A [API DEP usada pelos Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para fazer o enrollment dos dispositivos, verificar o status do enrollment e verificar o status das transações.
- A API DEP privada não documentada. Ela é utilizada pelos Apple Devices para solicitar seu perfil DEP. No macOS, o binário `cloudconfigurationd` é responsável pela comunicação com essa API.
- Mais moderna e baseada em **JSON** (em comparação com plist)
- A Apple concede um **token OAuth** ao vendor de MDM

**API de “cloud service” do DEP**

- RESTful
- sincroniza os registros de dispositivos da Apple com o servidor MDM
- sincroniza “perfis DEP” do servidor MDM para a Apple (entregues posteriormente pela Apple ao dispositivo)
- Um “perfil” DEP contém:
- URL do servidor do vendor de MDM
- Certificados confiáveis adicionais para a URL do servidor (pinning opcional)
- Configurações adicionais (por exemplo, quais telas ignorar no Setup Assistant)

## Número de série

Os dispositivos Apple fabricados após 2010 geralmente possuem números de série **alfanuméricos de 12 caracteres**, em que os **três primeiros dígitos representam o local de fabricação**, os **dois seguintes** indicam o **ano** e a **semana** de fabricação, os **três dígitos seguintes** fornecem um **identificador** **único** e os **últimos quatro** representam o **número do modelo**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapas de enrollment e gerenciamento

1. Criação do registro do dispositivo (Revendedor, Apple): o registro do novo dispositivo é criado
2. Atribuição do registro do dispositivo (Cliente): o dispositivo é atribuído a um servidor MDM
3. Sincronização do registro do dispositivo (vendor de MDM): o MDM sincroniza os registros dos dispositivos e envia os perfis DEP para a Apple
4. Check-in do DEP (Dispositivo): o dispositivo recebe seu perfil DEP
5. Recuperação do perfil (Dispositivo)
6. Instalação do perfil (Dispositivo), incluindo os payloads de MDM, SCEP e CA raiz
7. Emissão de comandos MDM (Dispositivo)

![Número de série - Etapas de enrollment e gerenciamento: 7. Emissão de comandos MDM (Dispositivo)](<../../../images/image (694).png>)

O arquivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funções que podem ser consideradas **“etapas” de alto nível** do processo de enrollment.

### Etapa 4: check-in do DEP - Obtendo o Activation Record

Esta parte do processo ocorre quando um **usuário inicializa um Mac pela primeira vez** (ou após uma limpeza completa)

![Etapas de enrollment e gerenciamento - Etapa 4: check-in do DEP - Obtendo o Activation Record: esta parte do processo ocorre quando um usuário inicializa um Mac pela primeira vez (ou após uma...](<../../../images/image (1044).png>)

ou ao executar `sudo profiles show -type enrollment`

- Determina **se o dispositivo está habilitado para DEP**
- Activation Record é o nome interno do **“perfil” DEP**
- Começa assim que o dispositivo é conectado à Internet
- É conduzido por **`CPFetchActivationRecord`**
- Implementado pelo **`cloudconfigurationd`** via XPC. O **"Setup Assistant**" (quando o dispositivo é inicializado pela primeira vez) ou o comando **`profiles`** entrará em contato com esse daemon para recuperar o activation record.
- LaunchDaemon (sempre executado como root)

São executadas algumas etapas para obter o Activation Record por meio do **`MCTeslaConfigurationFetcher`**. Esse processo utiliza uma criptografia chamada **Absinthe**<sup>[[1]](#references)</sup>

1. Recuperar o **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** o estado a partir do certificado (**`NACInit`**)
1. Utiliza vários dados específicos do dispositivo (por exemplo, **Número de série via `IOKit`**)
3. Recuperar a **chave de sessão**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Estabelecer a sessão (**`NACKeyEstablishment`**)
5. Fazer a solicitação
1. POST para [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando os dados `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. O payload JSON é criptografado usando Absinthe (**`NACSign`**)
3. Todas as solicitações usam HTTPs; certificados raiz integrados são utilizados

![Etapas de enrollment e gerenciamento - Etapa 4: check-in do DEP - Obtendo o Activation Record: 3. Todas as solicitações usam HTTPs; certificados raiz integrados são utilizados](<../../../images/image (566) (1).png>)

A resposta é um dicionário JSON com alguns dados importantes, como:

- **url**: URL do host do vendor de MDM para o perfil de ativação
- **anchor-certs**: matriz de certificados DER utilizados como âncoras confiáveis

### **Etapa 5: recuperação do perfil**

![Etapa 4: check-in do DEP - Obtendo o Activation Record - Etapa 5: recuperação do perfil: Etapa 5: recuperação do perfil](<../../../images/image (444).png>)

- Solicitação enviada para a **url fornecida no perfil DEP**.
- Os **certificados âncora** são utilizados para **avaliar a confiança**, se fornecidos.
- Lembrete: a propriedade **anchor_certs** do perfil DEP
- A **solicitação é um .plist simples** com a identificação do dispositivo
- Exemplos: **UDID, versão do sistema operacional**.
- Assinado com CMS e codificado em DER
- Assinado usando o **certificado de identidade do dispositivo (do APNS)**
- A **cadeia de certificados** inclui o **Apple iPhone Device CA** expirado

![Etapa 4: check-in do DEP - Obtendo o Activation Record - Etapa 5: recuperação do perfil: assinado usando o certificado de identidade do dispositivo (do APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Etapa 6: instalação do perfil

- Depois de recuperado, o **perfil é armazenado no sistema**
- Esta etapa começa automaticamente (se estiver no **Setup Assistant**)
- Conduzida por **`CPInstallActivationProfile`**
- Implementada pelo mdmclient via XPC
- LaunchDaemon (como root) ou LaunchAgent (como usuário), dependendo do contexto
- Configuration profiles possuem vários payloads para instalar
- O framework tem uma arquitetura baseada em plugins para instalar perfis
- Cada tipo de payload está associado a um plugin
- Pode ser XPC (no framework) ou Cocoa clássico (no ManagedClient.app)
- Exemplo:
- Payloads de certificados usam CertificateService.xpc

Normalmente, o **activation profile** fornecido por um vendor de MDM **incluirá os seguintes payloads**:

- `com.apple.mdm`: para fazer o **enrollment** do dispositivo no MDM
- `com.apple.security.scep`: para fornecer com segurança um **certificado de cliente** ao dispositivo.
- `com.apple.security.pem`: para **instalar certificados CA confiáveis** no System Keychain do dispositivo.
- A instalação do payload MDM equivale ao **MDM check-in na documentação**
- O payload **contém propriedades importantes**:
- - URL de check-in do MDM (**`CheckInURL`**)
- URL de polling de comandos MDM (**`ServerURL`**) + tópico APNs para acioná-la
- Para instalar o payload MDM, uma solicitação é enviada para **`CheckInURL`**
- Implementado no **`mdmclient`**
- O payload MDM pode depender de outros payloads
- Permite que as **solicitações sejam pinned a certificados específicos**:
- Propriedade: **`CheckInURLPinningCertificateUUIDs`**
- Propriedade: **`ServerURLPinningCertificateUUIDs`**
- Entregue por meio de um payload PEM
- Permite atribuir ao dispositivo um certificado de identidade:
- Propriedade: IdentityCertificateUUID
- Entregue por meio de um payload SCEP

### **Etapa 7: escutando comandos MDM**

- Depois que o check-in do MDM é concluído, o vendor pode **emitir notificações push usando APNs**
- Ao recebê-las, elas são processadas pelo **`mdmclient`**
- Para fazer polling dos comandos MDM, uma solicitação é enviada para ServerURL
- Utiliza o payload MDM instalado anteriormente:
- **`ServerURLPinningCertificateUUIDs`** para fazer pinning da solicitação
- **`IdentityCertificateUUID`** para o certificado de cliente TLS

## Ataques

### Fazendo enrollment de dispositivos em outras organizações

Conforme comentado anteriormente, para tentar fazer o enrollment de um dispositivo em uma organização, **é necessário apenas um Número de série pertencente a essa Organização**. Depois que o dispositivo é enrolled, várias organizações instalam dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, isso pode ser um ponto de entrada perigoso para atacantes se o processo de enrollment não estiver protegido corretamente:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referências

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
