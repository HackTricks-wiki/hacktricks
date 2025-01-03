# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para aprender sobre MDMs do macOS, consulte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Básicos

### **Visão Geral do MDM (Gerenciamento de Dispositivos Móveis)**

[Gerenciamento de Dispositivos Móveis](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) é utilizado para supervisionar vários dispositivos de usuários finais, como smartphones, laptops e tablets. Particularmente para as plataformas da Apple (iOS, macOS, tvOS), envolve um conjunto de recursos, APIs e práticas especializadas. O funcionamento do MDM depende de um servidor MDM compatível, que pode ser comercial ou de código aberto, e deve suportar o [Protocolo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Os pontos principais incluem:

- Controle centralizado sobre os dispositivos.
- Dependência de um servidor MDM que adere ao protocolo MDM.
- Capacidade do servidor MDM de enviar vários comandos para os dispositivos, por exemplo, apagamento remoto de dados ou instalação de configurações.

### **Noções Básicas do DEP (Programa de Inscrição de Dispositivos)**

O [Programa de Inscrição de Dispositivos](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) oferecido pela Apple simplifica a integração do Gerenciamento de Dispositivos Móveis (MDM) ao facilitar a configuração sem toque para dispositivos iOS, macOS e tvOS. O DEP automatiza o processo de inscrição, permitindo que os dispositivos estejam operacionais assim que retirados da caixa, com mínima intervenção do usuário ou do administrador. Aspectos essenciais incluem:

- Permite que os dispositivos se registrem autonomamente em um servidor MDM pré-definido na ativação inicial.
- Principalmente benéfico para dispositivos novos, mas também aplicável a dispositivos que estão sendo reconfigurados.
- Facilita uma configuração simples, tornando os dispositivos prontos para uso organizacional rapidamente.

### **Consideração de Segurança**

É crucial notar que a facilidade de inscrição proporcionada pelo DEP, embora benéfica, também pode representar riscos de segurança. Se as medidas de proteção não forem adequadamente aplicadas para a inscrição no MDM, os atacantes podem explorar esse processo simplificado para registrar seu dispositivo no servidor MDM da organização, disfarçando-se como um dispositivo corporativo.

> [!CAUTION]
> **Alerta de Segurança**: A inscrição simplificada no DEP pode potencialmente permitir o registro não autorizado de dispositivos no servidor MDM da organização se as salvaguardas adequadas não estiverem em vigor.

### Noções Básicas — O que é SCEP (Protocolo de Inscrição Simples de Certificado)?

- Um protocolo relativamente antigo, criado antes que TLS e HTTPS se tornassem amplamente utilizados.
- Oferece aos clientes uma maneira padronizada de enviar um **Pedido de Assinatura de Certificado** (CSR) com o propósito de obter um certificado. O cliente solicitará ao servidor que lhe forneça um certificado assinado.

### O que são Perfis de Configuração (também conhecidos como mobileconfigs)?

- A maneira oficial da Apple de **definir/impor a configuração do sistema.**
- Formato de arquivo que pode conter múltiplos payloads.
- Baseado em listas de propriedades (o tipo XML).
- “pode ser assinado e criptografado para validar sua origem, garantir sua integridade e proteger seu conteúdo.” Noções Básicas — Página 70, Guia de Segurança do iOS, Janeiro de 2018.

## Protocolos

### MDM

- Combinação de APNs (**servidores da Apple**) + API RESTful (**servidores de fornecedores de MDM**)
- **Comunicação** ocorre entre um **dispositivo** e um servidor associado a um **produto de gerenciamento de dispositivos**
- **Comandos** entregues do MDM para o dispositivo em **dicionários codificados em plist**
- Através de **HTTPS**. Servidores MDM podem ser (e geralmente são) fixados.
- A Apple concede ao fornecedor de MDM um **certificado APNs** para autenticação

### DEP

- **3 APIs**: 1 para revendedores, 1 para fornecedores de MDM, 1 para identidade do dispositivo (não documentada):
- A chamada [API "serviço em nuvem" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Esta é usada pelos servidores MDM para associar perfis DEP a dispositivos específicos.
- A [API DEP usada por Revendedores Autorizados da Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscrever dispositivos, verificar status de inscrição e verificar status de transação.
- A API privada DEP não documentada. Esta é usada pelos Dispositivos Apple para solicitar seu perfil DEP. No macOS, o binário `cloudconfigurationd` é responsável pela comunicação através dessa API.
- Mais moderna e baseada em **JSON** (vs. plist)
- A Apple concede um **token OAuth** ao fornecedor de MDM

**API "serviço em nuvem" DEP**

- RESTful
- sincroniza registros de dispositivos da Apple para o servidor MDM
- sincroniza “perfis DEP” da Apple para o servidor MDM (entregues pela Apple ao dispositivo posteriormente)
- Um “perfil” DEP contém:
- URL do servidor do fornecedor de MDM
- Certificados confiáveis adicionais para a URL do servidor (fixação opcional)
- Configurações extras (por exemplo, quais telas pular na Assistente de Configuração)

## Número de Série

Dispositivos Apple fabricados após 2010 geralmente têm números de série **alfanuméricos de 12 caracteres**, com os **três primeiros dígitos representando o local de fabricação**, os **dois** seguintes indicando o **ano** e a **semana** de fabricação, os próximos **três** dígitos fornecendo um **identificador único**, e os **últimos** **quatro** dígitos representando o **número do modelo**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapas para inscrição e gerenciamento

1. Criação do registro do dispositivo (Revendedor, Apple): O registro para o novo dispositivo é criado
2. Atribuição do registro do dispositivo (Cliente): O dispositivo é atribuído a um servidor MDM
3. Sincronização do registro do dispositivo (Fornecedor de MDM): O MDM sincroniza os registros dos dispositivos e envia os perfis DEP para a Apple
4. Check-in DEP (Dispositivo): O dispositivo recebe seu perfil DEP
5. Recuperação do perfil (Dispositivo)
6. Instalação do perfil (Dispositivo) a. incl. payloads de MDM, SCEP e CA raiz
7. Emissão de comando MDM (Dispositivo)

![](<../../../images/image (694).png>)

O arquivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funções que podem ser consideradas **"etapas" de alto nível** do processo de inscrição.

### Etapa 4: Check-in DEP - Obtendo o Registro de Ativação

Esta parte do processo ocorre quando um **usuário inicializa um Mac pela primeira vez** (ou após uma limpeza completa)

![](<../../../images/image (1044).png>)

ou ao executar `sudo profiles show -type enrollment`

- Determinar **se o dispositivo está habilitado para DEP**
- O Registro de Ativação é o nome interno para o **"perfil" DEP**
- Começa assim que o dispositivo está conectado à Internet
- Impulsionado por **`CPFetchActivationRecord`**
- Implementado por **`cloudconfigurationd`** via XPC. O **"Assistente de Configuração"** (quando o dispositivo é inicializado pela primeira vez) ou o comando **`profiles`** irá **contatar este daemon** para recuperar o registro de ativação.
- LaunchDaemon (sempre executa como root)

Segue algumas etapas para obter o Registro de Ativação realizado por **`MCTeslaConfigurationFetcher`**. Este processo utiliza uma criptografia chamada **Absinthe**

1. Recuperar **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** estado a partir do certificado (**`NACInit`**)
1. Usa vários dados específicos do dispositivo (ou seja, **Número de Série via `IOKit`**)
3. Recuperar **chave de sessão**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Estabelecer a sessão (**`NACKeyEstablishment`**)
5. Fazer a solicitação
1. POST para [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando os dados `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. O payload JSON é criptografado usando Absinthe (**`NACSign`**)
3. Todas as solicitações via HTTPs, certificados raiz embutidos são usados

![](<../../../images/image (566) (1).png>)

A resposta é um dicionário JSON com alguns dados importantes, como:

- **url**: URL do host do fornecedor de MDM para o perfil de ativação
- **anchor-certs**: Array de certificados DER usados como âncoras confiáveis

### **Etapa 5: Recuperação do Perfil**

![](<../../../images/image (444).png>)

- Solicitação enviada para **url fornecida no perfil DEP**.
- **Certificados âncora** são usados para **avaliar a confiança** se fornecidos.
- Lembrete: a propriedade **anchor_certs** do perfil DEP
- **A solicitação é um simples .plist** com identificação do dispositivo
- Exemplos: **UDID, versão do OS**.
- Assinada por CMS, codificada em DER
- Assinada usando o **certificado de identidade do dispositivo (do APNS)**
- **A cadeia de certificados** inclui **Apple iPhone Device CA** expirado

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Etapa 6: Instalação do Perfil

- Uma vez recuperado, **o perfil é armazenado no sistema**
- Esta etapa começa automaticamente (se no **assistente de configuração**)
- Impulsionado por **`CPInstallActivationProfile`**
- Implementado pelo mdmclient via XPC
- LaunchDaemon (como root) ou LaunchAgent (como usuário), dependendo do contexto
- Perfis de configuração têm múltiplos payloads a serem instalados
- O framework tem uma arquitetura baseada em plugins para instalação de perfis
- Cada tipo de payload está associado a um plugin
- Pode ser XPC (no framework) ou Cocoa clássica (no ManagedClient.app)
- Exemplo:
- Payloads de Certificado usam CertificateService.xpc

Normalmente, o **perfil de ativação** fornecido por um fornecedor de MDM incluirá os seguintes payloads:

- `com.apple.mdm`: para **inscrever** o dispositivo no MDM
- `com.apple.security.scep`: para fornecer de forma segura um **certificado de cliente** ao dispositivo.
- `com.apple.security.pem`: para **instalar certificados CA confiáveis** no Keychain do Sistema do dispositivo.
- A instalação do payload de MDM é equivalente ao **check-in de MDM na documentação**
- O payload **contém propriedades-chave**:
- - URL de Check-In do MDM (**`CheckInURL`**)
- URL de Polling de Comando do MDM (**`ServerURL`**) + tópico APNs para acioná-lo
- Para instalar o payload de MDM, uma solicitação é enviada para **`CheckInURL`**
- Implementado em **`mdmclient`**
- O payload de MDM pode depender de outros payloads
- Permite **solicitações serem fixadas a certificados específicos**:
- Propriedade: **`CheckInURLPinningCertificateUUIDs`**
- Propriedade: **`ServerURLPinningCertificateUUIDs`**
- Entregue via payload PEM
- Permite que o dispositivo seja atribuído a um certificado de identidade:
- Propriedade: IdentityCertificateUUID
- Entregue via payload SCEP

### **Etapa 7: Escutando por comandos MDM**

- Após o check-in do MDM ser concluído, o fornecedor pode **emitir notificações push usando APNs**
- Ao receber, é tratado pelo **`mdmclient`**
- Para consultar comandos MDM, uma solicitação é enviada para ServerURL
- Faz uso do payload de MDM previamente instalado:
- **`ServerURLPinningCertificateUUIDs`** para fixação da solicitação
- **`IdentityCertificateUUID`** para o certificado de cliente TLS

## Ataques

### Inscrevendo Dispositivos em Outras Organizações

Como comentado anteriormente, para tentar inscrever um dispositivo em uma organização **apenas um Número de Série pertencente a essa Organização é necessário**. Uma vez que o dispositivo está inscrito, várias organizações instalarão dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, isso pode ser um ponto de entrada perigoso para atacantes se o processo de inscrição não estiver corretamente protegido:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
