# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para saber mais sobre MDMs no macOS, consulte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Noções básicas

### **Visão geral do MDM (Mobile Device Management)**

O [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) é utilizado para gerenciar vários dispositivos de usuários finais, como smartphones, laptops e tablets. Nas plataformas da Apple (iOS, macOS, tvOS), em particular, ele envolve um conjunto de recursos, APIs e práticas especializadas. O funcionamento do MDM depende de um servidor MDM compatível, disponível comercialmente ou de código aberto, que deve oferecer suporte ao [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Os principais pontos são:

- Controle centralizado dos dispositivos.
- Dependência de um servidor MDM que siga o protocolo MDM.
- Capacidade do servidor MDM de enviar vários comandos aos dispositivos, como apagar dados remotamente ou instalar configurações.

### **Noções básicas do DEP (Device Enrollment Program)**

O [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) oferecido pela Apple simplifica a integração do Mobile Device Management (MDM), permitindo a configuração sem intervenção manual de dispositivos iOS, macOS e tvOS. O DEP automatiza o processo de inscrição, permitindo que os dispositivos estejam operacionais assim que saem da caixa, com mínima intervenção do usuário ou do administrador. Os principais aspectos são:

- Permite que os dispositivos se registrem automaticamente em um servidor MDM predefinido durante a ativação inicial.
- É principalmente útil para dispositivos novos, mas também pode ser usado em dispositivos que estão sendo reconfigurados.
- Simplifica a configuração, deixando os dispositivos prontos rapidamente para uso na organização.

### **Consideração de segurança**

É importante observar que a facilidade de inscrição oferecida pelo DEP, embora vantajosa, também pode representar riscos à segurança. Se as medidas de proteção para a inscrição no MDM não forem aplicadas adequadamente, atacantes poderão explorar esse processo simplificado para registrar seus dispositivos no servidor MDM da organização, fazendo-os passar por dispositivos corporativos.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerta de segurança**: a inscrição simplificada pelo DEP pode permitir que dispositivos não autorizados sejam registrados no servidor MDM da organização caso não existam as proteções adequadas.

### Noções básicas: o que é SCEP (Simple Certificate Enrolment Protocol)?

- Um protocolo relativamente antigo, criado antes da ampla adoção de TLS e HTTPS.
- Oferece aos clientes uma maneira padronizada de enviar uma **solicitação de assinatura de certificado** (CSR) para obter um certificado. O cliente solicita ao servidor um certificado assinado.

### O que são Configuration Profiles (também chamados de mobileconfigs)?

- A maneira oficial da Apple de **definir/aplicar configurações do sistema**.
- Formato de arquivo que pode conter vários payloads.
- Baseados em property lists (do tipo XML).
- “podem ser assinados e criptografados para validar sua origem, garantir sua integridade e proteger seu conteúdo”. Noções básicas — Página 70, iOS Security Guide, janeiro de 2018.

## Protocolos

### MDM

- Combinação de APNs (servidores da **Apple**) + API RESTful (servidores dos **fornecedores** de **MDM**)
- A **comunicação** ocorre entre um **dispositivo** e um servidor associado a um **produto** de **gerenciamento** de **dispositivos**
- **Comandos** enviados do MDM ao dispositivo em **dicionários codificados em plist**
- Tudo por **HTTPS**. Os servidores MDM podem usar pinning (e geralmente usam).
- A Apple concede ao fornecedor de MDM um **certificado APNs** para autenticação

### DEP

- **3 APIs**: 1 para revendedores, 1 para fornecedores de MDM, 1 para identidade do dispositivo (não documentada):
  - A chamada API de [“serviço em nuvem” do DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Os servidores MDM a utilizam para associar perfis DEP a dispositivos específicos.
  - A [API DEP usada pelos Revendedores Autorizados Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscrever dispositivos, verificar o status de inscrição e verificar o status das transações.
  - A API DEP privada não documentada. Ela é usada pelos dispositivos Apple para solicitar seu perfil DEP. No macOS, o binário `cloudconfigurationd` é responsável por se comunicar por meio dessa API.
- Mais moderno e baseado em **JSON** (em vez de plist)
- A Apple concede um **token OAuth** ao fornecedor de MDM

**API de “serviço em nuvem” do DEP**

- RESTful
- Sincroniza os registros de dispositivos da Apple para o servidor MDM
- Sincroniza “perfis DEP” do servidor MDM para a Apple (que depois os envia ao dispositivo)
- Um “perfil” DEP contém:
  - URL do servidor do fornecedor de MDM
  - Certificados confiáveis adicionais para a URL do servidor (pinning opcional)
  - Configurações extras (por exemplo, quais telas ignorar no Setup Assistant)

## Número de série

Os dispositivos Apple fabricados após 2010 geralmente têm números de série **alfanuméricos de 12 caracteres**. Os **três primeiros dígitos representam o local de fabricação**, os **dois seguintes** indicam o **ano** e a **semana** de fabricação, os **três próximos** fornecem um **identificador** **único**, e os **últimos** **quatro dígitos** representam o **número do modelo**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapas de inscrição e gerenciamento

1. Criação do registro do dispositivo (Revendedor, Apple): o registro do novo dispositivo é criado
2. Atribuição do registro do dispositivo (Cliente): o dispositivo é atribuído a um servidor MDM
3. Sincronização do registro do dispositivo (fornecedor de MDM): o MDM sincroniza os registros do dispositivo e envia os perfis DEP à Apple
4. Check-in do DEP (Dispositivo): o dispositivo obtém seu perfil DEP
5. Recuperação do perfil (Dispositivo)
6. Instalação do perfil (Dispositivo) a. inclui payloads MDM, SCEP e CA raiz
7. Emissão de comandos MDM (Dispositivo)

![Número de série - Etapas de inscrição e gerenciamento: 7. Emissão de comandos MDM (Dispositivo)](<../../../images/image (694).png>)

O arquivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funções que podem ser consideradas **“etapas” de alto nível** do processo de inscrição.

### Etapa 4: check-in do DEP — obtenção do Activation Record

Esta parte do processo ocorre quando um **usuário inicia um Mac pela primeira vez** (ou após uma limpeza completa)

![Etapas de inscrição e gerenciamento - Etapa 4: check-in do DEP - obtenção do Activation Record: esta parte do processo ocorre quando um usuário inicia um Mac pela primeira vez (ou após uma...](<../../../images/image (1044).png>)

ou ao executar `sudo profiles show -type enrollment`

- Determina **se o dispositivo está habilitado para DEP**
- Activation Record é o nome interno do **“perfil” DEP**
- Começa assim que o dispositivo se conecta à Internet
- Acionado por **`CPFetchActivationRecord`**
- Implementado por **`cloudconfigurationd`** via XPC. O **"Setup Assistant**" (quando o dispositivo é iniciado pela primeira vez) ou o comando **`profiles`** contata esse daemon para recuperar o Activation Record.
  - LaunchDaemon (sempre executado como root)

O processo executa algumas etapas para obter o Activation Record, realizadas por **`MCTeslaConfigurationFetcher`**. Esse processo usa uma criptografia chamada **Absinthe**<sup>[[1]](#references)</sup>

1. Recuperar **certificado**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** o estado a partir do certificado (**`NACInit`**)
   1. Usa vários dados específicos do dispositivo (isto é, **número de série via `IOKit`**)
3. Recuperar **chave de sessão**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Estabelecer a sessão (**`NACKeyEstablishment`**)
5. Fazer a solicitação
   1. POST para [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), enviando os dados `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. O payload JSON é criptografado usando Absinthe (**`NACSign`**)
   3. Todas as solicitações são feitas por HTTPS, usando certificados raiz integrados

![Etapas de inscrição e gerenciamento - Etapa 4: check-in do DEP - obtenção do Activation Record: 3. Todas as solicitações são feitas por HTTPS, usando certificados raiz integrados](<../../../images/image (566) (1).png>)

A resposta é um dicionário JSON com alguns dados importantes, como:

- **url**: URL do host do fornecedor de MDM para o perfil de ativação
- **anchor-certs**: matriz de certificados DER usados como âncoras de confiança

### **Etapa 5: recuperação do perfil**

![Etapa 4: check-in do DEP - obtenção do Activation Record - Etapa 5: recuperação do perfil: Etapa 5: recuperação do perfil](<../../../images/image (444).png>)

- A solicitação é enviada para a **url fornecida no perfil DEP**.
- Os **certificados âncora** são usados para **avaliar a confiança**, se fornecidos.
  - Lembrete: a propriedade **anchor_certs** do perfil DEP
- A **solicitação é um .plist simples** com a identificação do dispositivo
  - Exemplos: **UDID, versão do sistema operacional**.
- Assinada por CMS e codificada em DER
- Assinada usando o **certificado de identidade do dispositivo (do APNS)**
- A **cadeia de certificados** inclui o certificado expirado **Apple iPhone Device CA**

![Etapa 4: check-in do DEP - obtenção do Activation Record - Etapa 5: recuperação do perfil: assinada usando o certificado de identidade do dispositivo (do APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Etapa 6: instalação do perfil

- Depois de recuperado, o **perfil é armazenado no sistema**
- Esta etapa começa automaticamente (se estiver no **setup assistant**)
- Acionada por **`CPInstallActivationProfile`**
- Implementada por mdmclient via XPC
  - LaunchDaemon (como root) ou LaunchAgent (como usuário), dependendo do contexto
- Os Configuration Profiles têm vários payloads para instalar
- O framework tem uma arquitetura baseada em plugins para instalar perfis
- Cada tipo de payload está associado a um plugin
  - Pode ser XPC (no framework) ou Cocoa clássico (em ManagedClient.app)
- Exemplo:
  - Payloads de certificado usam CertificateService.xpc

Normalmente, o **perfil de ativação** fornecido por um fornecedor de MDM **inclui os seguintes payloads**:

- `com.apple.mdm`: para **inscrever** o dispositivo no MDM
- `com.apple.security.scep`: para fornecer com segurança um **certificado de cliente** ao dispositivo.
- `com.apple.security.pem`: para **instalar certificados de CA confiáveis** no System Keychain do dispositivo.
- Instalar o payload MDM equivale ao **check-in do MDM na documentação**
- O payload **contém propriedades importantes**:
- - URL de check-in do MDM (**`CheckInURL`**)
  - URL de consulta de comandos do MDM (**`ServerURL`**) + tópico APNs para acioná-la
- Para instalar o payload MDM, uma solicitação é enviada para **`CheckInURL`**
- Implementado em **`mdmclient`**
- O payload MDM pode depender de outros payloads
- Permite **fixar solicitações a certificados específicos**:
  - Propriedade: **`CheckInURLPinningCertificateUUIDs`**
  - Propriedade: **`ServerURLPinningCertificateUUIDs`**
  - Fornecidas pelo payload PEM
- Permite atribuir uma identidade ao dispositivo por meio de um certificado:
  - Propriedade: IdentityCertificateUUID
  - Fornecido pelo payload SCEP

### **Etapa 7: escuta de comandos MDM**

- Depois que o check-in do MDM é concluído, o fornecedor pode **emitir notificações push usando APNs**
- Ao recebê-las, elas são processadas por **`mdmclient`**
- Para consultar comandos MDM, uma solicitação é enviada para ServerURL
- Usa um payload MDM instalado anteriormente:
  - **`ServerURLPinningCertificateUUIDs`** para fixar a solicitação
  - **`IdentityCertificateUUID`** para o certificado de cliente TLS

## Ataques

### Inscrição de dispositivos em outras organizações

Um número de série atribuído pode identificar o caminho de inscrição da organização, mas **não** garante a inscrição no MDM. O servidor pode exigir autenticação do usuário por meio de `configuration_web_url` antes de retornar o perfil de inscrição. Avalie se um caminho de inscrição alternativo omite essa verificação, em vez de presumir que todo número de série atribuído pode ser adicionado à frota.<sup>[[3]](#references)</sup>

Para um fluxo de inscrição fraudulenta, use a página vinculada abaixo. Para controle do MDM e entrega de pacotes após o comprometimento, consulte [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Uma análise aprofundada do macOS MDM (e como ele pode ser comprometido)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (pesquisa de segurança sobre inscrição DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Autenticação por meio de visualizações da web](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
