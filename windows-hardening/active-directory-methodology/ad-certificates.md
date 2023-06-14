# Certificados AD

## Informações Básicas

### Partes de um certificado

* **Subject** - O proprietário do certificado.
* **Chave pública** - Associa o Subject com uma chave privada armazenada separadamente.
* **Datas NotBefore e NotAfter** - Definem a duração em que o certificado é válido.
* **Número de série** - Um identificador para o certificado atribuído pela CA.
* **Emissor** - Identifica quem emitiu o certificado (comumente uma CA).
* **SubjectAlternativeName** - Define um ou mais nomes alternativos que o Subject pode ter. (_Ver abaixo_)
* **Restrições básicas** - Identifica se o certificado é uma CA ou uma entidade final, e se há alguma restrição ao usar o certificado.
* **Usos estendidos de chave (EKUs)** - Identificadores de objeto (OIDs) que descrevem **como o certificado será usado**. Também conhecido como Enhanced Key Usage na terminologia da Microsoft. Os EKUs comuns incluem:
  * Assinatura de código (OID 1.3.6.1.5.5.7.3.3) - O certificado é para assinar código executável.
  * Sistema de arquivos criptografado (OID 1.3.6.1.4.1.311.10.3.4) - O certificado é para criptografar sistemas de arquivos.
  * Email seguro (1.3.6.1.5.5.7.3.4) - O certificado é para criptografar e-mails.
  * Autenticação do cliente (OID 1.3.6.1.5.5.7.3.2) - O certificado é para autenticação em outro servidor (por exemplo, no AD).
  * Logon de cartão inteligente (OID 1.3.6.1.4.1.311.20.2.2) - O certificado é para uso na autenticação de cartão inteligente.
  * Autenticação do servidor (OID 1.3.6.1.5.5.7.3.1) - O certificado é para identificar servidores (por exemplo, certificados HTTPS).
* **Algoritmo de assinatura** - Especifica o algoritmo usado para assinar o certificado.
* **Assinatura** - A assinatura do corpo do certificado feita usando a chave privada do emissor (por exemplo, de uma CA).

#### Subject Alternative Names

Um **Subject Alternative Name** (SAN) é uma extensão X.509v3. Ele permite que **identidades adicionais** sejam vinculadas a um **certificado**. Por exemplo, se um servidor da web hospeda **conteúdo para vários domínios**, **cada** domínio aplicável poderia ser **incluído** no **SAN** para que o servidor da web precise apenas de um único certificado HTTPS.

Por padrão, durante a autenticação baseada em certificado, o AD mapeia os certificados para contas de usuário com base em um UPN especificado no SAN. Se um atacante puder **especificar um SAN arbitrário** ao solicitar um certificado que tenha um **EKU habilitando a autenticação do cliente**, e a CA criar e assinar um certificado usando o SAN fornecido pelo atacante, o **atacante pode se tornar qualquer usuário no domínio**.

### CAs

AD CS define certificados de CA em quatro locais em que a floresta AD confia sob o contêiner `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`, cada um diferindo por seu propósito:

* O contêiner **Certification Authorities** define **certificados de CA raiz confiáveis**. Essas CAs estão no **topo da hierarquia da árvore PKI** e são a base da confiança em ambientes AD CS. Cada CA é representada como um objeto AD dentro do contêiner onde o **objectClass** é definido como **`certificationAuthority`** e a propriedade **`cACertificate`** contém os **bytes do certificado da CA**. O Windows propaga esses certificados de CA para o armazenamento de certificados de Autoridades de Certificação Raiz Confiáveis em **cada máquina Windows**. Para que o AD considere um certificado como **confiável**, a cadeia de confiança do certificado deve eventualmente **terminar com um dos CAs raiz** definidos neste contêiner.
* O contêiner **Enrolment Services** define cada **CA empresarial** (ou seja, CAs criadas no AD CS com a função de CA empresarial habilitada). Cada CA empresarial tem um objeto AD com os seguintes atributos:
  * Um atributo **objectClass** para **`pKIEnrollmentService`**
  * Um atributo **`cACertificate`** contendo os **bytes do certificado da CA**
  * Um atributo **`dNSHostName`** define o **host DNS da CA**
  * Um campo **certificateTemplates** definindo os **modelos de certificado habilitados**. Os modelos de certificado são um "modelo" de configurações que a CA usa ao criar um certificado e incluem coisas como os EKUs, permissões de inscrição, a expiração do certificado, requisitos de emissão e configurações de criptografia. Discutiremos os modelos de certificado com mais detalhes posteriormente.

{% hint style="info" %}
Em ambientes AD, **os clientes interagem com as CAs empresariais para solicitar um certificado** com base nas configurações definidas em um modelo de certificado. Os certificados
### Direitos de Inscrição de Modelos de Certificado

* **O ACE concede a um principal o direito estendido de inscrição de certificado**. O ACE bruto concede ao principal o direito de acesso `RIGHT_DS_CONTROL_ACCESS45` onde o **ObjectType** é definido como `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Este GUID corresponde ao direito estendido de **Inscrição de Certificado**.
* **O ACE concede a um principal o direito estendido de Autoinscrição de Certificado**. O ACE bruto concede ao principal o direito de acesso `RIGHT_DS_CONTROL_ACCESS48` onde o **ObjectType** é definido como `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Este GUID corresponde ao direito estendido de **Autoinscrição de Certificado**.
* **Um ACE concede a um principal todos os Direitos Estendidos**. O ACE bruto habilita o direito de acesso `RIGHT_DS_CONTROL_ACCESS` onde o **ObjectType** é definido como `00000000-0000-0000-0000-000000000000`. Este GUID corresponde a **todos os direitos estendidos**.
* **Um ACE concede a um principal Controle Total/GenericAll**. O ACE bruto habilita o direito de acesso Controle Total/GenericAll.

### Direitos de Inscrição de CA Empresarial

O **descritor de segurança** configurado no **CA Empresarial** define esses direitos e é **visível** no snap-in MMC do Certificado de Autoridade `certsrv.msc` clicando com o botão direito do mouse no CA → Propriedades → Segurança.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Isso acaba definindo o valor do registro de segurança na chave **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<NOME DO CA>`** no servidor CA. Encontramos vários servidores AD CS que concedem a usuários com baixo privilégio acesso remoto a essa chave via registro remoto:

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Usuários com baixo privilégio também podem **enumerar isso via DCOM** usando o método `GetCASecurity` da interface COM `ICertAdminD2`. No entanto, os clientes normais do Windows precisam instalar as Ferramentas de Administração do Servidor Remoto (RSAT) para usá-lo, já que a interface COM e quaisquer objetos COM que a implementem não estão presentes no Windows por padrão.

### Requisitos de Emissão

Outros requisitos podem estar em vigor para controlar quem pode obter um certificado.

#### Aprovação do Gerente

A aprovação do **gerente do certificado CA** resulta na definição do modelo de certificado do bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) no atributo `msPKI-EnrollmentFlag` do objeto AD. Isso coloca todas as **solicitações de certificado** com base no modelo no estado **pendente** (visível na seção "Solicitações Pendentes" em `certsrv.msc`), o que requer que um gerente de certificado **aprovar ou negar** a solicitação antes que o certificado seja emitido:

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Agentes de Inscrição, Assinaturas Autorizadas e Políticas de Aplicação

**Este número de assinaturas autorizadas** e a **política de aplicação**. O primeiro controla o **número de assinaturas necessárias** no CSR para o CA aceitá-lo. O último define os **OIDs EKU que o certificado de assinatura do CSR deve ter**.

Um uso comum para essas configurações é para **agentes de inscrição**. Um agente de inscrição é um termo AD CS dado a uma entidade que pode **solicitar certificados em nome de outro usuário**. Para fazer isso, o CA deve emitir para a conta do agente de inscrição um certificado contendo pelo menos o **EKU do Agente de Solicitação de Certificado** (OID 1.3.6.1.4.1.311.20.2.1). Depois de emitido, o agente de inscrição pode então **assinar CSRs e solicitar certificados em nome de outros usuários**. O CA emitirá o certificado do agente de inscrição como **outro usuário** somente sob o seguinte conjunto não abrangente de **condições** (implementado principalmente no módulo de política padrão `certpdef.dll`):

* O usuário do Windows que se autentica no CA tem direitos de inscrição no modelo de certificado de destino.
* Se a versão do esquema do modelo de certificado for 1, o CA exigirá que os certificados de assinatura tenham o OID do Agente de Solicitação de Certificado antes de emitir o certificado. A versão do esquema do modelo é especificada na propriedade msPKI-Template-Schema-Version do objeto AD do modelo.
* Se a versão do esquema do modelo de certificado for 2:
  * O modelo deve definir a configuração "Este número de assinaturas autorizadas" e o número especificado de agentes de inscrição deve assinar o CSR (o atributo mspkira-signature do modelo define essa configuração). Em outras palavras, essa configuração especifica quantos agentes de inscrição devem assinar um CSR antes que o CA considere emitir um certificado.
  * A restrição de emissão da "Política de Aplicação" do modelo deve ser definida como
## Enumeração do AD CS

Assim como para a maioria do AD, todas as informações abordadas até agora estão disponíveis consultando o LDAP como um usuário autenticado no domínio, mas sem privilégios.

Se quisermos **enumerar os CAs empresariais** e suas configurações, podemos consultar o LDAP usando o filtro LDAP `(objectCategory=pKIEnrollmentService)` na base de pesquisa `CN=Configuration,DC=<domínio>,DC=<com>` (esta base de pesquisa corresponde ao contexto de nomeação de Configuração da floresta AD). Os resultados identificarão o nome do host DNS do servidor CA, o próprio nome do CA, as datas de início e término do certificado, várias flags, modelos de certificado publicados e muito mais.

**Ferramentas para enumerar certificados vulneráveis:**

* [**Certify**](https://github.com/GhostPack/Certify) é uma ferramenta em C# que pode **enumerar informações úteis de configuração e infraestrutura sobre ambientes AD CS** e pode solicitar certificados de várias maneiras diferentes.
* [**Certipy**](https://github.com/ly4k/Certipy) é uma ferramenta em **python** para poder **enumerar e abusar** dos Serviços de Certificado do Active Directory (**AD CS**) **de qualquer sistema** (com acesso ao DC) que pode gerar saída para o BloodHound criado por [**Lyak**](https://twitter.com/ly4k\_) (boa pessoa, melhor hacker).
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## Referências

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
