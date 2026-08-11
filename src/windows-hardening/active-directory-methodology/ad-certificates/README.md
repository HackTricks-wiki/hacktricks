# Certificados AD

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Subject** do certificado denota seu proprietário.
- Uma **Public Key** é emparelhada com uma chave mantida em privado para vincular o certificado ao seu proprietário legítimo.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, indica a duração de validade do certificado.
- Um **Serial Number** exclusivo, fornecido pela Certificate Authority (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o subject, aumentando a flexibilidade de identificação.
- **Basic Constraints** identifica se o certificado é para uma CA ou uma entidade final e define restrições de uso.
- **Extended Key Usages (EKUs)** delineia as finalidades específicas do certificado, como assinatura de código ou criptografia de e-mail, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método usado para assinar o certificado.
- A **Signature**, criada com a chave privada do issuer, garante a autenticidade do certificado.<sup>[[1]](#references)</sup>

### Considerações Especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificado para múltiplas identidades, algo essencial para servidores com vários domínios. Processos seguros de emissão são fundamentais para evitar riscos de impersonation por attackers que manipulem a especificação do SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma forest do AD por meio de containers designados, cada um desempenhando funções específicas:<sup>[[1]](#references)</sup>

- O container **Certification Authorities** contém certificados de root CA confiáveis.
- O container **Enrolment Services** detalha as Enterprise CAs e seus certificate templates.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação no AD.
- O container **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e de cross CA.

### Aquisição de Certificados: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clients encontrando uma Enterprise CA.
2. Um CSR é criado, contendo uma public key e outros detalhes, após a geração de um par de chaves pública-privada.
3. A CA avalia o CSR com base nos certificate templates disponíveis e emite o certificado de acordo com as permissões do template.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o devolve ao client.<sup>[[1]](#references)</sup>

### Certificate Templates

Definidos no AD, esses templates descrevem as configurações e permissões para a emissão de certificados, incluindo os EKUs permitidos e os direitos de enrollment ou modificação, essenciais para gerenciar o acesso aos serviços de certificados.<sup>[[1]](#references)</sup>

## Enrollment de Certificados

O processo de enrollment de certificados é iniciado por um administrator que **cria um certificate template**, que então é **publicado** por uma Enterprise Certificate Authority (CA). Isso torna o template disponível para o enrollment do client, uma etapa realizada adicionando o nome do template ao campo `certificatetemplates` de um objeto do Active Directory.<sup>[[1]](#references)</sup>

Para que um client solicite um certificado, **enrollment rights** devem ser concedidos. Esses direitos são definidos por security descriptors no certificate template e na própria Enterprise CA. As permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.<sup>[[1]](#references)</sup>

### Direitos de Enrollment do Template

Esses direitos são especificados por meio de Access Control Entries (ACEs), detalhando permissões como:<sup>[[1]](#references)</sup>

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle completo sobre o template.

### Direitos de Enrollment da Enterprise CA

Os direitos da CA são descritos em seu security descriptor, acessível pelo console de gerenciamento da Certificate Authority. Algumas configurações permitem que users com poucos privilégios tenham acesso remoto, o que pode representar um problema de segurança.<sup>[[1]](#references)</sup>

### Controles Adicionais de Emissão

Determinados controles podem ser aplicados, como:<sup>[[1]](#references)</sup>

- **Manager Approval**: coloca as solicitações em estado pendente até que sejam aprovadas por um certificate manager.
- **Enrolment Agents and Authorized Signatures**: especificam o número de assinaturas necessárias em um CSR e os Application Policy OIDs necessários.

### Métodos para Solicitar Certificados

Os certificados podem ser solicitados por meio de:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), por meio de named pipes ou TCP/IP.
3. A **certificate enrollment web interface**, com a role Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Users do Windows também podem solicitar certificados pela GUI (`certmgr.msc` ou `certlm.msc`) ou por ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

O Active Directory (AD) oferece suporte à autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Essa solicitação passa por várias validações realizadas pelo controlador de domínio, incluindo a **validade**, a **cadeia** e o status de **revogação** do certificado. As validações também incluem verificar se o certificado provém de uma fonte confiável e confirmar a presença do emissor no **repositório de certificados NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é fundamental para estabelecer confiança na autenticação por certificado.<sup>[[1]](#references)</sup>

### Autenticação Secure Channel (Schannel)

Schannel facilita conexões TLS/SSL seguras nas quais, durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso.<sup>[[2]](#references)</sup> O mapeamento de um certificado para uma conta do AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.<sup>[[1]](#references)</sup>

### Enumeração dos Serviços de Certificados do AD

Os serviços de certificados do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre as **Enterprise Certificate Authorities (CAs)** e suas configurações. Isso é acessível a qualquer usuário autenticado no domínio sem privilégios especiais.<sup>[[1]](#references)</sup> Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.<sup>[[3]](#references)</sup>

Os comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
O Rubeus também pode usar um certificado PFX protegido por senha para autenticação PKINIT e solicitar um TGT. A opção `/getcredentials` opcional solicita um service ticket U2U e tenta recuperar o NT hash da conta:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Abusando dos Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [O que é autenticação de cliente SSL/TLS e como ela funciona?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
