# Certificados AD

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Subject** do certificado indica seu proprietário.
- Uma **Public Key** é pareada com uma chave privada para vincular o certificado ao seu legítimo proprietário.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificado.
- Um **Serial Number** único, fornecido pela Certificate Authority (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o subject, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificado é para uma CA ou uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delimitam os propósitos específicos do certificado, como assinatura de código ou criptografia de e-mail, através de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método para assinar o certificado.
- A **Signature**, criada com a chave privada do issuer, garante a autenticidade do certificado.

### Considerações Especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificado para múltiplas identidades, sendo cruciais para servidores com domínios múltiplos. Processos seguros de emissão são vitais para evitar riscos de impersonação por atacantes que manipulem a especificação SAN.

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta do AD através de containers designados, cada um servindo papéis únicos:

- O container **Certification Authorities** contém certificados de CA raiz confiáveis.
- O container **Enrolment Services** detalha as Enterprise CAs e seus certificate templates.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação no AD.
- O container **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e cross CA.

### Aquisição de Certificado: Fluxo de Requisição de Certificado pelo Cliente

1. O processo de requisição começa com os clientes encontrando uma Enterprise CA.
2. Um CSR é criado, contendo uma public key e outros detalhes, após a geração de um par de chaves pública-privada.
3. A CA avalia o CSR contra os certificate templates disponíveis, emitindo o certificado com base nas permissões do template.
4. Após aprovação, a CA assina o certificado com sua chave privada e o retorna ao cliente.

### Certificate Templates

Definidos dentro do AD, esses templates descrevem as configurações e permissões para emissão de certificados, incluindo EKUs permitidos e direitos de enrolment ou modificação, sendo críticos para gerenciar o acesso aos serviços de certificado.

## Inscrição de Certificado

O processo de inscrição para certificados é iniciado por um administrador que **cria um certificate template**, o qual é então **publicado** por uma Enterprise Certificate Authority (CA). Isso torna o template disponível para inscrição dos clientes, um passo realizado adicionando o nome do template ao campo `certificatetemplates` de um objeto do Active Directory.

Para que um cliente solicite um certificado, devem ser concedidos **enrollment rights**. Esses direitos são definidos por descritores de segurança no certificate template e na própria Enterprise CA. Permissões devem ser concedidas em ambos os locais para que uma requisição seja bem-sucedida.

### Template Enrollment Rights

Esses direitos são especificados através de Access Control Entries (ACEs), detalhando permissões como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle completo sobre o template.

### Enterprise CA Enrollment Rights

Os direitos da CA são descritos em seu descritor de segurança, acessível via o console de gerenciamento do Certificate Authority. Algumas configurações permitem até mesmo que usuários com poucos privilégios tenham acesso remoto, o que pode ser uma preocupação de segurança.

### Controles Adicionais de Emissão

Certos controles podem ser aplicados, como:

- **Manager Approval**: Coloca requisições em estado pendente até serem aprovadas por um gerente de certificados.
- **Enrolment Agents and Authorized Signatures**: Especificam o número de assinaturas necessárias em um CSR e os Application Policy OIDs exigidos.

### Métodos para Solicitar Certificados

Certificados podem ser solicitados através de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), através de named pipes ou TCP/IP.
3. A **certificate enrollment web interface**, com a função Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Usuários Windows também podem solicitar certificados via GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de linha de comando (`certreq.exe` ou o comando PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **private key** do certificado do usuário. Essa solicitação passa por várias validações pelo domain controller, incluindo o **validity**, **path**, e **revocation status** do certificado. As validações também incluem verificar que o certificado provém de uma fonte confiável e confirmar a presença do emissor no **NTAUTH certificate store**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança na autenticação por certificado.

### Secure Channel (Schannel) Authentication

Schannel facilita conexões TLS/SSL seguras, onde durante o handshake o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função do Kerberos **S4U2Self** ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

### AD Certificate Services Enumeration

Os serviços de certificados do AD podem ser enumerados por consultas LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Isso é acessível a qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Comandos para usar essas ferramentas incluem:
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
## Referências

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
