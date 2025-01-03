# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Sujeito** do certificado denota seu proprietário.
- Uma **Chave Pública** é emparelhada com uma chave privada para vincular o certificado ao seu legítimo proprietário.
- O **Período de Validade**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificado.
- Um **Número de Série** único, fornecido pela Autoridade Certificadora (CA), identifica cada certificado.
- O **Emissor** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o sujeito, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificado é para uma CA ou uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delineiam os propósitos específicos do certificado, como assinatura de código ou criptografia de e-mail, através de Identificadores de Objetos (OIDs).
- O **Algoritmo de Assinatura** especifica o método para assinar o certificado.
- A **Assinatura**, criada com a chave privada do emissor, garante a autenticidade do certificado.

### Considerações Especiais

- **Subject Alternative Names (SANs)** expandem a aplicabilidade de um certificado para múltiplas identidades, crucial para servidores com múltiplos domínios. Processos de emissão seguros são vitais para evitar riscos de impersonação por atacantes que manipulam a especificação SAN.

### Autoridades Certificadoras (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta AD através de contêineres designados, cada um servindo a papéis únicos:

- O contêiner **Certification Authorities** contém certificados de CA raiz confiáveis.
- O contêiner **Enrolment Services** detalha CAs Empresariais e seus modelos de certificado.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados de CA intermediários e cruzados.

### Aquisição de Certificado: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clientes encontrando uma CA Empresarial.
2. Um CSR é criado, contendo uma chave pública e outros detalhes, após gerar um par de chaves pública-privada.
3. A CA avalia o CSR em relação aos modelos de certificado disponíveis, emitindo o certificado com base nas permissões do modelo.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o retorna ao cliente.

### Modelos de Certificado

Definidos dentro do AD, esses modelos delineiam as configurações e permissões para emissão de certificados, incluindo EKUs permitidos e direitos de inscrição ou modificação, críticos para gerenciar o acesso aos serviços de certificado.

## Inscrição de Certificado

O processo de inscrição para certificados é iniciado por um administrador que **cria um modelo de certificado**, que é então **publicado** por uma Autoridade Certificadora Empresarial (CA). Isso torna o modelo disponível para a inscrição do cliente, um passo alcançado ao adicionar o nome do modelo ao campo `certificatetemplates` de um objeto do Active Directory.

Para que um cliente solicite um certificado, **direitos de inscrição** devem ser concedidos. Esses direitos são definidos por descritores de segurança no modelo de certificado e na própria CA Empresarial. As permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Direitos de Inscrição do Modelo

Esses direitos são especificados através de Entradas de Controle de Acesso (ACEs), detalhando permissões como:

- Direitos de **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle total sobre o modelo.

### Direitos de Inscrição da CA Empresarial

Os direitos da CA são delineados em seu descritor de segurança, acessível através do console de gerenciamento da Autoridade Certificadora. Algumas configurações até permitem que usuários com privilégios baixos tenham acesso remoto, o que pode ser uma preocupação de segurança.

### Controles Adicionais de Emissão

Certos controles podem se aplicar, como:

- **Aprovação do Gerente**: Coloca solicitações em um estado pendente até serem aprovadas por um gerente de certificado.
- **Agentes de Inscrição e Assinaturas Autorizadas**: Especificam o número de assinaturas necessárias em um CSR e os OIDs de Política de Aplicação necessários.

### Métodos para Solicitar Certificados

Os certificados podem ser solicitados através de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), através de pipes nomeados ou TCP/IP.
3. A **interface web de inscrição de certificados**, com o papel de Inscrição Web da Autoridade Certificadora instalado.
4. O **Serviço de Inscrição de Certificado** (CES), em conjunto com o serviço de Política de Inscrição de Certificado (CEP).
5. O **Serviço de Inscrição de Dispositivos de Rede** (NDES) para dispositivos de rede, usando o Protocolo Simples de Inscrição de Certificado (SCEP).

Usuários do Windows também podem solicitar certificados via GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, o pedido de um usuário para um Ticket Granting Ticket (TGT) é assinado usando a **chave privada** do certificado do usuário. Este pedido passa por várias validações pelo controlador de domínio, incluindo a **validade**, **caminho** e **status de revogação** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **NTAUTH certificate store**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança para autenticação de certificados.

### Autenticação de Canal Seguro (Schannel)

Schannel facilita conexões seguras TLS/SSL, onde durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

### Enumeração de Serviços de Certificado AD

Os serviços de certificado do AD podem ser enumerados através de consultas LDAP, revelando informações sobre **Autoridades de Certificação (CAs) Empresariais** e suas configurações. Isso é acessível por qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Os comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referências

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../../banners/hacktricks-training.md}}
