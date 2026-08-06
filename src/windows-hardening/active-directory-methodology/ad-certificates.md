# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Subject** do certificado indica seu proprietário.
- Uma **Public Key** é associada a uma chave mantida em sigilo para vincular o certificado ao seu legítimo proprietário.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, determina a duração de validade do certificado.
- Um **Serial Number** exclusivo, fornecido pela Certificate Authority (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o subject, aumentando a flexibilidade da identificação.
- **Basic Constraints** identificam se o certificado é destinado a uma CA ou a uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delimitam as finalidades específicas do certificado, como assinatura de código ou criptografia de e-mail, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método usado para assinar o certificado.
- A **Signature**, criada com a chave privada do issuer, garante a autenticidade do certificado.<sup>[[4]](#references)</sup>

### Considerações Especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificado a várias identidades, algo essencial para servidores com múltiplos domínios. Processos seguros de emissão são fundamentais para evitar riscos de impersonation por attackers que manipulam a especificação do SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta AD por meio de containers designados, cada um desempenhando funções específicas:<sup>[[4]](#references)</sup>

- O container **Certification Authorities** contém certificados de CA raiz confiáveis.
- O container **Enrolment Services** detalha as Enterprise CAs e seus certificate templates.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação no AD.
- O container **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e de CAs cross.

### Aquisição de Certificados: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clientes localizando uma Enterprise CA.
2. Um CSR é criado, contendo uma chave pública e outros detalhes, após a geração de um par de chaves público-privada.
3. A CA avalia o CSR em relação aos certificate templates disponíveis e emite o certificado com base nas permissões do template.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o devolve ao cliente.<sup>[[4]](#references)</sup>

### Certificate Templates

Definidos no AD, esses templates especificam as configurações e permissões para a emissão de certificados, incluindo EKUs permitidos e direitos de enrollment ou modificação, sendo essenciais para gerenciar o acesso aos serviços de certificados.<sup>[[4]](#references)</sup>

**A versão do schema do template é importante.** Os templates **v1** legados (por exemplo, o template **WebServer** integrado) não possuem vários mecanismos modernos de enforcement. A pesquisa sobre **ESC15/EKUwu** mostrou que, em **v1 templates**, um solicitante pode inserir **Application Policies/EKUs** no CSR, que têm **preferência sobre** os EKUs configurados no template, permitindo certificados de client-auth, enrollment agent ou code-signing com apenas direitos de enrollment. Prefira templates **v2/v3**, remova ou substitua os padrões v1 e restrinja rigorosamente os EKUs à finalidade pretendida.<sup>[[1]](#references)</sup>

## Certificate Enrollment

O processo de enrollment de certificados é iniciado por um administrador que **cria um certificate template**, que então é **publicado** por uma Enterprise Certificate Authority (CA). Isso disponibiliza o template para enrollment dos clientes, uma etapa realizada adicionando o nome do template ao campo `certificatetemplates` de um objeto do Active Directory.<sup>[[4]](#references)</sup>

Para que um cliente solicite um certificado, é necessário conceder **enrollment rights**. Esses direitos são definidos por security descriptors no certificate template e na própria Enterprise CA. As permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Template Enrollment Rights

Esses direitos são especificados por meio de Access Control Entries (ACEs), detalhando permissões como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle completo sobre o template.

### Enterprise CA Enrollment Rights

Os direitos da CA são definidos em seu security descriptor, acessível pelo console de gerenciamento da Certificate Authority. Algumas configurações permitem até mesmo acesso remoto a usuários com poucos privilégios, o que pode representar um risco de segurança.

### Additional Issuance Controls

Determinados controles podem ser aplicados, como:

- **Manager Approval**: coloca as solicitações em estado pendente até serem aprovadas por um certificate manager.
- **Enrolment Agents and Authorized Signatures**: especificam o número de assinaturas necessárias em um CSR e os Application Policy OIDs exigidos.

### Methods to Request Certificates

Os certificados podem ser solicitados por meio de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), por meio de named pipes ou TCP/IP.
3. A **certificate enrollment web interface**, com a role Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Usuários do Windows também podem solicitar certificados pela GUI (`certmgr.msc` ou `certlm.msc`) ou por ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

O Active Directory (AD) oferece suporte à autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Essa solicitação passa por várias validações realizadas pelo controlador de domínio, incluindo a **validade**, a **cadeia de certificação** e o **status de revogação** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **repositório de certificados NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança na autenticação de certificados.<sup>[[4]](#references)</sup>

Desde o rollout da **KB5014754**, a autenticação moderna de certificados do Kerberos trata principalmente da **força do mapeamento**, e não apenas dos EKUs.<sup>[[2]](#references)</sup> Em forests protegidas:

- Um certificado que contenha apenas um **UPN/DNS SAN** pode não ser mais suficiente para o logon.
- O KDC prefere um **strong binding**, normalmente a **SID security extension** (`1.3.6.1.4.1.311.25.2`) ou um mapeamento explícito forte em `altSecurityIdentities`.
- Se o certificado não tiver um mapeamento forte, os DCs registram o **Kdcsvc Event ID 39/41** no compatibility mode e negam a autenticação no enforcement mode.
- Em attack paths combinados, **ESC9/ESC16** são relevantes porque removem a SID extension dos certificados emitidos; os operadores então dependem de mapeamentos explícitos ou de formatos de SID em SAN URL quando o attack path oferece suporte a eles.

### Autenticação do Secure Channel (Schannel)

O Schannel facilita conexões TLS/SSL seguras. Durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta do AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.<sup>[[4]](#references)</sup>

O Schannel também é o fallback prático quando o **PKINIT** não está disponível. Por exemplo, se um domain controller não tiver um certificado adequado de **Smart Card Logon**, as ferramentas `certipy auth`/PKINIT podem falhar ao obter um TGT, mas o mesmo certificado ainda pode ser utilizável com **LDAPS** ou **LDAP StartTLS** para autenticação e operações LDAP.

### Enumeração dos Serviços de Certificados do AD

Os serviços de certificados do AD podem ser enumerados por meio de queries LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Isso é acessível a qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Os comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilidades recentes e atualizações de segurança (2022-2025)

| Ano | ID / Nome | Impacto | Principais conclusões |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalonamento de privilégios* por meio da falsificação de certificados de contas de máquina durante o PKINIT. | O patch está incluído nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria e strong-mapping foram introduzidos por meio da **KB5014754**; os ambientes agora devem estar no modo *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* nas funções AD CS Web Enrollment (certsrv) e CES. | Os PoCs públicos são limitados, mas os componentes IIS vulneráveis costumam estar expostos internamente. Corrigido a partir do Patch Tuesday de **julho de 2023**. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Em **v1 templates**, um requester com direitos de enrollment pode inserir **Application Policies/EKUs** no CSR, que têm preferência sobre os EKUs do template, produzindo certificados de client-auth, enrollment agent ou code-signing. | Corrigido a partir de **12 de novembro de 2024**. Substitua ou torne obsoletos os v1 templates (por exemplo, o WebServer padrão), restrinja os EKUs à finalidade pretendida e limite os direitos de enrollment. |

### Linha do tempo de hardening da Microsoft (KB5014754)

A Microsoft introduziu uma implementação em três fases (Compatibility → Audit → Enforcement) para afastar a autenticação de certificados Kerberos de mapeamentos implícitos fracos. A partir de **11 de fevereiro de 2025**, os domain controllers alternam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Posteriormente, a Microsoft atualizou a linha do tempo para que o fallback para o modo de compatibilidade continue sendo possível até a atualização de segurança de **9 de setembro de 2025**.<sup>[[2]](#references)</sup> Os administradores devem:

1. Aplicar patches em todos os DCs e servidores AD CS (maio de 2022 ou posterior).
2. Monitorar os Event IDs 39/41 em busca de mapeamentos fracos durante a fase de *Audit*.
3. Reemitir certificados de client-auth com a nova **SID extension** ou configurar mapeamentos manuais fortes antes que o enforcement bloqueie os mapeamentos fracos.

### Observações para operadores de forests protegidas

- **ESC1/ESC6 isoladamente já não contam toda a história** em ambientes 2025+. Se você solicitar um cert para outro principal, normalmente também precisará de um artefato de strong mapping, como a SID extension ou um mapeamento explícito.
- **ESC15 (EKUwu)** é mais valioso em ambientes sem patches, pois transforma v1 templates inofensivos, como **WebServer**, em certs capazes de autenticação ou enrollment agent por meio da injeção de **Application Policies**. O Kerberos PKINIT ainda avalia os EKUs, mas o **LDAP Schannel** também respeita as Application Policies, mantendo relevante o abuso baseado em LDAP.<sup>[[1]](#references)</sup>
- **ESC16** é uma configuração abrangente da CA: se a CA desabilitar globalmente a SID security extension, todo certificado emitido ficará sujeito a um comportamento de mapeamento mais fraco, a menos que a cadeia de ataque injete uma SID por outro formato compatível.

---

## Melhorias de detecção e hardening

* O **Defender for Identity AD CS sensor (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real, como *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Garanta que os sensors estejam implantados em todos os servidores AD CS para aproveitar essas detecções.<sup>[[3]](#references)</sup>
* Desabilite ou restrinja rigorosamente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU definidos explicitamente.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que sejam absolutamente necessários (trata de cenários ESC2).
* Exija **manager approval** ou workflows dedicados de Enrollment Agent para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restrinja o web enrollment (`certsrv`) e os endpoints CES/NDES a redes confiáveis ou proteja-os com autenticação por client certificate.
* Exija criptografia no RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar o ESC11 (RPC relay). A flag vem **ativada por padrão**, mas costuma ser desabilitada para clientes legados, reabrindo o risco de relay.
* Proteja os **endpoints de enrollment baseados em IIS** (CES/Certsrv): desabilite NTLM quando possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

---

## Referências

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
