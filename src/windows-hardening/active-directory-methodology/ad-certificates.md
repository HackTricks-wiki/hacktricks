# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificate

- O **Subject** do certificate denota seu owner.
- Uma **Public Key** é pareada com uma key mantida em privado para vincular o certificate ao seu rightful owner.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificate.
- Um **Serial Number** único, fornecido pela Certificate Authority (CA), identifica cada certificate.
- O **Issuer** se refere à CA que emitiu o certificate.
- **SubjectAlternativeName** permite nomes adicionais para o subject, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificate é para uma CA ou uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delimitam os propósitos específicos do certificate, como code signing ou email encryption, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método de assinatura do certificate.
- A **Signature**, criada com a private key do issuer, garante a autenticidade do certificate.

### Considerações Especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificate para múltiplas identities, o que é crucial para servers com múltiplos domains. Processos de emissão seguros são vitais para evitar riscos de impersonation por attackers manipulando a especificação do SAN.

### Certificate Authorities (CAs) no Active Directory (AD)

AD CS reconhece certificates de CA em uma floresta AD por meio de containers designados, cada um com funções específicas:

- O container **Certification Authorities** mantém trusted root CA certificates.
- O container **Enrolment Services** detalha Enterprise CAs e seus certificate templates.
- O objeto **NTAuthCertificates** inclui CA certificates autorizados para AD authentication.
- O container **AIA (Authority Information Access)** facilita a validação da certificate chain com intermediate e cross CA certificates.

### Aquisição de Certificate: Fluxo de Request de Client Certificate

1. O processo de request começa com clients encontrando uma Enterprise CA.
2. Um CSR é criado, contendo uma public key e outros detalhes, após gerar um par de keys pública e privada.
3. A CA avalia o CSR em relação aos certificate templates disponíveis, emitindo o certificate com base nas permissões do template.
4. Após a aprovação, a CA assina o certificate com sua private key e o retorna ao client.

### Certificate Templates

Definidos dentro do AD, esses templates descrevem as settings e permissions para emissão de certificates, incluindo EKUs permitidos e direitos de enrollment ou modification, algo crítico para gerenciar o acesso aos serviços de certificate.

**A versão do schema do template importa.** Templates legados **v1** (por exemplo, o template **WebServer** nativo) não têm várias opções modernas de enforcement. A pesquisa **ESC15/EKUwu** mostrou que, em **templates v1**, um requester pode embutir **Application Policies/EKUs** no CSR que são **preferidos em relação aos** EKUs configurados no template, permitindo certificados de client-auth, enrollment agent ou code-signing com apenas direitos de enrollment. Prefira **templates v2/v3**, remova ou substitua padrões v1 e restrinja fortemente os EKUs ao propósito pretendido.

## Certificate Enrollment

O processo de enrollment para certificates é iniciado por um administrator que **cria um certificate template**, que então é **publicado** por uma Enterprise Certificate Authority (CA). Isso torna o template disponível para client enrollment, uma etapa alcançada ao adicionar o nome do template ao campo `certificatetemplates` de um Active Directory object.

Para que um client solicite um certificate, **enrollment rights** devem ser concedidos. Esses rights são definidos por security descriptors no certificate template e na própria Enterprise CA. As permissions precisam ser concedidas em ambos os locais para que a request seja bem-sucedida.

### Template Enrollment Rights

Esses rights são especificados por meio de Access Control Entries (ACEs), detalhando permissions como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as extended permissions.
- **FullControl/GenericAll**, fornecendo controle total sobre o template.

### Enterprise CA Enrollment Rights

Os rights da CA são descritos em seu security descriptor, acessível via o console de gerenciamento da Certificate Authority. Algumas settings até permitem acesso remoto para users com poucos privilégios, o que pode ser uma preocupação de segurança.

### Controles Adicionais de Issuance

Certos controles podem ser aplicados, como:

- **Manager Approval**: Coloca requests em estado pendente até serem aprovadas por um certificate manager.
- **Enrolment Agents and Authorized Signatures**: Especifica o número de signatures exigidas em um CSR e os Application Policy OIDs necessários.

### Methods to Request Certificates

Certificates podem ser solicitados por meio de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), por meio de named pipes ou TCP/IP.
3. A **certificate enrollment web interface**, com a função Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para network devices, usando o Simple Certificate Enrollment Protocol (SCEP).

Windows users também podem solicitar certificates via GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de command-line (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário para um Ticket Granting Ticket (TGT) é assinada usando a **private key** do certificado do usuário. Essa solicitação passa por várias validações pelo domain controller, incluindo a **validity**, **path** e **revocation status** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **NTAUTH certificate store**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** em AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança na autenticação por certificado.

Desde o rollout do **KB5014754**, a autenticação Kerberos moderna por certificado gira principalmente em torno de **mapping strength**, e não apenas de EKUs. Em forests hardened:

- Um certificado que contenha apenas um **UPN/DNS SAN** pode não ser mais suficiente para logon.
- O KDC prefere um **strong binding**, normalmente a **SID security extension** (`1.3.6.1.4.1.311.25.2`) ou um strong explicit mapping em `altSecurityIdentities`.
- Se o cert não tiver um strong mapping, os DCs registram **Kdcsvc Event ID 39/41** em compatibility mode e negam auth em enforcement mode.
- Em mixed attack paths, **ESC9/ESC16** importam porque removem a SID extension dos certs emitidos; os operadores então dependem de explicit mappings ou de formatos SAN URL SID onde o attack path os suportar.

### Secure Channel (Schannel) Authentication

Schannel facilita conexões TLS/SSL seguras, em que, durante um handshake, o client apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função Kerberos **S4U2Self** ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

Schannel também é o fallback prático quando **PKINIT** não está disponível. Por exemplo, se um domain controller não tiver um certificado adequado de **Smart Card Logon**, o tooling `certipy auth`/PKINIT pode falhar ao obter um TGT, mas o mesmo certificado ainda pode ser usado contra **LDAPS** ou **LDAP StartTLS** para autenticação e operações LDAP.

### AD Certificate Services Enumeration

Os certificate services do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Isso está acessível a qualquer usuário autenticado no domain, sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

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

## Vulnerabilidades Recentes & Atualizações de Segurança (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalada de privilégios* ao falsificar certificados de conta de máquina durante PKINIT. | O patch está incluído nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria e strong-mapping foram introduzidos via **KB5014754**; os ambientes agora devem estar em modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* nas funções AD CS Web Enrollment (certsrv) e CES. | PoCs públicas são limitadas, mas os componentes IIS vulneráveis frequentemente estão expostos internamente. Patch a partir do Patch Tuesday de **julho de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Em *templates v1*, um solicitante com direitos de enrollment pode incorporar **Application Policies/EKUs** no CSR que têm prioridade sobre os EKUs do template, produzindo certificados de client-auth, enrollment agent ou code-signing. | Corrigido em **12 de novembro de 2024**. Substitua ou aposente templates v1 (por exemplo, o WebServer padrão), restrinja os EKUs ao propósito pretendido e limite os direitos de enrollment. |

### Cronograma de hardening da Microsoft (KB5014754)

A Microsoft introduziu uma implementação em três fases (Compatibility → Audit → Enforcement) para mover a autenticação Kerberos por certificado para longe de mapeamentos implícitos fracos. Em **11 de fevereiro de 2025**, os controladores de domínio mudam automaticamente para **Full Enforcement** se o valor de registry `StrongCertificateBindingEnforcement` não estiver definido. A Microsoft depois atualizou o cronograma para que o fallback para o modo de compatibilidade continue possível até a atualização de segurança de **9 de setembro de 2025**. Os administradores devem:

1. Patch em todos os DCs e servidores AD CS (maio de 2022 ou posterior).
2. Monitorar o Event ID 39/41 para mapeamentos fracos durante a fase *Audit*.
3. Reemitir certificados de client-auth com a nova **SID extension** ou configurar strong manual mappings antes que a enforcement bloqueie mapeamentos fracos.

### Notas do operador para florestas hardened

- **ESC1/ESC6 sozinho já não é toda a história** em ambientes de 2025+. Se você solicitar um cert para outro principal, normalmente também precisará de um strong mapping artifact, como a SID extension ou um mapeamento explícito.
- **ESC15 (EKUwu)** é mais valioso em ambientes não patchados porque transforma templates **v1** inofensivos, como **WebServer**, em certs capazes de autenticação ou de enrollment agent ao injetar **Application Policies**. O Kerberos PKINIT ainda avalia EKUs, mas **LDAP Schannel** também respeita Application Policies, o que mantém relevante o abuso baseado em LDAP.
- **ESC16** é um knob em nível de CA: se a CA desabilita globalmente a SID security extension, todo certificado emitido volta a um comportamento de mapeamento mais fraco, a menos que a cadeia de ataque injete um SID em outro formato suportado.

---

## Melhorias de Detecção & Hardening

* **Defender for Identity AD CS sensor (2023-2024)** agora expõe avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real como *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Garanta que os sensores estejam implantados em todos os servidores AD CS para aproveitar essas detecções.
* Desabilite ou restrinja fortemente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU definidos explicitamente.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que seja absolutamente आवश्यकário (cobre cenários ESC2).
* Exija **manager approval** ou workflows dedicados de Enrollment Agent para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restrinja os endpoints de web enrollment (`certsrv`) e CES/NDES a redes confiáveis ou atrás de autenticação por client-certificate.
* Aplique criptografia no enrollment via RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). A flag vem **ativada por padrão**, mas muitas vezes é desabilitada para clientes legados, o que reabre o risco de relay.
* Proteja os **endpoints de enrollment baseados em IIS** (CES/Certsrv): desabilite NTLM sempre que possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
