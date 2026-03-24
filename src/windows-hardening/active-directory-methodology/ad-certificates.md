# AD Certificados

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Subject** do certificado denota seu proprietário.
- Uma **Public Key** é emparelhada com uma chave privada para vincular o certificado ao seu legítimo proprietário.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificado.
- Um único **Serial Number**, fornecido pela Autoridade Certificadora (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o subject, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificado é para uma CA ou uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delineiam os propósitos específicos do certificado, como assinatura de código ou criptografia de email, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método para assinar o certificado.
- A **Signature**, criada com a chave privada do issuer, garante a autenticidade do certificado.

### Considerações Especiais

- **Subject Alternative Names (SANs)** expandem a aplicabilidade de um certificado para múltiplas identidades, crucial para servidores com múltiplos domínios. Processos de emissão seguros são vitais para evitar riscos de falsificação de identidade por atacantes que manipulam a especificação SAN.

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados CA em uma floresta AD através de contêineres designados, cada um servindo papéis únicos:

- O contêiner **Certification Authorities** armazena certificados root CA confiáveis.
- O contêiner **Enrolment Services** detalha Enterprise CAs e seus certificate templates.
- O objeto **NTAuthCertificates** inclui certificados CA autorizados para autenticação AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermédiários e cross CA.

### Aquisição de Certificado: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clientes localizando uma Enterprise CA.
2. Um CSR é criado, contendo uma public key e outros detalhes, após gerar um par de chaves pública-privada.
3. A CA avalia o CSR em relação aos certificate templates disponíveis, emitindo o certificado com base nas permissões do template.
4. Após aprovação, a CA assina o certificado com sua chave privada e o devolve ao cliente.

### Certificate Templates

Definidos dentro do AD, esses templates descrevem as configurações e permissões para emitir certificados, incluindo EKUs permitidos e direitos de enrollment ou modificação, críticos para gerenciar o acesso aos serviços de certificado.

**Template schema version matters.** Templates legados **v1** (por exemplo, o built-in **WebServer** template) não possuem vários mecanismos de enforcement modernos. A pesquisa **ESC15/EKUwu** mostrou que em **v1 templates**, um requester pode embutir **Application Policies/EKUs** no CSR que são **preferred over** os EKUs configurados pelo template, permitindo certificados client-auth, enrollment agent, ou code-signing apenas com direitos de enrollment. Prefira **v2/v3 templates**, remova ou substitua os padrões v1, e restrinja rigidamente os EKUs ao propósito pretendido.

## Inscrição de Certificado

O processo de inscrição para certificados é iniciado por um administrador que **cria um certificate template**, o qual é então **publicado** por uma Enterprise Certificate Authority (CA). Isso torna o template disponível para enrollment do cliente, passo realizado adicionando o nome do template ao campo `certificatetemplates` de um objeto Active Directory.

Para um cliente solicitar um certificado, **enrollment rights** devem ser concedidos. Esses direitos são definidos por security descriptors no certificate template e na própria Enterprise CA. Permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Direitos de Enrollment do Template

Esses direitos são especificados através de Access Control Entries (ACEs), detalhando permissões como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, proporcionando controle completo sobre o template.

### Direitos de Enrollment da Enterprise CA

Os direitos da CA estão delineados em seu security descriptor, acessível via o console de gerenciamento da Certificate Authority. Algumas configurações até permitem que usuários com baixos privilégios tenham acesso remoto, o que pode ser uma preocupação de segurança.

### Controles Adicionais de Emissão

Certos controles podem ser aplicados, tais como:

- **Manager Approval**: Coloca solicitações em estado pendente até serem aprovadas por um certificate manager.
- **Enrolment Agents and Authorized Signatures**: Especificam o número de assinaturas necessárias em um CSR e os Application Policy OIDs necessários.

### Métodos para Solicitar Certificados

Certificados podem ser solicitados através de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), através de named pipes ou TCP/IP.
3. A **certificate enrollment web interface**, com o role Certificate Authority Web Enrollment instalado.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Usuários Windows também podem solicitar certificados via GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Essa solicitação passa por várias validações pelo controlador de domínio, incluindo a **validade**, a **cadeia (path)** e o **status de revogação** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **NTAUTH certificate store**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança na autenticação baseada em certificados.

### Secure Channel (Schannel) Authentication

Schannel facilita conexões seguras TLS/SSL, onde durante um handshake o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta do AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

### AD Certificate Services Enumeration

Os serviços de certificados do AD podem ser enumerados através de consultas LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Isto é acessível por qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilidades Recentes & Atualizações de Segurança (2022-2025)

| Ano | ID / Nome | Impacto | Principais conclusões |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalação de privilégio* por falsificação de certificados de contas de máquina durante o PKINIT. | Patch está incluído nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria & strong-mapping foram introduzidos via **KB5014754**; os ambientes agora devem estar em modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* em AD CS Web Enrollment (certsrv) e funções CES. | PoCs públicas são limitadas, mas os componentes IIS vulneráveis frequentemente ficam expostos internamente. Patch disponível desde o **Patch Tuesday de julho de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Em **v1 templates**, um solicitante com direitos de enrollment pode embutir **Application Policies/EKUs** no CSR que têm prioridade sobre os EKUs do template, produzindo certificados client-auth, enrollment agent ou code-signing. | Corrigido em **12 de novembro de 2024**. Substitua ou supersede templates v1 (ex.: default WebServer), restrinja EKUs ao propósito e limite direitos de enrollment. |

### Microsoft hardening timeline (KB5014754)

A Microsoft introduziu um rollout em três fases (Compatibility → Audit → Enforcement) para afastar a autenticação de certificados Kerberos de mapeamentos implícitos fracos. A partir de **11 de fevereiro de 2025**, domain controllers alternam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Administradores devem:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detecção & melhorias de hardening

* **Defender for Identity AD CS sensor (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real como *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Garanta que os sensores estejam implantados em todos os servidores AD CS para aproveitar essas detecções.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que absolutamente necessário (resolve cenários ESC2).
* Exija aprovação de gerente ou fluxos de trabalho dedicados de **Enrollment Agent** para templates sensíveis (ex.: WebServer / CodeSigning).
* Restrinja web enrollment (`certsrv`) e endpoints CES/NDES a redes confiáveis ou coloque-os atrás de autenticação por certificado de cliente.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). O flag está **on by default**, mas frequentemente é desabilitado para clientes legados, o que reabre o risco de relay.
* Proteja **IIS-based enrollment endpoints** (CES/Certsrv): desative NTLM onde possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

---



## Referências

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
