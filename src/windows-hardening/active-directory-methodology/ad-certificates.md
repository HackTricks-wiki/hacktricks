# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- O container **Certification Authorities** mantém certificados root de CA confiáveis.
- O container **Enrolment Services** descreve Enterprise CAs e seus modelos de certificado.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação no AD.
- O container **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e cross CA.

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:

- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.
- **ExtendedRights**, allowing all extended permissions.
- **FullControl/GenericAll**, providing complete control over the template.

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.

### Additional Issuance Controls

Certain controls may apply, such as:

- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.

### Methods to Request Certificates

Certificates can be requested through:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Esta solicitação passa por várias validações pelo controlador de domínio, incluindo a **validade**, **cadeia (path)** e **estado de revogação** do certificado. As validações também incluem verificar que o certificado provém de uma fonte confiável e confirmar a presença do emissor no **armazenamento de certificados NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
É central para estabelecer confiança na autenticação por certificados.

### Autenticação de Secure Channel (Schannel)

Schannel facilita conexões seguras TLS/SSL, onde durante um handshake o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. A vinculação de um certificado a uma conta do AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

### Enumeração dos Serviços de Certificados do AD

Os serviços de certificado do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre **Autoridades Certificadoras Empresariais (CAs)** e suas configurações. Isso é acessível a qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

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

## Vulnerabilidades recentes & Atualizações de Segurança (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

A Microsoft introduziu um rollout em três fases (Compatibility → Audit → Enforcement) para mover a autenticação de certificados Kerberos longe de mapeamentos implícitos fracos. A partir de **11 de fevereiro de 2025**, domain controllers mudam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Administradores devem:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detecção & Melhorias de Hardening

* **Defender for Identity AD CS sensor (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real como *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Garanta que os sensores estejam implantados em todos os servidores AD CS para se beneficiar dessas detecções.
* Desative ou restrinja estritamente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU explicitamente definidos.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que seja absolutamente necessário (aborda cenários ESC2).
* Exija **manager approval** ou workflows dedicados de Enrollment Agent para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restrinja o web enrollment (`certsrv`) e endpoints CES/NDES a redes confiáveis ou coloque-os atrás de autenticação por certificado de cliente.
* Aplique criptografia no RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (RPC relay). A flag está **on by default**, mas frequentemente é desabilitada para clientes legados, o que reabre o risco de relay.
* Proteja **IIS-based enrollment endpoints** (CES/Certsrv): desative NTLM quando possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
