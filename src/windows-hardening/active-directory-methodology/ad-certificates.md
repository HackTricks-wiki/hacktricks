# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um certificado

- O **Subject** do certificado indica seu proprietário.
- Uma **Public Key** é pareada com uma chave mantida em privado para vincular o certificado ao seu legítimo proprietário.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, indica o período de validade do certificado.
- Um **Serial Number** exclusivo, fornecido pela Certificate Authority (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite adicionar nomes para o subject, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificado é de uma CA ou de uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** especificam as finalidades do certificado, como assinatura de código ou criptografia de e-mail, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método usado para assinar o certificado.
- A **Signature**, criada com a chave privada do emissor, garante a autenticidade do certificado.<sup>[[4]](#references)</sup>

### Considerações especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificado para várias identidades, algo essencial para servidores com vários domínios. Processos seguros de emissão são fundamentais para evitar riscos de impersonation por atacantes que manipulem a especificação do SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta AD por meio de contêineres designados, cada um com uma função específica:<sup>[[4]](#references)</sup>

- O contêiner **Certification Authorities** contém certificados de CA raiz confiáveis.
- O contêiner **Enrolment Services** contém informações sobre CAs Enterprise e seus certificate templates.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e de CAs cruzadas.

### Obtenção de certificados: fluxo de solicitação de certificado pelo cliente

1. O processo de solicitação começa quando os clientes localizam uma CA Enterprise.
2. Após a geração de um par de chaves pública e privada, é criado um CSR contendo uma chave pública e outros detalhes.
3. A CA avalia o CSR em relação aos certificate templates disponíveis e emite o certificado com base nas permissões do template.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o devolve ao cliente.<sup>[[4]](#references)</sup>

### Certificate Templates

Definidos no AD, esses templates especificam as configurações e permissões para emitir certificados, incluindo EKUs permitidos e direitos de enrollment ou modificação, essenciais para gerenciar o acesso aos serviços de certificados.<sup>[[4]](#references)</sup>

**A versão do schema do template é importante.** Os templates legados **v1** (por exemplo, o template integrado **WebServer**) não têm vários controles modernos de enforcement. A pesquisa **ESC15/EKUwu** mostrou que, em **templates v1**, um solicitante pode incluir **Application Policies/EKUs** no CSR, que têm **prioridade sobre** os EKUs configurados no template. Isso permite obter certificados de client-auth, enrollment agent ou code-signing com apenas direitos de enrollment. Prefira templates **v2/v3**, remova ou substitua os padrões v1 e limite rigorosamente os EKUs à finalidade pretendida.<sup>[[1]](#references)</sup>

## Enrollment de certificados

O processo de enrollment de certificados é iniciado por um administrador que **cria um certificate template**, que então é **publicado** por uma Enterprise Certificate Authority (CA). Isso disponibiliza o template para enrollment pelos clientes, o que é feito adicionando o nome do template ao campo `certificatetemplates` de um objeto do Active Directory.<sup>[[4]](#references)</sup>

Para que um cliente solicite um certificado, é necessário conceder **direitos de enrollment**. Esses direitos são definidos por descritores de segurança no certificate template e na própria Enterprise CA. As permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Direitos de enrollment do template

Esses direitos são especificados por meio de Access Control Entries (ACEs), que detalham permissões como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, que permitem todas as permissões estendidas.
- **FullControl/GenericAll**, que concede controle total sobre o template.

### Direitos de enrollment da Enterprise CA

Os direitos da CA são definidos em seu descritor de segurança, acessível pelo console de gerenciamento da Certificate Authority. Algumas configurações permitem até mesmo acesso remoto a usuários com poucos privilégios, o que pode representar um risco de segurança.

### Controles adicionais de emissão

Podem ser aplicados certos controles, como:

- **Manager Approval**: mantém as solicitações pendentes até que um certificate manager as aprove.
- **Enrolment Agents and Authorized Signatures**: especificam o número de assinaturas necessárias em um CSR e os OIDs de Application Policy exigidos.

### Métodos para solicitar certificados

Os certificados podem ser solicitados por meio de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), por meio de named pipes ou TCP/IP.
3. A **interface web de enrollment de certificados**, com a função Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Os usuários do Windows também podem solicitar certificados pela GUI (`certmgr.msc` ou `certlm.msc`) ou por ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticação por Certificado

O Active Directory (AD) oferece suporte à autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Essa solicitação passa por várias validações pelo controlador de domínio, incluindo a **validade**, o **caminho** e o **status de revogação** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **repositório de certificados NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD pode ser encontrado em:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

é fundamental para estabelecer confiança na autenticação por certificado.<sup>[[4]](#references)</sup>

Desde a implementação do **KB5014754**, a autenticação moderna Kerberos por certificado trata principalmente da **força do mapeamento**, não apenas dos EKUs.<sup>[[2]](#references)</sup> Em florestas com segurança reforçada:

- Um certificado que contém apenas um **UPN/DNS SAN** pode já não ser suficiente para o logon.
- O KDC prefere um **vínculo forte**, normalmente a **extensão de segurança SID** (`1.3.6.1.4.1.311.25.2`) ou um mapeamento explícito forte em `altSecurityIdentities`.
- Se o certificado não tiver um mapeamento forte, os DCs registram o **Kdcsvc Event ID 39/41** no modo de compatibilidade e negam a autenticação no modo de imposição.
- Em caminhos de ataque combinados, **ESC9/ESC16** são relevantes porque removem a extensão SID dos certificados emitidos; os operadores então recorrem a mapeamentos explícitos ou a formatos de SID em URLs SAN, quando o caminho de ataque oferece suporte.

### Autenticação Secure Channel (Schannel)

O Schannel facilita conexões TLS/SSL seguras. Durante o handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.<sup>[[4]](#references)</sup>

O Schannel também é a alternativa prática quando o **PKINIT** não está disponível. Por exemplo, se um controlador de domínio não tiver um certificado **Smart Card Logon** adequado, as ferramentas `certipy auth`/PKINIT podem não conseguir obter um TGT, mas o mesmo certificado ainda pode ser usado contra **LDAPS** ou **LDAP StartTLS** para autenticação e operações LDAP.

### Enumeração dos serviços de certificados do AD

Os serviços de certificados do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Qualquer usuário autenticado no domínio pode acessar essas informações sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalonamento de privilégios* por falsificação de certificados de contas de máquina durante o PKINIT. | O patch está incluído nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria e de mapeamento forte foram introduzidos por meio da **KB5014754**; os ambientes agora devem estar no modo *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* nas funções AD CS Web Enrollment (certsrv) e CES. | Os PoCs públicos são limitados, mas os componentes IIS vulneráveis costumam estar expostos internamente. Aplique o patch disponibilizado na atualização Patch Tuesday de **julho de 2023**. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Em **templates v1**, um solicitante com direitos de inscrição pode incluir **Application Policies/EKUs** no CSR, que têm preferência sobre os EKUs do template, gerando certificados de autenticação de cliente, agente de inscrição ou assinatura de código. | Corrigido em **12 de novembro de 2024**. Substitua ou torne obsoletos os templates v1 (por exemplo, o WebServer padrão), restrinja os EKUs à finalidade pretendida e limite os direitos de inscrição. |

### Cronograma de hardening da Microsoft (KB5014754)

A Microsoft introduziu uma implementação em três fases (Compatibilidade → Auditoria → Imposição) para afastar a autenticação de certificados Kerberos de mapeamentos implícitos fracos. Desde **11 de fevereiro de 2025**, os controladores de domínio mudam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Posteriormente, a Microsoft atualizou o cronograma para permitir o retorno ao modo de compatibilidade até a atualização de segurança de **9 de setembro de 2025**.<sup>[[2]](#references)</sup> Os administradores devem:

1. Aplicar patches a todos os DCs e servidores AD CS (maio de 2022 ou posterior).
2. Monitorar os Event IDs 39/41 para detectar mapeamentos fracos durante a fase de *Auditoria*.
3. Emitir novamente certificados de autenticação de cliente com a nova **extensão SID** ou configurar mapeamentos manuais fortes antes que a imposição bloqueie os mapeamentos fracos.

### Observações para operadores de florestas com hardening

- **ESC1/ESC6, por si só, já não contam toda a história** em ambientes de 2025 em diante. Se você solicitar um certificado para outra entidade, geralmente também precisará de um artefato de mapeamento forte, como a extensão SID ou um mapeamento explícito.
- **ESC15 (EKUwu)** é mais valioso em ambientes sem patches, pois transforma templates **v1** aparentemente inofensivos, como **WebServer**, em certificados capazes de autenticação ou de atuar como agente de inscrição, por meio da injeção de **Application Policies**. O Kerberos PKINIT ainda avalia os EKUs, mas o **LDAP Schannel** também respeita as Application Policies, mantendo relevante o abuso baseado em LDAP.<sup>[[1]](#references)</sup>
- **ESC16** é uma configuração global da CA: se a CA desativar globalmente a extensão de segurança SID, todos os certificados emitidos tenderão a recorrer a um comportamento de mapeamento mais fraco, a menos que a cadeia de ataque injete um SID em outro formato compatível.
- **Os direitos ESC7 são distintos:** uma concessão `ManageCA` na CA pode permitir alterações em configurações como `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), enquanto `ManageCertificates` controla a aprovação de solicitações. Uma regra explícita de negação dos direitos de gerenciador de certificados pode bloquear essa via de aprovação, mesmo que também exista uma regra de permissão; avalie a ACL efetiva da CA antes de encadear configurações e templates. Consulte [a avaliação da ACL da CA da Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Melhorias de detecção e hardening

* O **sensor AD CS do Defender for Identity (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real, como *“Emissão de certificado de controlador de domínio para um dispositivo que não é DC”* (ESC8) e *“Impedir a inscrição de certificados com Application Policies arbitrárias”* (ESC15). Implante sensores em todos os servidores AD CS para aproveitar essas detecções.<sup>[[3]](#references)</sup>
* Desative ou limite rigorosamente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU definidos explicitamente.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que sejam absolutamente necessários (mitiga cenários ESC2).
* Exija **aprovação do gerente** ou fluxos de trabalho dedicados de Enrollment Agent para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restrinja os endpoints de web enrollment (`certsrv`) e CES/NDES a redes confiáveis ou proteja-os com autenticação por certificado de cliente.
* Exija criptografia para a inscrição RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (relay RPC). O sinalizador fica **ativado por padrão**, mas costuma ser desativado para clientes legados, reabrindo o risco de relay.
* Proteja os endpoints de inscrição baseados em **IIS** (CES/Certsrv): desative NTLM quando possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

Avalie ESC11 no host que executa a CA, que pode ser um servidor membro do domínio, e não um controlador de domínio. Leia `InterfaceFlags` da CA ativa em `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; um valor ilegível ou ausente indica um resultado desconhecido, não prova que a criptografia RPC está desativada. Um bit `IF_ENFORCEENCRYPTICERTREQUEST` desativado é uma pista de configuração que ainda exige um endpoint de RPC de inscrição acessível, credenciais que possam ser coagidas e um template de certificado utilizável. Para ESC8, um desafio NTLM por HTTP, por si só, não é suficiente: confirme a existência de um endpoint de inscrição funcional.

---

## References

- [1] [EKUwu: Não é apenas mais um ESC do AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Alterações na autenticação baseada em certificados nos controladores de domínio do Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Avaliações da postura de segurança de certificados - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certificado de origem: abusando dos Serviços de Certificados do Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
