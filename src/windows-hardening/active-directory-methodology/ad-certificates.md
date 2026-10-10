# Certificados AD

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um certificado

- O **Subject** do certificado indica seu proprietário.
- Uma **Public Key** é pareada com uma chave mantida em sigilo para vincular o certificado ao seu legítimo proprietário.
- O **Validity Period**, definido pelas datas **NotBefore** e **NotAfter**, indica o período de validade do certificado.
- Um **Serial Number** exclusivo, fornecido pela Certificate Authority (CA), identifica cada certificado.
- O **Issuer** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite adicionar nomes para o subject, aumentando a flexibilidade da identificação.
- **Basic Constraints** identifica se o certificado é de uma CA ou de uma entidade final e define restrições de uso.
- **Extended Key Usages (EKUs)** definem as finalidades específicas do certificado, como assinatura de código ou criptografia de e-mail, por meio de Object Identifiers (OIDs).
- O **Signature Algorithm** especifica o método usado para assinar o certificado.
- A **Signature**, criada com a chave privada do issuer, garante a autenticidade do certificado.<sup>[[4]](#references)</sup>

### Considerações especiais

- **Subject Alternative Names (SANs)** ampliam a aplicabilidade de um certificado para várias identidades, algo essencial para servidores com vários domínios. Processos seguros de emissão são fundamentais para evitar riscos de falsificação de identidade por atacantes que manipulem a especificação do SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta do AD por meio de contêineres designados, cada um com uma função específica:<sup>[[4]](#references)</sup>

- O contêiner **Certification Authorities** armazena certificados de CA raiz confiáveis.
- O contêiner **Enrolment Services** contém informações sobre Enterprise CAs e seus modelos de certificado.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação no AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e de CAs cruzadas.

### Aquisição de certificados: fluxo de solicitação de certificado do cliente

1. O processo de solicitação começa quando os clientes encontram uma Enterprise CA.
2. Um CSR é criado com uma chave pública e outros detalhes, após a geração de um par de chaves pública e privada.
3. A CA avalia o CSR em relação aos modelos de certificado disponíveis e emite o certificado conforme as permissões do modelo.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o devolve ao cliente.<sup>[[4]](#references)</sup>

### Modelos de certificado

Definidos no AD, esses modelos especificam as configurações e permissões para a emissão de certificados, incluindo EKUs permitidos e direitos de inscrição ou modificação, essenciais para gerenciar o acesso aos serviços de certificado.<sup>[[4]](#references)</sup>

**A versão do esquema do modelo é importante.** Os modelos **v1** legados (por exemplo, o modelo **WebServer** integrado) não têm vários controles modernos de aplicação de políticas. A pesquisa sobre **ESC15/EKUwu** mostrou que, em **modelos v1**, quem solicita um certificado pode incorporar **Application Policies/EKUs** no CSR, que têm **precedência sobre** as EKUs configuradas no modelo. Isso permite obter certificados de autenticação de cliente, agente de inscrição ou assinatura de código apenas com direitos de inscrição. Prefira modelos **v2/v3**, remova ou substitua os padrões v1 e restrinja rigorosamente as EKUs à finalidade pretendida.<sup>[[1]](#references)</sup>

## Inscrição de certificados

O processo de inscrição de certificados é iniciado por um administrador que **cria um modelo de certificado**, que então é **publicado** por uma Enterprise Certificate Authority (CA). Isso disponibiliza o modelo para a inscrição de clientes, uma etapa realizada adicionando o nome do modelo ao campo `certificatetemplates` de um objeto do Active Directory.<sup>[[4]](#references)</sup>

Para que um cliente solicite um certificado, é necessário conceder **direitos de inscrição**. Esses direitos são definidos por descritores de segurança no modelo de certificado e na própria Enterprise CA. As permissões precisam ser concedidas em ambos os locais para que a solicitação seja bem-sucedida.

### Direitos de inscrição do modelo

Esses direitos são especificados por meio de Access Control Entries (ACEs), que detalham permissões como:

- Direitos **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, que permitem todas as permissões estendidas.
- **FullControl/GenericAll**, que concedem controle total sobre o modelo.

### Direitos de inscrição da Enterprise CA

Os direitos da CA são definidos em seu descritor de segurança, acessível pelo console de gerenciamento da Certificate Authority. Algumas configurações permitem até mesmo acesso remoto a usuários com poucos privilégios, o que pode representar um problema de segurança.

### Controles adicionais de emissão

Podem ser aplicados determinados controles, como:

- **Aprovação do gerente**: mantém as solicitações pendentes até que um gerente de certificados as aprove.
- **Agentes de inscrição e assinaturas autorizadas**: especificam o número de assinaturas exigidas em um CSR e os OIDs de Application Policy necessários.

### Métodos para solicitar certificados

Os certificados podem ser solicitados por meio de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), por meio de named pipes ou TCP/IP.
3. A **interface Web de inscrição de certificados**, com a função Certificate Authority Web Enrollment instalada.
4. O **Certificate Enrollment Service** (CES), em conjunto com o serviço Certificate Enrollment Policy (CEP).
5. O **Network Device Enrollment Service** (NDES) para dispositivos de rede, usando o Simple Certificate Enrollment Protocol (SCEP).

Os usuários do Windows também podem solicitar certificados pela GUI (`certmgr.msc` ou `certlm.msc`) ou por ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticação por certificado

O Active Directory (AD) oferece suporte à autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um usuário por um Ticket Granting Ticket (TGT) é assinada usando a **chave privada** do certificado do usuário. Essa solicitação passa por várias validações pelo controlador de domínio, incluindo a **validade**, a **cadeia** e o status de revogação do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **repositório de certificados NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

é fundamental para estabelecer a confiança na autenticação por certificado.<sup>[[4]](#references)</sup>

Desde a implementação do **KB5014754**, a autenticação moderna Kerberos por certificado depende principalmente da **força do mapeamento**, não apenas dos EKUs.<sup>[[2]](#references)</sup> Em florestas protegidas:

- Um certificado que contenha apenas um **UPN/DNS SAN** pode não ser mais suficiente para o logon.
- O KDC prefere uma **associação forte**, normalmente a **extensão de segurança SID** (`1.3.6.1.4.1.311.25.2`) ou um mapeamento explícito forte em `altSecurityIdentities`.
- Se o certificado não tiver um mapeamento forte, os DCs registram o **Kdcsvc Event ID 39/41** no modo de compatibilidade e negam a autenticação no modo de imposição.
- Em caminhos de ataque mistos, **ESC9/ESC16** são importantes porque removem a extensão SID dos certificados emitidos; os operadores então dependem de mapeamentos explícitos ou de formatos de SID em URLs SAN, quando o caminho de ataque oferece suporte a eles.

### Autenticação Secure Channel (Schannel)

O Schannel permite conexões TLS/SSL seguras. Durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.<sup>[[4]](#references)</sup>

O Schannel também é a alternativa prática quando o **PKINIT** não está disponível. Por exemplo, se um controlador de domínio não tiver um certificado adequado de **Smart Card Logon**, as ferramentas `certipy auth`/PKINIT podem falhar ao tentar obter um TGT, mas o mesmo certificado ainda pode ser usado contra **LDAPS** ou **LDAP StartTLS** para autenticação e operações LDAP.

### Enumeração dos serviços de certificados do AD

Os serviços de certificados do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre **Enterprise Certificate Authorities (CAs)** e suas configurações. Isso está acessível a qualquer usuário autenticado no domínio, sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalonamento de privilégios* ao falsificar certificados de contas de máquina durante o PKINIT. | A correção está incluída nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria e mapeamento forte foram introduzidos pelo **KB5014754**; os ambientes agora devem estar no modo *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* nas funções AD CS Web Enrollment (certsrv) e CES. | Os PoCs públicos são limitados, mas os componentes IIS vulneráveis costumam estar expostos internamente. Aplicar a correção disponibilizada na Patch Tuesday de **julho de 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Em **templates v1**, um solicitante com direitos de enrollment pode incluir **Application Policies/EKUs** na CSR, que têm precedência sobre os EKUs do template, gerando certificados de autenticação de cliente, agente de enrollment ou assinatura de código. | Corrigido em **12 de novembro de 2024**. Substitua ou torne obsoletos os templates v1 (por exemplo, o WebServer padrão), restrinja os EKUs à finalidade desejada e limite os direitos de enrollment. |

### Cronograma de hardening da Microsoft (KB5014754)

A Microsoft introduziu uma implementação em três fases (Compatibility → Audit → Enforcement) para afastar a autenticação de certificados Kerberos de mapeamentos implícitos fracos. Desde **11 de fevereiro de 2025**, os controladores de domínio mudam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Posteriormente, a Microsoft atualizou o cronograma para permitir o retorno ao modo de compatibilidade até a atualização de segurança de **9 de setembro de 2025**.<sup>[[2]](#references)</sup> Os administradores devem:

1. Aplicar as atualizações em todos os DCs e servidores AD CS (maio de 2022 ou posterior).
2. Monitorar os Event IDs 39/41 para identificar mapeamentos fracos durante a fase *Audit*.
3. Reemitir certificados de autenticação de cliente com a nova **extensão SID** ou configurar mapeamentos manuais fortes antes que o enforcement bloqueie os mapeamentos fracos.

### Observações para operadores de florestas com hardening

- **ESC1/ESC6, por si só, já não contam toda a história** em ambientes de 2025 em diante. Se você solicitar um certificado para outra entidade, normalmente também precisará de um artefato de mapeamento forte, como a extensão SID ou um mapeamento explícito.
- **ESC15 (EKUwu)** é mais útil em ambientes sem patches, pois transforma templates **v1** inofensivos, como **WebServer**, em certificados capazes de autenticação ou de atuar como agente de enrollment, injetando **Application Policies**. O Kerberos PKINIT ainda avalia os EKUs, mas o **LDAP Schannel** também considera Application Policies, mantendo relevante o abuso baseado em LDAP.<sup>[[1]](#references)</sup>
- **ESC16** é uma configuração global da CA: se a CA desabilitar globalmente a extensão de segurança SID, todos os certificados emitidos passam a usar um comportamento de mapeamento mais fraco, a menos que a cadeia de ataque injete um SID por outro formato compatível.
- **Os direitos ESC7 são distintos:** uma concessão `ManageCA` na CA pode permitir alterações em configurações como `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), enquanto `ManageCertificates` controla a aprovação de solicitações. Uma negação explícita nos direitos de gerenciador de certificados pode bloquear essa via de aprovação, mesmo que também haja uma permissão Allow; avalie a ACL efetiva da CA antes de encadear configurações e templates. Consulte [a avaliação da ACL da CA da Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Melhorias de detecção e hardening

* O **sensor AD CS do Defender for Identity (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real, como *“Emissão de certificado de controlador de domínio para um não controlador de domínio”* (ESC8) e *“Impedir enrollment de certificados com Application Policies arbitrárias”* (ESC15). Garanta que os sensores estejam implantados em todos os servidores AD CS para aproveitar essas detecções.<sup>[[3]](#references)</sup>
* Desabilite ou restrinja rigorosamente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU definidos explicitamente.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que sejam absolutamente necessários (mitiga cenários ESC2).
* Exija **aprovação do gerente** ou fluxos de trabalho dedicados de Enrollment Agent para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restrinja o web enrollment (`certsrv`) e os endpoints CES/NDES a redes confiáveis ou proteja-os com autenticação por certificado de cliente.
* Exija criptografia no enrollment via RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) para mitigar ESC11 (relay RPC). A flag fica **ativada por padrão**, mas costuma ser desabilitada para clientes legados, reabrindo o risco de relay.
* Proteja os **endpoints de enrollment baseados em IIS** (CES/Certsrv): desabilite NTLM quando possível ou exija HTTPS + Extended Protection para bloquear relays ESC8.

Avalie ESC11 no host que executa a CA, que pode ser um servidor membro do domínio, e não um controlador de domínio. Leia `InterfaceFlags` da CA ativa em `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; um valor ilegível ou ausente indica um resultado desconhecido, não prova que a criptografia RPC está desabilitada. Um bit `IF_ENFORCEENCRYPTICERTREQUEST` desativado é uma pista de configuração que ainda exige um endpoint RPC de enrollment acessível, credenciais que possam ser forçadas e um template de certificado utilizável. Para ESC8, um desafio HTTP NTLM, por si só, não é suficiente: confirme que existe um endpoint de enrollment funcional.

---

## References

- [1] [EKUwu: Não é apenas mais um ESC do AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Alterações na autenticação baseada em certificados nos controladores de domínio do Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Avaliações da postura de segurança de certificados - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusando dos Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
