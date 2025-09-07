# AD CS Persistência de Domínio

{{#include ../../../banners/hacktricks-training.md}}

**Isto é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Verifique-o para mais detalhes.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Como saber se um certificado é um certificado de CA?

Pode-se determinar que um certificado é de CA se várias condições forem satisfeitas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como TPM/HSM se o sistema operacional suportar.
- Ambos os campos Issuer e Subject do certificado coincidem com o distinguished name da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados de CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada deste certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via GUI integrada. No entanto, este certificado não difere dos outros armazenados no sistema; portanto, métodos como a [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Após adquirir o certificado CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
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
> O usuário alvo da falsificação de certificado deve estar ativo e ser capaz de autenticar no Active Directory para que o processo tenha sucesso. Falsificar um certificado para contas especiais como krbtgt é ineficaz.

Este certificado forjado será **válido** até a data de expiração especificada e enquanto o certificado do root CA estiver válido (geralmente de 5 a **10+ anos**). Também é válido para **máquinas**, então combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** pelo tempo em que o certificado da CA estiver válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados** porque a CA não tem conhecimento deles.

### Operando sob a Aplicação Rigorosa de Mapeamento de Certificados (2025+)

Desde 11 de fevereiro de 2025 (após a implantação do KB5014754), os controladores de domínio usam por padrão **Full Enforcement** para mapeamentos de certificados. Na prática isso significa que seus certificados forjados devem ou:

- Conter um vínculo forte à conta alvo (por exemplo, a SID security extension), ou
- Ser emparelhado com um mapeamento explícito e forte no atributo `altSecurityIdentities` do objeto alvo.

Uma abordagem confiável para persistência é emitir um certificado forjado encadeado à Enterprise CA roubada e então adicionar um mapeamento explícito e forte ao principal da vítima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Se você puder criar certificados forjados que incluam a extensão de segurança SID, estes mapearão implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos explícitos e fortes. Veja [account-persistence](account-persistence.md) para mais sobre mapeamentos explícitos.
- A revogação não ajuda os defensores neste caso: certificados forjados são desconhecidos para o CA database e, portanto, não podem ser revogados.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Esta capacidade é especialmente relevante quando usada em conjunto com um método previamente descrito envolvendo ForgeCert para gerar certificados dinamicamente.

> Considerações de mapeamento pós-2025: colocar uma CA rogue em NTAuth apenas estabelece confiança na CA emissora. Para usar certificados leaf para logon quando os DCs estiverem em **Full Enforcement**, o certificado leaf deve ou conter a extensão de segurança SID ou deve haver um mapeamento explícito forte no objeto alvo (por exemplo, Issuer+Serial em `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Configuração maliciosa - DPERSIST3

Existem muitas oportunidades para **persistência** por meio de **modificações do security descriptor nos componentes do AD CS**. As modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "control rights" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis como:

- O objeto de computador AD do servidor CA
- O servidor RPC/DCOM do servidor CA
- Qualquer **objeto ou container AD descendente** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o Certificate Templates container, o Certification Authorities container, o objeto NTAuthCertificates, etc.)
- Grupos AD com direitos delegados para controlar o AD CS por padrão ou pela organização (como o grupo integrado Cert Publishers e qualquer um de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que possui **permissões elevadas** no domínio, adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, com o atacante sendo o principal para esse direito. Para explorar isso, o atacante primeiro mudaria a propriedade do template **`User`** para si mesmo. Na sequência, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na requisição. Posteriormente, o atacante poderia **enroll** usando o **template**, escolhendo um nome de **administrador de domínio** como nome alternativo, e utilizar o certificado adquirido para autenticação como o DA.

Ajustes práticos que atacantes podem configurar para persistência de longo prazo no domínio (veja {{#ref}}domain-escalation.md{{#endref}} para detalhes completos e detecção):

- Flags de política da CA que permitem SAN a partir dos solicitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém caminhos do tipo ESC1 exploráveis.
- DACL ou configurações do template que permitem emissão com capacidade de autenticação (por exemplo, adicionar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os containers do CA para reintroduzir continuamente emissores rogue se defensores tentarem limpar.

> [!TIP]
> Em ambientes reforçados após KB5014754, combinar essas configurações incorretas com mapeamentos explícitos fortes (`altSecurityIdentities`) garante que os certificados que você emitiu ou forjou permaneçam utilizáveis mesmo quando os DCs aplicarem mapeamento forte.



## Referências

- Microsoft KB5014754 – Alterações na autenticação baseada em certificados nos Windows domain controllers (cronograma de aplicação e mapeamentos fortes). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Referência de comandos e uso de forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
