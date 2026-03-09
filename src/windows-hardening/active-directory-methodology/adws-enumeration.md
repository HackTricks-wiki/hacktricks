# Active Directory Web Services (ADWS) Enumeração & Coleta Furtiva

{{#include ../../banners/hacktricks-training.md}}

## O que é o ADWS?

Active Directory Web Services (ADWS) está **habilitado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta em TCP **9389**. Apesar do nome, **nenhum HTTP está envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP através de uma pilha de protocolos proprietários de framing .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego é encapsulado dentro desses frames SOAP binários e viaja por uma porta incomum, **a enumeração via ADWS tem muito menos probabilidade de ser inspecionada, filtrada ou detectada por assinaturas do que o tráfego clássico LDAP/389 & 636**. Para operadores, isso significa:

* Reconhecimento mais furtivo – as equipes Blue frequentemente se concentram em consultas LDAP.
* Liberdade para coletar de **hosts não-Windows (Linux, macOS)** tunelando 9389/TCP através de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (users, groups, ACLs, schema, etc.) e a capacidade de realizar **writes** (ex.: `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações ADWS são implementadas sobre WS-Enumeration: toda consulta começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um GUID `EnumerationContext`, seguida por uma ou mais mensagens `Pull` que transmitem até a janela de resultados definida pelo servidor. Contextos expiram após ~30 minutos, então as ferramentas precisam ou paginar resultados ou dividir filtros (consultas por prefixo por CN) para evitar perder estado. Ao solicitar security descriptors, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário o ADWS simplesmente remove o atributo `nTSecurityDescriptor` da sua resposta SOAP.

> NOTA: ADWS também é usado por muitas ferramentas RSAT GUI/PowerShell, então o tráfego pode se misturar com atividade administrativa legítima.

## SoaPy – Cliente Python Nativo

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolo ADWS em Python puro**. Ele constrói os frames NBFX/NBFSE/NNS/NMF byte-a-byte, permitindo coleta a partir de sistemas Unix-like sem tocar no runtime .NET.

### Principais Recursos

* Suporta **proxy através de SOCKS** (útil a partir de C2 implants).
* Filtros de busca granulares idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **write** ( `--set` / `--delete` ).
* Modo de saída **BOFHound** para ingestão direta no BloodHound.
* Flag `--parse` para embelezar timestamps / `userAccountControl` quando for necessária legibilidade humana.

### Flags de coleta direcionada & operações de escrita

SoaPy vem com opções curadas que replicam as tarefas de hunting LDAP mais comuns sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além dos knobs brutos `--query` / `--filter` para pulls customizados. Combine essas opções com primitivas de escrita como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting direcionado) e `--asrep` (inverter `DONT_REQ_PREAUTH` em `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credentials para imediatamente explorar as descobertas: liste objetos compatíveis com RBCD usando `--rbcds`, depois aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar uma cadeia Resource-Based Constrained Delegation (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork of `ldapdomaindump` que substitui consultas LDAP por chamadas ADWS em TCP/9389 para reduzir detecções por assinatura LDAP.
* Realiza uma verificação inicial de alcance a 9389, a menos que `--force` seja usado (pula a sondagem se varreduras de portas forem barulhentas/filtradas).
* Testado contra Microsoft Defender for Endpoint e CrowdStrike Falcon, com bypass bem-sucedido descrito no README.

### Instalação
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
A saída típica registra a verificação de acessibilidade da porta 9389, o bind do ADWS e o início/término do dump:
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

* **Busca e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e emite JSON compatível com BloodHound v4. Ele constrói um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`), depois o reutiliza para passes de alto volume `--bhdump`, `--certdump` (ADCS), ou `--dnsdump` (AD-integrated DNS) de modo que apenas ~35 atributos críticos saiam do DC. AutoSplit (`--autosplit --threshold <N>`) fragmenta automaticamente as consultas por prefixo CN para ficar abaixo do timeout EnumerationContext de 30 minutos em florestas grandes.

Fluxo de trabalho típico em uma VM do operador associada ao domínio:
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
Exporta slots JSON diretamente para fluxos de trabalho do SharpHound/BloodHound — see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas menor do que ADExplorer-style snapshots.

## Fluxo de Coleta AD Sigiloso

O fluxo a seguir mostra como enumerar **domain & ADCS objects** over ADWS, convertê-los para BloodHound JSON e procurar por caminhos de ataque baseados em certificado – tudo a partir do Linux:

1. **Túnel 9389/TCP** da rede alvo para sua máquina (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use SoaPy’s `--proxyHost/--proxyPort`.

2. **Colete o objeto root domain:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Colete objetos relacionados ao ADCS do Configuration NC:**
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
Combine isto com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo de Ferramentas

| Objetivo | Ferramenta | Observações |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
