# Active Directory Web Services (ADWS) Enumeração & Coleta Sigilosa

{{#include ../../banners/hacktricks-training.md}}

## O que é ADWS?

Active Directory Web Services (ADWS) está **ativado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta em TCP **9389**. Apesar do nome, **nenhum HTTP está envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP através de uma pilha de protocolos proprietários de framing .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Porque o tráfego é encapsulado dentro desses frames binários SOAP e trafega por uma porta incomum, **a enumeração via ADWS é muito menos provável de ser inspecionada, filtrada ou detectada por assinaturas do que o tráfego clássico LDAP/389 & 636**. Para operadores isso significa:

* Recon mais sigiloso – as equipes Blue frequentemente se concentram em consultas LDAP.
* Liberdade para coletar a partir de **hosts não-Windows (Linux, macOS)** ao tunelar 9389/TCP através de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (users, groups, ACLs, schema, etc.) e a capacidade de realizar **writes** (por exemplo `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações ADWS são implementadas sobre WS-Enumeration: cada query começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um `EnumerationContext` GUID, seguido por uma ou mais mensagens `Pull` que transmitem até a janela de resultados definida pelo servidor. Contextos expiram após ~30 minutos, então as ferramentas precisam paginar resultados ou dividir filtros (queries por prefixo no CN) para evitar perder estado. Ao solicitar descriptors de segurança, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário o ADWS simplesmente omite o atributo `nTSecurityDescriptor` da sua resposta SOAP.

> NOTA: ADWS também é usado por muitas ferramentas RSAT GUI/PowerShell, então o tráfego pode se misturar com atividade administrativa legítima.

## SoaPy – Cliente Python Nativo

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolo ADWS em Python puro**. Ele constrói os frames NBFX/NBFSE/NNS/NMF byte-a-byte, permitindo coleta a partir de sistemas Unix-like sem tocar no runtime .NET.

### Principais Recursos

* Suporta **proxying através de SOCKS** (útil a partir de implants C2).
* Filtros de busca granulares idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **write** ( `--set` / `--delete` ).
* Modo de saída **BOFHound** para ingestão direta no BloodHound.
* Flag `--parse` para embelezar timestamps / `userAccountControl` quando for necessária legibilidade humana.

### Flags de coleta direcionada & operações de escrita

SoaPy vem com switches curados que replicam as tarefas de hunting LDAP mais comuns sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além de knobs brutos `--query` / `--filter` para pulls customizados. Combine-os com primitivos de escrita como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting direcionado) e `--asrep` (inverte `DONT_REQ_PREAUTH` em `userAccountControl`).

Exemplo de busca SPN direcionada que retorna apenas `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credenciais para imediatamente weaponise findings: dump RBCD-capable objects com `--rbcds`, depois aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar uma cadeia Resource-Based Constrained Delegation (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Um cliente prático para ADWS em Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Busca e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Coleta ADWS de alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e emite JSON compatível com BloodHound v4. Ele constrói um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`), então o reutiliza para execuções de alto volume `--bhdump`, `--certdump` (ADCS), ou `--dnsdump` (AD-integrated DNS) de modo que apenas ~35 atributos críticos deixam o DC. O AutoSplit (`--autosplit --threshold <N>`) fragmenta automaticamente as consultas por prefixo CN para ficar abaixo do timeout EnumerationContext de 30 minutos em grandes florestas.

Fluxo de trabalho típico em uma VM do operador ingressada no domínio:
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
JSON exportado diretamente em fluxos de trabalho SharpHound/BloodHound — veja [BloodHound methodology](bloodhound.md) para ideias de visualização de grafos posteriores. AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas inferior à de snapshots no estilo ADExplorer.

## Fluxo de Coleta AD Silencioso

O seguinte fluxo mostra como enumerar **objetos de domínio e ADCS** sobre ADWS, convertê-los para BloodHound JSON e procurar por caminhos de ataque baseados em certificados — tudo a partir do Linux:

1. **Tunnel 9389/TCP** do network alvo para sua máquina (por exemplo via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Coletar objetos relacionados ao ADCS do Configuration NC:**
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
5. **Upload the ZIP** na GUI do BloodHound e execute queries cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalonamento de certificados (ESC1, ESC8, etc.).

### Escrevendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine isto com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo de Ferramentas

| Propósito | Ferramenta | Notas |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/gravação |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Pode ser encaminhado através do mesmo SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos - permite enumeration, criação de objetos, modificações de atributos e alterações de senhas |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
