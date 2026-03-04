# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## O que é o ADWS?

Active Directory Web Services (ADWS) está **habilitado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta em TCP **9389**. Apesar do nome, **não há HTTP envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP através de uma pilha de protocolos proprietários de framing .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Porque o tráfego é encapsulado dentro desses frames binários SOAP e viaja por uma porta incomum, **a enumeração via ADWS tem muito menos probabilidade de ser inspecionada, filtrada ou detectada por assinaturas do que o tráfego LDAP/389 & 636 clássico**. Para operadores isso significa:

* Reconhecimento mais furtivo – Blue teams frequentemente se concentram em consultas LDAP.
* Liberdade para coletar de hosts não-Windows (Linux, macOS) ao tunelar 9389/TCP através de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (users, groups, ACLs, schema, etc.) e a capacidade de realizar **writes** (por exemplo `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações ADWS são implementadas sobre WS-Enumeration: toda query começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um `EnumerationContext` GUID, seguida por uma ou mais mensagens `Pull` que transmitem até a janela de resultados definida pelo servidor. Contextos expiram após ~30 minutos, então as ferramentas precisam paginar resultados ou dividir filtros (consultas por prefixo no CN) para evitar perda de estado. Ao solicitar security descriptors, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs, caso contrário o ADWS simplesmente remove o atributo `nTSecurityDescriptor` da sua resposta SOAP.

> NOTA: ADWS também é usado por muitas ferramentas RSAT GUI/PowerShell, então o tráfego pode se misturar com atividade administrativa legítima.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolos ADWS em Python puro**. Ele constrói os frames NBFX/NBFSE/NNS/NMF byte-for-byte, permitindo coleta a partir de sistemas Unix-like sem tocar no runtime .NET.

### Key Features

* Suporta **proxying through SOCKS** (útil a partir de implants C2).
* Filtros de busca fine-grained idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **write** ( `--set` / `--delete` ).
* **BOFHound output mode** para ingestão direta no BloodHound.
* Flag `--parse` para prettify timestamps / `userAccountControl` quando for necessária legibilidade humana.

### Targeted collection flags & write operations

SoaPy vem com switches curados que replicam as tarefas de hunting LDAP mais comuns sobre ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além de `--query` / `--filter` brutos para pulls customizados. Combine-os com primitivas de escrita como `--rbcd <source>` (seta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting direcionado) e `--asrep` (inverte `DONT_REQ_PREAUTH` em `userAccountControl`).

Exemplo de busca direcionada por SPN que retorna apenas `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credenciais para imediatamente explorar as descobertas: extraia objetos compatíveis com RBCD usando `--rbcds`, depois aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar uma cadeia de Resource-Based Constrained Delegation (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump sobre ADWS (Linux/Windows)

* Fork de `ldapdomaindump` que troca consultas LDAP por chamadas ADWS em TCP/9389 para reduzir detecções por assinatura LDAP.
* Realiza uma verificação inicial de alcançabilidade em 9389 a menos que `--force` seja passado (pula a sondagem se varreduras de portas forem ruidosas/filtradas).
* Testado contra Microsoft Defender for Endpoint e CrowdStrike Falcon com bypass bem-sucedido no README.

### Instalação
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
A saída típica registra a verificação de acessibilidade da porta 9389, o bind do ADWS e o início/fim do dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Um cliente prático para ADWS em Golang

Assim como soapy, [sopa](https://github.com/Macmod/sopa) implementa a pilha de protocolos ADWS (MS-NNS + MC-NMF + SOAP) em Golang, expondo flags de linha de comando para emitir chamadas ADWS como:

* **Busca e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Coleta ADWS de alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e emite JSON compatível com BloodHound v4. Ele constrói um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`), e então o reutiliza para execuções de alto volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (AD-integrated DNS), de modo que apenas ~35 atributos críticos saiam do DC. AutoSplit (`--autosplit --threshold <N>`) divide automaticamente as consultas por prefixo CN para manter-se abaixo do tempo limite do EnumerationContext de 30 minutos em florestas grandes.

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
Os arquivos JSON exportados se encaixam diretamente em workflows do SharpHound/BloodHound — veja [BloodHound methodology](bloodhound.md) para ideias de geração de gráficos posteriores. O AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas inferior à de snapshots no estilo ADExplorer.

## Fluxo Stealth de Coleta AD

O fluxo a seguir mostra como enumerar **objetos do domínio & ADCS** via ADWS, convertê-los para BloodHound JSON e procurar por caminhos de ataque baseados em certificado — tudo a partir do Linux:

1. **Tunnel 9389/TCP** da rede alvo para sua máquina (por exemplo via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use `--proxyHost/--proxyPort` do SoaPy.

2. **Colete o objeto raiz do domínio:**
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
5. **Faça o upload do ZIP** na GUI do BloodHound e execute cypher queries como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalada de certificados (ESC1, ESC8, etc.).

### Escrevendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine isso com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo de Ferramentas

| Propósito | Ferramenta | Notas |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Pode ser encaminhado através do mesmo SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos - permite enumeração, criação de objetos, modificações de atributos e alterações de senha. |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
