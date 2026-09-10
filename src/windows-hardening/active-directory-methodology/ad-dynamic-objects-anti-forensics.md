# Objetos Dinâmicos do AD (dynamicObject) - Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mecânica e noções básicas de detecção

- Qualquer objeto criado com a classe auxiliar **`dynamicObject`** recebe **`entryTTL`** (contagem regressiva em segundos) e **`msDS-Entry-Time-To-Die`** (expiração absoluta). Quando `entryTTL` chega a 0 **e o objeto não tem descendentes**, o Garbage Collector o exclui sem tombstone/recycle-bin, apagando o criador e os timestamps e impedindo a recuperação.<sup>[[4]](#references)</sup>
- **`entryTTL` é um atributo operacional/constructed**: solicite-o explicitamente nas consultas LDAP. O TTL pode ser atualizado modificando `entryTTL` antes da expiração ou por meio do OID de atualização de TTL do LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- Os valores mínimo/padrão do TTL são AVAs em toda a forest, localizados em **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` e `DynamicObjectDefaultTTLSeconds=<seconds>`. A Microsoft documenta **86400s** como TTL padrão e **900s** como TTL mínimo válido padrão; o intervalo de schema de `entryTTL` é **1–31557600s** (um segundo a um ano).<sup>[[3]](#references)</sup> Objetos dinâmicos são **unsupported** nas partições Configuration/Schema.
- Não existe **conversão de static→dynamic** nem fase de tombstone após a expiração. As equipes de IR não podem depender de controles de objetos excluídos ou do Recycle Bin; elas precisam capturar o objeto/metadados ativos antes que o GC os remova.
- A atualização é **sensível à replica**: se o TTL for renovado muito próximo da expiração, outra replica gravável ou o GC ainda poderá excluir o objeto localmente antes que a atualização seja replicada. TTLs muito curtos funcionam melhor quando o atacante sabe qual DC atenderá o abuso, enquanto os defensores devem consultar **todos os naming contexts / replicas** durante a triagem.
- A exclusão pode atrasar alguns minutos em DCs com pouco tempo de atividade (<24h), deixando uma estreita janela de resposta para consultar/fazer backup dos atributos. Detecte isso **alertando sobre novos objetos que contenham `entryTTL`/`msDS-Entry-Time-To-Die`** e correlacionando-os com SIDs órfãos/links quebrados.<sup>[[1]](#references)</sup>

### Grafo de expiração e casos extremos de limpeza de referências

- Todo descendente abaixo de um objeto dinâmico também deve ser dinâmico. Um pai dinâmico expirado só é coletado pelo Garbage Collector depois que se torna uma folha; se um descendente tiver um `msDS-Entry-Time-To-Die` posterior, o DC avança a expiração do pai para além da expiração máxima dos descendentes. Consequentemente, uma subtree dinâmica gravável pode **fixar/estender um pai que parece prestes a desaparecer**: enumere toda a subtree e não use o `entryTTL` observado do pai como prazo de limpeza.<sup>[[4]](#references)</sup>
- A limpeza da expiração é **ciente de schema-link**. As replicas removem valores de atributos vinculados que fazem referência ao objeto dinâmico excluído, mas preservam valores não vinculados. Espere que os membros comuns de forward/back-link sejam limpos, enquanto referências de inteiros/SIDs/strings, como `primaryGroupID`, SIDs incorporados em `nTSecurityDescriptor` ou texto de `gPLink`, possam persistir como vestígios forenses.<sup>[[4]](#references)</sup>

## Enumeração rápida / triagem em tempo real

- Consulte todos os **`namingContexts` do RootDSE**, não apenas o domínio NC. O abuso de objetos dinâmicos pode existir em **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou em partições de aplicações.
- Enquanto o objeto ainda estiver ativo, descarregue imediatamente os **metadados de replicação** e quaisquer atributos vinculados/ACLs. Após a expiração, podem restar apenas **valores `gPLink` quebrados, SIDs órfãos ou respostas DNS em cache**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasão de MAQ com Computadores que se Excluem

- O **`ms-DS-MachineAccountQuota` = 10** padrão permite que qualquer usuário autenticado crie computadores. Adicione `dynamicObject` durante a criação para que o computador se exclua automaticamente e **libere o slot da quota**, enquanto apaga as evidências.
- Ajuste do Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se o TTL solicitado estiver **abaixo de `DynamicObjectMinTTL`**, espere um ajuste ou uma rejeição do lado do servidor, dependendo do caminho de criação; em muitos domínios, o limite efetivo é **900s** e o fallback/padrão continua sendo **86400s**. O ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.
- Enquanto o objeto existir, os defensores ainda poderão identificar o criador sem privilégios por meio de **`msDS-CreatorSID`** no objeto do computador. Depois que o computador dinâmico expirar, essa atribuição desaparecerá junto com o objeto.<sup>[[1]](#references)</sup>

## Associação Discreta ao Primary Group

- Crie um **grupo de segurança dinâmico** e defina o **`primaryGroupID`** de um usuário como o RID desse grupo para obter uma associação efetiva que **não aparece em `memberOf`**, mas é considerada pelo Kerberos/tokens de acesso.<sup>[[1]](#references)</sup>
- A expiração do TTL **exclui o grupo apesar da proteção contra exclusão do grupo primário**, deixando o usuário com um **`primaryGroupID`** corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.
- Os relatórios dependem da ferramenta: **`Get-ADGroupMember` / `net group`** geralmente resolvem a associação derivada do grupo primário, enquanto **`memberOf`** e **`Get-ADGroup -Properties member`** não. Para mais detalhes sobre tradecraft de **`primaryGroupID`**, consulte [esta outra página sobre abuso de DCShadow e PGID](dcshadow.md).
- Para alvos **não protegidos pelo AdminSDHolder**, os atacantes podem combinar a técnica do grupo dinâmico com uma **DACL deny na leitura de `primaryGroupID`** (ou do atributo `member` do grupo) para ocultar a relação de muitos fluxos de trabalho LDAP/PowerShell, mesmo antes da expiração do grupo.<sup>[[2]](#references)</sup>

## Poluição de SID Órfão no AdminSDHolder

- Adicione ACEs de um **usuário/grupo dinâmico de curta duração** a **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL, o SID se torna **irresolvível (“Unknown SID”)** na ACL do template, e o **SDProp (~60 min)** propaga esse SID órfão por todos os objetos Tier-0 protegidos.
- A análise forense perde a atribuição porque o principal desapareceu (sem DN de objeto excluído). Monitore **novos principals dinâmicos + SIDs órfãos repentinos no AdminSDHolder/ACLs privilegiadas**.<sup>[[1]](#references)</sup>

## Execução de GPO Dinâmica com Evidências que se Autodestroem

- Crie um objeto **`groupPolicyContainer` dinâmico** com um **`gPCFileSysPath`** malicioso (por exemplo, um compartilhamento SMB à la GPODDITY) e **vincule-o por meio de `gPLink`** a uma OU-alvo.
- Os clientes processam a policy e obtêm o conteúdo do SMB do atacante. Quando o TTL expira, o objeto GPO (e o **`gPCFileSysPath`**) desaparece; apenas um GUID de **`gPLink` quebrado** permanece, removendo do LDAP as evidências do payload executado.
- Isso é operacionalmente mais limpo do que a limpeza clássica no estilo **GPODDITY**: em vez de restaurar manualmente o `gPCFileSysPath` original, o AD remove automaticamente o GPC malicioso quando o timer expira.<sup>[[1]](#references)</sup> Consulte [abuso de persistência de ACL](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) para obter os detalhes do protocolo e das ferramentas, em vez de duplicá-los aqui.

## Redirecionamento Efêmero de DNS Integrado ao AD

- Os registros DNS do AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como **objetos dinâmicos** permite o redirecionamento temporário de hosts (captura de credenciais/MITM). Os clientes armazenam em cache a resposta A/AAAA maliciosa; posteriormente, o registro se exclui automaticamente para que a zona pareça limpa (o DNS Manager pode precisar recarregar a zona para atualizar a visualização).
- Detecção: gere um alerta para **qualquer registro DNS que contenha `dynamicObject`/`entryTTL`** por meio de logs de replicação/eventos; registros transitórios raramente aparecem nos logs DNS padrão.<sup>[[1]](#references)</sup>

## Lacuna de Delta-Sync Híbrido do Entra ID (Observação)

- O delta sync do Entra Connect depende de **tombstones** para detectar exclusões. Um **usuário on-prem dinâmico** pode ser sincronizado com o Entra ID, expirar e ser excluído sem tombstone — o delta sync não removerá a conta na cloud, deixando um **usuário Entra ativo órfão** até que um **initial/full sync** ou uma limpeza manual na cloud seja forçada.<sup>[[1]](#references)</sup>



## References

- [1] [Objetos Dinâmicos no Active Directory: A Ameaça Discreta](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Aventuras no Comportamento, Relatórios e Exploração de Grupos Primários](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuração dos Limites de TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Requisitos de DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
