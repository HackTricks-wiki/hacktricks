# Anti-Forensics de AD Dynamic Objects (dynamicObject)

{{#include ../../banners/hacktricks-training.md}}

## Mecânica e fundamentos de detecção

- Qualquer objeto criado com a classe auxiliar **`dynamicObject`** obtém **`entryTTL`** (contagem regressiva em segundos) e **`msDS-Entry-Time-To-Die`** (expiração absoluta). Quando `entryTTL` chega a 0, o **Garbage Collector o exclui sem tombstone/recycle-bin**, apagando o criador e os timestamps e impedindo a recuperação.
- **`entryTTL` é um atributo operacional/constructed**: solicite-o explicitamente nas consultas LDAP. O TTL pode ser atualizado antes da expiração ou por meio do LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Os valores mínimo/padrão do TTL são aplicados em **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. A Microsoft documenta **86400s** como TTL padrão e **900s** como TTL mínimo válido padrão; ambos aceitam valores de **1s–1y**. Dynamic objects não são suportados nas partições Configuration/Schema.
- Não existe conversão de static para dynamic nem uma fase de tombstone após a expiração. As equipes de IR não podem depender de controles de objetos excluídos ou do Recycle Bin; elas precisam capturar o objeto ativo e seus metadados antes que o GC o remova.
- O refresh é **sensível à replica**: se o TTL for renovado muito próximo da expiração, outra replica gravável ou o GC ainda poderá excluir o objeto localmente antes que o refresh seja replicado. TTLs muito curtos funcionam melhor quando o atacante sabe qual DC atenderá o abuso, enquanto os defensores devem consultar **todos os naming contexts / replicas** durante a triagem.
- A exclusão pode atrasar alguns minutos em DCs com pouco tempo de atividade (<24h), deixando uma janela estreita de resposta para consultar/fazer backup dos atributos. Detecte alertando sobre **novos objetos que contenham `entryTTL`/`msDS-Entry-Time-To-Die`** e correlacionando-os com SIDs órfãos/links quebrados.<sup>[[1]](#references)</sup>

## Enumeração rápida / Live Triage

- Consulte **todos os `namingContexts` do RootDSE**, não apenas o NC do domínio. O abuso de objetos dinâmicos pode estar em **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou em application partitions.
- Enquanto o objeto ainda estiver ativo, faça imediatamente o dump dos **metadados de replicação** e de quaisquer atributos vinculados/ACLs. Após a expiração, podem restar apenas **valores `gPLink` quebrados, SIDs órfãos ou respostas DNS em cache**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasão de MAQ com Computadores que se Autodeletam

- O **`ms-DS-MachineAccountQuota` = 10** padrão permite que qualquer usuário autenticado crie computadores. Adicione `dynamicObject` durante a criação para que o computador se autodelete e **libere o slot da quota**, eliminando evidências.
- Ajuste do Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se o TTL solicitado estiver **abaixo de `DynamicObjectMinTTL`**, espere um ajuste ou uma rejeição no servidor, dependendo do caminho de criação; em muitos domínios, o limite efetivo é de **900s**, e o fallback/padrão continua sendo **86400s**. O ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.
- Enquanto o objeto existir, os defensores ainda poderão recuperar o criador sem privilégios por meio de **`msDS-CreatorSID`** no objeto do computador. Quando o computador dinâmico expirar, essa atribuição desaparecerá junto com o objeto.<sup>[[1]](#references)</sup>

## Associação Discreta a Grupo Primário

- Crie um **grupo de segurança dinâmico** e defina o **`primaryGroupID`** de um usuário como o RID desse grupo para obter associação efetiva que **não aparece em `memberOf`**, mas é considerada no Kerberos/tokens de acesso.<sup>[[1]](#references)</sup>
- A expiração do TTL **exclui o grupo apesar da proteção contra exclusão de grupo primário**, deixando o usuário com um `primaryGroupID` corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.
- Os relatórios dependem da ferramenta: **`Get-ADGroupMember` / `net group`** geralmente resolvem associações derivadas do grupo primário, enquanto **`memberOf`** e **`Get-ADGroup -Properties member`** não. Para mais técnicas relacionadas a `primaryGroupID`, consulte [esta outra página sobre abuso de DCShadow e PGID](dcshadow.md).
- Para alvos **não protegidos pelo AdminSDHolder**, os atacantes podem combinar o truque do grupo dinâmico com uma **negação DACL de leitura de `primaryGroupID`** (ou do atributo `member` do grupo) para ocultar o vínculo de muitos fluxos de trabalho LDAP/PowerShell, mesmo antes de o grupo expirar.<sup>[[2]](#references)</sup>

## Poluição de SID Órfão do AdminSDHolder

- Adicione ACEs de um **usuário/grupo dinâmico de curta duração** a **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL, o SID se torna **não resolvível (“Unknown SID”)** na ACL do template, e o **SDProp (~60 min)** propaga esse SID órfão por todos os objetos protegidos do Tier-0.
- A análise forense perde a atribuição porque o principal desapareceu (não há DN de objeto excluído). Monitore **novos principais dinâmicos + SIDs órfãos repentinos no AdminSDHolder/ACLs privilegiadas**.<sup>[[1]](#references)</sup>

## Execução de GPO Dinâmica com Evidências que se Autodestroem

- Crie um objeto **`groupPolicyContainer` dinâmico** com um **`gPCFileSysPath`** malicioso (por exemplo, um compartilhamento SMB à la GPODDITY) e **vincule-o por meio de `gPLink`** a uma OU-alvo.
- Os clientes processam a política e obtêm o conteúdo do SMB do atacante. Quando o TTL expira, o objeto GPO (e o `gPCFileSysPath`) desaparece; resta apenas um GUID **`gPLink`** quebrado, removendo do LDAP as evidências do payload executado.
- Isso é operacionalmente mais limpo do que a limpeza no estilo **GPODDITY** clássico: em vez de restaurar manualmente o `gPCFileSysPath` original, o AD remove automaticamente o GPC malicioso quando o temporizador expira.<sup>[[1]](#references)</sup>

## Redirecionamento Efêmero de DNS Integrado ao AD

- Os registros DNS do AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como **objetos dinâmicos** permite o redirecionamento temporário de hosts (captura de credenciais/MITM). Os clientes armazenam em cache a resposta A/AAAA maliciosa; depois, o registro se autodeleta para que a zona pareça limpa (o DNS Manager pode precisar recarregar a zona para atualizar a visualização).
- Detecção: alerte sobre **qualquer registro DNS que contenha `dynamicObject`/`entryTTL`** por meio de logs de replicação/eventos; registros transitórios raramente aparecem nos logs DNS padrão.<sup>[[1]](#references)</sup>

## Lacuna de Delta Sync do Entra ID Híbrido (Nota)

- A sincronização delta do Entra Connect depende de **tombstones** para detectar exclusões. Um **usuário dinâmico on-premises** pode ser sincronizado com o Entra ID, expirar e ser excluído sem tombstone — a sincronização delta não removerá a conta na cloud, deixando um **usuário Entra ativo órfão** até que uma **sincronização inicial/completa** ou uma limpeza manual na cloud seja forçada.<sup>[[1]](#references)</sup>

## Referências

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
