# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Qualquer object criado com a auxiliary class **`dynamicObject`** ganha **`entryTTL`** (contagem regressiva em segundos) e **`msDS-Entry-Time-To-Die`** (expiração absoluta). Quando `entryTTL` chega a 0, o **Garbage Collector** o deleta sem tombstone/recycle-bin, apagando creator/timestamps e bloqueando recovery.
- **`entryTTL` é um atributo operacional/constructed**: solicite-o explicitamente em consultas LDAP. O TTL pode ser renovado atualizando `entryTTL` antes da expiração ou via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- O TTL mínimo/padrão é imposto em **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. A Microsoft documenta **86400s** como TTL padrão e **900s** como TTL mínimo válido padrão; ambos suportam **1s–1y**. Dynamic objects são **unsupported em partições Configuration/Schema**.
- Não há conversão estática→dinâmica e não existe fase de tombstone após a expiração. As equipes de IR não podem contar com deleted-object controls ou Recycle Bin; elas precisam capturar o objeto/metadata ativos antes que o GC os remova.
- A renovação é **replica-sensitive**: se o TTL for renovado muito perto da expiração, outro writable replica ou GC ainda pode deletar o objeto localmente antes de a renovação se replicar. TTLs muito curtos funcionam melhor quando o atacante sabe qual DC irá atender o abuso, enquanto os defensores devem consultar **todos os naming contexts / replicas** durante a triagem.
- A deleção pode atrasar alguns minutos em DCs com uptime curto (<24h), deixando uma janela estreita de resposta para consultar/backup de atributos. Detecte alertando sobre novos objects que carregam `entryTTL`/`msDS-Entry-Time-To-Die` e correlacionando com orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Consulte **todos os `namingContexts` do RootDSE**, não apenas o domain NC. O abuso dynamic pode viver em **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou em application partitions.
- Enquanto o object ainda estiver vivo, faça dump imediato de **replication metadata** e de quaisquer linked attributes/ACLs. Após a expiração, você pode ficar apenas com **broken `gPLink` values, orphan SIDs, ou cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasão de MAQ com Computadores Autoexcluíveis

- O padrão **`ms-DS-MachineAccountQuota` = 10** permite que qualquer usuário autenticado crie computadores. Adicione `dynamicObject` durante a criação para fazer o computador se autoexcluir e **liberar o slot da quota** enquanto apaga evidências.
- Ajuste do Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se o TTL solicitado estiver **abaixo de `DynamicObjectMinTTL`**, espere ajuste do lado do servidor ou rejeição, dependendo do caminho de criação; em muitos domínios o piso efetivo é **900s** e o fallback/padrão continua **86400s**. O ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.
- Enquanto o objeto existir, defensores ainda podem recuperar o criador sem privilégios a partir de **`msDS-CreatorSID`** no objeto de computador. Depois que o computador dinâmico expira, essa atribuição desaparece junto com o objeto.

## Associação furtiva ao Primary Group

- Crie um **dynamic security group**, depois defina o **`primaryGroupID`** de um usuário para o RID desse grupo para obter associação efetiva que **não aparece em `memberOf`** mas é respeitada em Kerberos/access tokens.
- A expiração do TTL **exclui o grupo apesar da proteção de exclusão do primary group**, deixando o usuário com um `primaryGroupID` corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.
- O reporting depende da ferramenta: **`Get-ADGroupMember` / `net group`** normalmente resolvem associação derivada do primary group, enquanto **`memberOf`** e **`Get-ADGroup -Properties member`** não. Para uma tradecraft mais ampla de `primaryGroupID`, veja [this other page about DCShadow and PGID abuse](dcshadow.md).
- Para alvos **não protegidos por AdminSDHolder**, atacantes podem combinar o truque do dynamic-group com um **DACL deny na leitura de `primaryGroupID`** (ou do atributo `member` do grupo) para ocultar o vínculo de muitos fluxos LDAP/PowerShell mesmo antes de o grupo expirar.

## Poluição de SID Órfão do AdminSDHolder

- Adicione ACEs para um **usuário/grupo dinâmico de curta duração** em **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL, o SID se torna **não resolvível (“Unknown SID”)** na ACL do template, e o **SDProp (~60 min)** propaga esse SID órfão por todos os objetos protegidos Tier-0.
- A forense perde a atribuição porque o principal desapareceu (sem DN de objeto excluído). Monitore **novos principais dinâmicos + SIDs órfãos repentinos em AdminSDHolder/ACLs privilegiadas**.

## Execução Dinâmica de GPO com Evidências Autodestrutivas

- Crie um objeto **dynamic `groupPolicyContainer`** com um **`gPCFileSysPath`** malicioso (por exemplo, share SMB à la GPODDITY) e **vincule-o via `gPLink`** a uma OU alvo.
- Os clientes processam a policy e puxam conteúdo do SMB do atacante. Quando o TTL expira, o objeto GPO (e `gPCFileSysPath`) desaparece; apenas um GUID de **`gPLink`** quebrado permanece, removendo evidência LDAP do payload executado.
- Isso é operacionalmente mais limpo do que a limpeza clássica no estilo **GPODDITY**: em vez de restaurar você mesmo o `gPCFileSysPath` original, o AD remove automaticamente o GPC malicioso quando o timer expira.

## Redirecionamento Efêmero de DNS Integrado ao AD

- Registros DNS do AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como objetos dinâmicos permite redirecionamento temporário de hosts (captura de credenciais/MITM). Os clientes armazenam em cache a resposta A/AAAA maliciosa; o registro depois se autoexclui, deixando a zona limpa (o DNS Manager pode precisar recarregar a zona para atualizar a visualização).
- Detecção: alerte sobre **qualquer registro DNS contendo `dynamicObject`/`entryTTL`** via logs de replicação/evento; registros transitórios raramente aparecem em logs DNS padrão.

## Gap de Delta-Sync Híbrido do Entra ID (Nota)

- O delta sync do Entra Connect depende de **tombstones** para detectar exclusões. Um **dynamic on-prem user** pode sincronizar com o Entra ID, expirar e ser excluído sem tombstone — o delta sync não removerá a conta na cloud, deixando um **usuário Entra ativo órfão** até que um **initial/full sync** ou uma limpeza manual na cloud seja forçada.

## Referências

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
