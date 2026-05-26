# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Any object created with the auxiliary class **`dynamicObject`** gains **`entryTTL`** (seconds countdown) and **`msDS-Entry-Time-To-Die`** (absolute expiry). When `entryTTL` reaches 0 the **Garbage Collector deletes it without tombstone/recycle-bin**, erasing creator/timestamps and blocking recovery.
- **`entryTTL` is an operational/constructed attribute**: request it explicitly in LDAP queries. TTL can be refreshed either by updating `entryTTL` before expiry or via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default are enforced in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documents **86400s** as the default TTL and **900s** as the default minimum valid TTL; both support **1s–1y**. Dynamic objects are **unsupported in Configuration/Schema partitions**.
- There is **no static→dynamic conversion** and no tombstone phase after expiry. IR teams cannot rely on deleted-object controls or Recycle Bin; they must capture the live object/metadata before GC removes it.
- Refresh is **replica-sensitive**: if TTL is renewed too close to expiry, another writable replica or GC can still delete the object locally before the refresh replicates. Very short TTLs therefore work best when the attacker knows which DC will service the abuse, while defenders should query **all naming contexts / replicas** during triage.
- Deletion can lag a few minutes on DCs with short uptime (<24h), leaving a narrow response window to query/backup attributes. Detect by **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** and correlating with orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Query **all `namingContexts` from RootDSE**, not only the domain NC. Dynamic abuse can live in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) or in application partitions.
- While the object is still alive, immediately dump **replication metadata** and any linked attributes/ACLs. After expiry you may be left only with **broken `gPLink` values, orphan SIDs, or cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasão de MAQ com Computers Autoexcluídos

- O **`ms-DS-MachineAccountQuota` = 10** padrão permite que qualquer usuário autenticado crie computers. Adicione `dynamicObject` durante a criação para fazer o computer se autoexcluir e **liberar o slot da quota** enquanto apaga evidências.
- Ajuste do Powermad dentro de `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se o TTL solicitado estiver **abaixo de `DynamicObjectMinTTL`**, espere ajuste do lado do servidor ou rejeição dependendo do caminho de criação; em muitos domínios o piso efetivo é **900s** e o fallback/padrão continua sendo **86400s**. O ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.
- Enquanto o objeto existe, defensores ainda podem recuperar o criador sem privilégios de **`msDS-CreatorSID`** no objeto computer. Quando o dynamic computer expira, essa atribuição desaparece junto com o objeto.

## Membership de Primary Group Discreto

- Crie um **dynamic security group**, depois defina o **`primaryGroupID`** de um usuário para o RID desse grupo para obter membership efetivo que **não aparece em `memberOf`** mas é respeitado no Kerberos/access tokens.
- A expiração do TTL **exclui o grupo apesar da proteção de exclusão do primary-group**, deixando o usuário com um `primaryGroupID` corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.
- O reporting depende da ferramenta: **`Get-ADGroupMember` / `net group`** normalmente resolvem membership derivado de primary-group, enquanto **`memberOf`** e **`Get-ADGroup -Properties member`** não. Para tradecraft mais amplo de `primaryGroupID`, veja [esta outra página sobre DCShadow e abuso de PGID](dcshadow.md).
- Para alvos **não protegidos por AdminSDHolder**, attackers podem combinar o truque do dynamic-group com uma **DACL deny na leitura de `primaryGroupID`** (ou do atributo `member` do grupo) para ocultar o vínculo de muitos workflows LDAP/PowerShell mesmo antes de o grupo expirar.

## Poluição de SID Órfão em AdminSDHolder

- Adicione ACEs para um **dynamic user/group** de vida curta a **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL, o SID torna-se **não resolvível (“Unknown SID”)** na ACL do template, e o **SDProp (~60 min)** propaga esse SID órfão para todos os objetos protegidos de Tier-0.
- A forensics perde a atribuição porque o principal desaparece (sem DN de objeto excluído). Monitore por **novos principals dynamic + SIDs órfãos súbitos em AdminSDHolder/privileged ACLs**.

## Execução Dinâmica de GPO com Evidências Auto-destrutivas

- Crie um objeto **dynamic `groupPolicyContainer`** com um **`gPCFileSysPath`** malicioso (por exemplo, um SMB share à la GPODDITY) e **linke-o via `gPLink`** a uma OU alvo.
- Os clientes processam a policy e puxam o conteúdo do SMB do attacker. Quando o TTL expira, o objeto GPO (e o `gPCFileSysPath`) desaparece; apenas um GUID de **`gPLink`** quebrado permanece, removendo evidência LDAP do payload executado.
- Operacionalmente isso é mais limpo do que a limpeza clássica no estilo **GPODDITY**: em vez de restaurar o `gPCFileSysPath` original manualmente, o AD remove automaticamente o GPC malicioso quando o timer expira.

## Redirecionamento Efêmero de DNS Integrado ao AD

- Os registros DNS do AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como **dynamic objects** permite redirecionamento temporário de host (credential capture/MITM). Os clientes armazenam em cache a resposta A/AAAA maliciosa; depois o registro se autoexclui para que a zona pareça limpa (o DNS Manager pode precisar de reload da zona para atualizar a visão).
- Detecção: alerte sobre **qualquer registro DNS que contenha `dynamicObject`/`entryTTL`** via logs de replication/evento; registros transitórios raramente aparecem em logs DNS padrão.

## Gap de Delta-Sync Híbrido do Entra ID (Nota)

- O delta sync do Entra Connect depende de **tombstones** para detectar exclusões. Um **dynamic on-prem user** pode sincronizar para o Entra ID, expirar e ser excluído sem tombstone — o delta sync não removerá a cloud account, deixando um **orphaned active Entra user** até que um **initial/full sync** ou uma limpeza manual na cloud seja forçada.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
