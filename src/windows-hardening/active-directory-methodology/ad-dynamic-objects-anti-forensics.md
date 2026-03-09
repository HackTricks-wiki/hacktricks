# AD Dynamic Objects (dynamicObject) Anti-Forense

{{#include ../../banners/hacktricks-training.md}}

## Mecânica & Noções Básicas de Detecção

- Qualquer objeto criado com a classe auxiliar **`dynamicObject`** ganha **`entryTTL`** (contagem regressiva em segundos) e **`msDS-Entry-Time-To-Die`** (expiração absoluta). Quando `entryTTL` chega a 0 o **Garbage Collector o exclui sem tombstone/recycle-bin**, apagando criador/carimbos de data/hora e impedindo a recuperação.
- O TTL pode ser renovado atualizando `entryTTL`; mínimos/padrões são aplicados em **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (suporta 1s–1y, mas comumente padrão é 86.400s/24h). Objetos dinâmicos não são suportados nas partições Configuration/Schema.
- A exclusão pode atrasar alguns minutos em DCs com uptime curto (<24h), deixando uma janela estreita para consultar/backup de atributos. Detecte alertando sobre **novos objetos carregando `entryTTL`/`msDS-Entry-Time-To-Die`** e correlacione com SIDs órfãos/links quebrados.

## MAQ Evasion with Self-Deleting Computers

- O padrão **`ms-DS-MachineAccountQuota` = 10** permite que qualquer usuário autenticado crie computadores. Adicione `dynamicObject` durante a criação para que o computador se autoexclua e **libere a vaga de quota** enquanto apaga evidências.
- Powermad tweak dentro de `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- TTL curto (ex.: 60s) frequentemente falha para usuários padrão; AD recai para **`DynamicObjectDefaultTTL`** (exemplo: 86.400s). ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.

## Stealth Primary Group Membership

- Crie um **dynamic security group**, então ajuste o **`primaryGroupID`** de um usuário para o RID do grupo para obter associação efetiva que **não aparece em `memberOf`** mas é respeitada em Kerberos/access tokens.
- A expiração do TTL **exclui o grupo apesar da proteção de exclusão do primary-group**, deixando o usuário com um `primaryGroupID` corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.

## AdminSDHolder Orphan-SID Pollution

- Adicione ACEs para um **usuário/grupo dinâmico de vida curta** em **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL o SID fica **irresolúvel (“Unknown SID”)** no ACL template, e **SDProp (~60 min)** propaga esse SID órfão por todos os objetos protegidos Tier-0.
- A forense perde atribuição porque o principal sumiu (sem DN de objeto excluído). Monitore por **novos principais dinâmicos + SIDs órfãos súbitos no AdminSDHolder/ACLs privilegiadas**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Crie um **dynamic `groupPolicyContainer`** com um malicioso **`gPCFileSysPath`** (ex.: SMB share à la GPODDITY) e **linke-o via `gPLink`** a uma OU alvo.
- Clientes processam a policy e puxam conteúdo do SMB do atacante. Quando o TTL expira, o objeto GPO (e `gPCFileSysPath`) some; só resta um **`gPLink`** GUID quebrado, removendo evidência LDAP do payload executado.

## Ephemeral AD-Integrated DNS Redirection

- Registros DNS AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como **dynamic objects** permite redirecionamento temporário de hosts (captura de credenciais/MITM). Clientes cacheiam a resposta A/AAAA maliciosa; o registro depois se autoexclui e a zone parece limpa (DNS Manager pode precisar reload da zone para atualizar a visualização).
- Detecção: alerte em **qualquer registro DNS carregando `dynamicObject`/`entryTTL`** via replicação/logs de evento; registros transitórios raramente aparecem em logs DNS padrão.

## Hybrid Entra ID Delta-Sync Gap (Nota)

- O delta sync do Entra Connect depende de **tombstones** para detectar exclusões. Um **usuário on-prem dinâmico** pode sincronizar para Entra ID, expirar e ser excluído sem tombstone — o delta sync não removerá a conta na cloud, deixando um **usuário Entra órfão ativo** até que um full sync manual seja forçado.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
