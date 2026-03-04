# Objetos Dinâmicos do AD (dynamicObject) Anti-Forense

{{#include ../../banners/hacktricks-training.md}}

## Mecânica & Noções Básicas de Detecção

- Qualquer objeto criado com a auxiliary class **`dynamicObject`** recebe **`entryTTL`** (contagem regressiva em segundos) e **`msDS-Entry-Time-To-Die`** (expiração absoluta). Quando `entryTTL` chega a 0 o **Garbage Collector o apaga sem tombstone/recycle-bin**, eliminando criador/timestamps e impedindo recuperação.
- O TTL pode ser renovado atualizando `entryTTL`; mínimos/padrões são aplicados em **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (suporta 1s–1y, mas comumente padrão é 86.400s/24h). Objetos dinâmicos são **não suportados nas partições Configuration/Schema**.
- A exclusão pode atrasar alguns minutos em DCs com uptime curto (<24h), deixando uma janela estreita para consultar/fazer backup de atributos. Detecte alertando sobre **novos objetos contendo `entryTTL`/`msDS-Entry-Time-To-Die`** e correlacionando com SIDs órfãos/links quebrados.

## Evasão de MAQ com Computadores Auto-Destrutivos

- O padrão **`ms-DS-MachineAccountQuota` = 10** permite que qualquer usuário autenticado crie computadores. Adicione `dynamicObject` durante a criação para que o computador se auto-exclua e **libere a vaga de quota** enquanto apaga evidências.
- Ajuste Powermad dentro de `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- TTL curto (ex.: 60s) frequentemente falha para usuários padrão; o AD recai para **`DynamicObjectDefaultTTL`** (exemplo: 86.400s). ADUC pode ocultar `entryTTL`, mas consultas LDP/LDAP o revelam.

## Associação Primária de Grupo Furtiva

- Crie um **grupo de segurança dinâmico**, então defina o **`primaryGroupID`** de um usuário para o RID desse grupo para obter associação efetiva que **não aparece em `memberOf`** mas é considerada em tokens Kerberos/acesso.
- Quando o TTL expira **o grupo é excluído apesar da proteção de exclusão de primary-group**, deixando o usuário com um `primaryGroupID` corrompido apontando para um RID inexistente e sem tombstone para investigar como o privilégio foi concedido.

## Poluição de SIDs-Órfãos no AdminSDHolder

- Adicione ACEs para um **usuário/grupo dinâmico de curta duração** em **`CN=AdminSDHolder,CN=System,...`**. Após a expiração do TTL o SID torna-se **irresolúvel (“Unknown SID”)** no ACL template, e o **SDProp (~60 min)** propaga esse SID órfão por todos os objetos protegidos Tier-0.
- A perícia perde atribuição porque o principal sumiu (sem DN de objeto excluído). Monitore por **novos principals dinâmicos + SIDs órfãos súbitos no AdminSDHolder/ACLs privilegiadas**.

## Execução Dinâmica de GPO com Evidência Auto-Destrutiva

- Crie um objeto **`groupPolicyContainer`** dinâmico com um malicioso **`gPCFileSysPath`** (ex.: SMB share ao estilo GPODDITY) e **linke via `gPLink`** para a OU alvo.
- Os clientes processam a policy e puxam conteúdo do SMB do atacante. Quando o TTL expira, o objeto GPO (e `gPCFileSysPath`) desaparece; só resta um **`gPLink`** GUID quebrado, removendo evidência LDAP do payload executado.

## Redirecionamento Efêmero de DNS Integrado ao AD

- Registros DNS do AD são objetos **`dnsNode`** em **DomainDnsZones/ForestDnsZones**. Criá-los como **dynamic objects** permite redirecionamento temporário de hosts (captura de credenciais/MITM). Os clientes cacheiam a resposta A/AAAA maliciosa; o registro depois se auto-exclui deixando a zona limpa (DNS Manager pode precisar recarregar a zona para atualizar a visualização).
- Detecção: alerte sobre **qualquer registro DNS contendo `dynamicObject`/`entryTTL`** via replicação/logs de evento; registros transitórios raramente aparecem em logs DNS padrão.

## Lacuna de Delta-Sync Híbrida do Entra ID (Nota)

- Entra Connect delta sync depende de **tombstones** para detectar exclusões. Um **usuário on-prem dinâmico** pode sincronizar para Entra ID, expirar e ser excluído sem tombstone — o delta sync não removerá a conta cloud, deixando um **usuário Entra órfão e ativo** até que um **full sync** manual seja forçado.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
