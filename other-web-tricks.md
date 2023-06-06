# Outros Truques da Web

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Cabeçalho do Host

Várias vezes, o back-end confia no **cabeçalho do Host** para realizar algumas ações. Por exemplo, ele pode usar o valor do cabeçalho como o **domínio para enviar uma redefinição de senha**. Então, quando você recebe um e-mail com um link para redefinir sua senha, o domínio que está sendo usado é aquele que você colocou no cabeçalho do Host. Então, você pode solicitar a redefinição de senha de outros usuários e alterar o domínio para um controlado por você para roubar seus códigos de redefinição de senha. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Observe que é possível que você nem precise esperar o usuário clicar no link de redefinição de senha para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.
{% endhint %}

### Booleanos de sessão

Às vezes, quando você completa alguma verificação corretamente, o back-end **apenas adiciona um booleano com o valor "True" a um atributo de segurança da sua sessão**. Em seguida, um endpoint diferente saberá se você passou com sucesso por essa verificação.\
No entanto, se você **passar na verificação** e sua sessão for concedida com o valor "True" no atributo de segurança, você pode tentar **acessar outros recursos** que **dependem do mesmo atributo** mas que você **não deveria ter permissões** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidade de registro

Tente se registrar como um usuário já existente. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

### Tomada de controle de e-mails

Registre um e-mail, antes de confirmá-lo, mude o e-mail. Então, se o novo e-mail de confirmação for enviado para o primeiro e-mail registrado, você pode assumir o controle de qualquer e-mail. Ou se você puder habilitar o segundo e-mail confirmando o primeiro, você também pode assumir o controle de qualquer conta.

### Acesso ao servicedesk interno de empresas usando atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Os desenvolvedores podem esquecer de desativar várias opções de depuração no ambiente de produção. Por exemplo, o método HTTP `TRACE` é projetado para fins de diagnóstico. Se ativado, o servidor web responderá a solicitações que usam o método `TRACE` ecoando na resposta a solicitação exata que foi recebida. Esse comportamento geralmente é inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de cabeçalhos de autenticação internos que podem ser anexados a solicitações por proxies reversos.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
