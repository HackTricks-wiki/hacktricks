Se em algum momento você encontrar uma **página da web que apresenta informações confidenciais com base em sua sessão**: talvez esteja refletindo cookies, ou imprimindo detalhes de cartão de crédito ou qualquer outra informação confidencial, você pode tentar roubá-la.\
Aqui apresento as principais maneiras de tentar alcançá-lo:

* [**Bypass de CORS**](pentesting-web/cors-bypass.md): Se você puder contornar os cabeçalhos CORS, poderá roubar as informações realizando uma solicitação Ajax para uma página maliciosa.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Se você encontrar uma vulnerabilidade XSS na página, poderá abusar dela para roubar as informações.
* [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection.md): Se você não puder injetar tags XSS, ainda poderá roubar as informações usando outras tags HTML regulares.
* [**Clickjaking**](pentesting-web/clickjacking.md): Se não houver proteção contra esse ataque, você poderá enganar o usuário para enviar a você os dados confidenciais (um exemplo [aqui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo Discord** ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me no Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
