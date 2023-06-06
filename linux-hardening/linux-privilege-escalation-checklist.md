# Checklist - Escalação de Privilégios no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).​

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novos programas de recompensas por bugs

💬 Participe de discussões na comunidade

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do sistema](privilege-escalation/#system-information)

* [ ] Obtenha informações do **sistema operacional**
* [ ] Verifique o [**PATH**](privilege-escalation/#path), alguma pasta **gravável**?
* [ ] Verifique as [**variáveis de ambiente**](privilege-escalation/#env-info), algum detalhe sensível?
* [ ] Procure por [**exploits do
