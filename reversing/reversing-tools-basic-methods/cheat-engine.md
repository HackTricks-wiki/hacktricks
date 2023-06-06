<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos na memória de um jogo em execução e alterá-los.\
Quando você o baixa e executa, é **apresentado** a um **tutorial** de como usar a ferramenta. Se você quiser aprender a usar a ferramenta, é altamente recomendável completá-lo.

# O que você está procurando?

![](<../../.gitbook/assets/image (580).png>)

Esta ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **é armazenado na memória** de um programa.\
**Geralmente, números** são armazenados em formato de **4 bytes**, mas você também pode encontrá-los em formatos de **double** ou **float**, ou pode querer procurar por algo **diferente de um número**. Por essa razão, você precisa ter certeza de que **seleciona** o que deseja **procurar**:

![](<../../.gitbook/assets/image (581).png>)

Você também pode indicar **diferentes** tipos de **pesquisas**:

![](<../../.gitbook/assets/image (582).png>)

Você também pode marcar a caixa para **parar o jogo enquanto examina a memória**:

![](<../../.gitbook/assets/image (584).png>)

## Teclas de atalho

Em _**Edit --> Settings --> Hotkeys**_ você pode definir diferentes **teclas de atalho** para diferentes propósitos, como **parar** o **jogo** (o que é bastante útil se em algum momento você quiser examinar a memória). Outras opções estão disponíveis:

![](<../../.gitbook/assets/image (583).png>)

# Modificando o valor

Uma vez que você **encontrou** onde está o **valor** que você está **procurando** (mais sobre isso nos próximos passos), você pode **modificá-lo** clicando duas vezes nele, depois clicando duas vezes em seu valor:

![](<../../.gitbook/assets/image (585).png>)

E finalmente **marcando a caixa** para que a modificação seja feita na memória:
