# Pickle Rick

## Pickle Rick

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../../.gitbook/assets/picklerick.gif)

Esta máquina foi categorizada como fácil e foi bastante fácil.

## Enumeração

Comecei **enumerando a máquina usando minha ferramenta** [**Legion**](https://github.com/carlospolop/legion):

![](<../../.gitbook/assets/image (79) (2).png>)

Como você pode ver, 2 portas estão abertas: 80 (**HTTP**) e 22 (**SSH**)

Então, executei o legion para enumerar o serviço HTTP:

![](<../../.gitbook/assets/image (234).png>)

Observe que na imagem você pode ver que `robots.txt` contém a string `Wubbalubbadubdub`

Depois de alguns segundos, revisei o que o `disearch` já descobriu:

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

E, como você pode ver na última imagem, uma **página de login** foi descoberta.

Verificando o código-fonte da página raiz, um nome de usuário é descoberto: `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Portanto, você pode fazer login na página de login usando as credenciais `R1ckRul3s:Wubbalubbadubdub`

## Usuário

Usando essas credenciais, você acessará um portal onde poderá executar comandos:

![](<../../.gitbook/assets/image (241).png>)

Alguns comandos como cat não são permitidos, mas você pode ler o primeiro ingrediente (flag) usando, por exemplo, grep:

![](<../../.gitbook/assets/image (242).png>)

Então eu usei:

![](<../../.gitbook/assets/image (243) (1).png>)

Para obter um shell reverso:

![](<../../.gitbook/assets/image (239) (1).png>)

O **segundo ingrediente** pode ser encontrado em `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Root

O usuário **www-data pode executar qualquer coisa como sudo**:

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
