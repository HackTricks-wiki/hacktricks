<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Para uma avaliação de phishing, às vezes pode ser útil **clonar completamente um site**.

Observe que você também pode adicionar alguns payloads ao site clonado, como um gancho BeEF para "controlar" a guia do usuário.

Existem diferentes ferramentas que você pode usar para esse fim:

## wget
```text
wget -mk -nH
```
## goclone

O goclone é uma ferramenta que permite clonar um site inteiro, incluindo todas as páginas, imagens e arquivos relacionados. Ele pode ser usado para criar uma cópia exata de um site legítimo para fins de phishing.

Para usar o goclone, primeiro você precisa instalá-lo em sua máquina. Depois de instalado, você pode executar o comando `goclone` seguido do URL do site que deseja clonar. O goclone irá então baixar todas as páginas e arquivos relacionados e salvá-los em um diretório local.

Uma vez que o site foi clonado, você pode fazer alterações no código HTML para adicionar seu próprio código malicioso. Por exemplo, você pode adicionar um formulário de login falso que envia as credenciais do usuário para um servidor controlado por você.

É importante lembrar que clonar um site sem permissão é ilegal e pode resultar em consequências legais graves. O goclone deve ser usado apenas para fins de teste e com o consentimento do proprietário do site.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit de Ferramentas de Engenharia Social

---

### Clone a Website

### Clonar um Site

This technique consists of creating a copy of a website in order to deceive the victim into believing that they are accessing the legitimate site. This is a very common technique in phishing attacks.

Esta técnica consiste em criar uma cópia de um site para enganar a vítima fazendo-a acreditar que está acessando o site legítimo. Essa é uma técnica muito comum em ataques de phishing.

#### Cloning a Website with HTTrack

#### Clonando um Site com o HTTrack

HTTrack is a free and open-source web crawler and website downloader. It allows you to download a website from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer.

O HTTrack é um rastreador de web e baixador de sites gratuito e de código aberto. Ele permite que você baixe um site da Internet para um diretório local, construindo recursivamente todos os diretórios, obtendo HTML, imagens e outros arquivos do servidor para o seu computador.

To clone a website with HTTrack, follow these steps:

Para clonar um site com o HTTrack, siga estes passos:

1. Install HTTrack on your machine.

   1. Instale o HTTrack em sua máquina.

2. Open HTTrack and click on "Next".

   2. Abra o HTTrack e clique em "Next".

3. Enter a name for your project and click on "Next".

   3. Digite um nome para o seu projeto e clique em "Next".

4. Enter the URL of the website you want to clone and click on "Next".

   4. Digite a URL do site que você deseja clonar e clique em "Next".

5. Choose the options you want and click on "Next".

   5. Escolha as opções que deseja e clique em "Next".

6. Wait for the website to be cloned.

   6. Aguarde o site ser clonado.

7. Access the cloned website on your local machine.

   7. Acesse o site clonado em sua máquina local.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
