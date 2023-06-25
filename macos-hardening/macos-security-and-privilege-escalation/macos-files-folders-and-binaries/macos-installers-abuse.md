## Informações Básicas do Pkg

Um **pacote de instalação** do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para instalar e executar corretamente.

O arquivo do pacote em si é um arquivo que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador de destino**. Ele também pode incluir **scripts** para executar tarefas antes e depois da instalação, como configurar arquivos de configuração ou limpar versões antigas do software.

### Hierarquia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribuição (xml)**: Personalizações (título, texto de boas-vindas...) e verificações de script/instalação
* **PackageInfo (xml)**: Informações, requisitos de instalação, local de instalação, caminhos para scripts a serem executados
* **Lista de materiais (bom)**: Lista de arquivos para instalar, atualizar ou remover com permissões de arquivo
* **Carga útil (arquivo CPIO compactado com gzip)**: Arquivos para instalar no `local-de-instalação` do PackageInfo
* **Scripts (arquivo CPIO compactado com gzip)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

### Descompactar
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Informações básicas sobre DMG

Os arquivos DMG, ou Apple Disk Images, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (ele contém seu próprio sistema de arquivos) que contém dados de bloco brutos normalmente compactados e às vezes criptografados. Quando você abre um arquivo DMG, o macOS o **monta como se fosse um disco físico**, permitindo que você acesse seu conteúdo.

### Hierarquia

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode ser diferente com base no conteúdo. No entanto, para DMGs de aplicativos, geralmente segue esta estrutura:

* Nível superior: este é a raiz da imagem do disco. Ele geralmente contém o aplicativo e possivelmente um link para a pasta Aplicativos.
* Aplicativo (.app): este é o aplicativo real. No macOS, um aplicativo é tipicamente um pacote que contém muitos arquivos e pastas individuais que compõem o aplicativo.
* Link de aplicativos: este é um atalho para a pasta Aplicativos no macOS. O objetivo disso é tornar fácil a instalação do aplicativo. Você pode arrastar o arquivo .app para este atalho para instalar o aplicativo.

## Privesc via abuso de pkg

### Execução de diretórios públicos

Se um script de pré ou pós-instalação estiver, por exemplo, executando de **`/var/tmp/Installerutil`**, um invasor poderia controlar esse script para que ele possa escalar privilégios sempre que for executado. Ou outro exemplo semelhante:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [função pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários instaladores e atualizadores chamarão para **executar algo como root**. Esta função aceita o **caminho** do **arquivo** a **executar** como parâmetro, no entanto, se um invasor pudesse **modificar** este arquivo, ele seria capaz de **abusar** de sua execução com root para **escalar privilégios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para mais informações, confira esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execução por montagem

Se um instalador escreve em `/tmp/fixedname/bla/bla`, é possível **criar uma montagem** em cima de `/tmp/fixedname` sem proprietários, para que você possa **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é **CVE-2021-26089**, que conseguiu **sobrescrever um script periódico** para obter a execução como root. Para mais informações, dê uma olhada na palestra: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Carga vazia

É possível gerar apenas um arquivo **`.pkg`** com **scripts de pré e pós-instalação** sem nenhuma carga útil.

### JS em xml de distribuição

É possível adicionar tags **`<script>`** no arquivo **xml de distribuição** do pacote e esse código será executado e pode **executar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
