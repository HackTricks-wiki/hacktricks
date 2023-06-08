## Informações básicas

Um pacote de instalação do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para instalar e executar corretamente.

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
## Privesc via abuso de pacotes pkg

### Execução a partir de diretórios públicos

Se um script de pré ou pós-instalação estiver executando, por exemplo, a partir de **`/var/tmp/Installerutil`**, um invasor pode controlar esse script para elevar privilégios sempre que for executado. Ou outro exemplo semelhante:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

## Referências

* [https://www.youtube.com/watch?v=iASSG0\_zobQ](https://www.youtube.com/watch?v=iASSG0\_zobQ)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
