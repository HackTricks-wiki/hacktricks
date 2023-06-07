# NTFS

## NTFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**New Technology File System**) é um sistema de arquivos de registro proprietário desenvolvido pela Microsoft.

O cluster é a menor unidade de tamanho no NTFS e o tamanho do cluster depende do tamanho de uma partição.

| Tamanho da partição | Setores por cluster | Tamanho do cluster |
| ------------------------ | ------------------- | ------------ |
| 512MB ou menos            | 1                   | 512 bytes    |
| 513MB-1024MB (1GB)       | 2                   | 1KB          |
| 1025MB-2048MB (2GB)      | 4                   | 2KB          |
| 2049MB-4096MB (4GB)      | 8                   | 4KB          |
| 4097MB-8192MB (8GB)      | 16                  | 8KB          |
| 8193MB-16,384MB (16GB)   | 32                  | 16KB         |
| 16,385MB-32,768MB (
### Timestamps NTFS

![](<../../../.gitbook/assets/image (512).png>)

Outra ferramenta útil para analisar o MFT é o [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (selecione o arquivo MFT ou a imagem e pressione dump all e extract para extrair todos os objetos).\
Este programa extrairá todos os dados do MFT e apresentará em formato CSV. Ele também pode ser usado para despejar arquivos.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

O arquivo **`$LOGFILE`** contém **logs** sobre as **ações** que foram **realizadas** **em** **arquivos**. Ele também **salva** a **ação** que precisaria ser executada em caso de um **refazer** e a ação necessária para **voltar** ao **estado** **anterior**.\
Esses logs são úteis para o MFT reconstruir o sistema de arquivos caso ocorra algum tipo de erro. O tamanho máximo deste arquivo é de **65536KB**.

Para inspecionar o `$LOGFILE`, você precisa extrair e inspecionar o `$MFT` anteriormente com o [**MFT2csv**](https://github.com/jschicht/Mft2Csv).\
Em seguida, execute o [**LogFileParser**](https://github.com/jschicht/LogFileParser) neste arquivo e selecione o arquivo `$LOGFILE` exportado e o CVS da inspeção do `$MFT`. Você obterá um arquivo CSV com os logs da atividade do sistema de arquivos registrados pelo log `$LOGFILE`.

![](<../../../.gitbook/assets/image (515).png>)

Filtrando por nomes de arquivos, você pode ver **todas as ações realizadas em relação a um arquivo**:

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

O arquivo `$EXTEND/$USNJnrl/$J` é um fluxo de dados alternativo do arquivo `$EXTEND$USNJnrl`. Este artefato contém um **registro de alterações produzidas dentro do volume NTFS com mais detalhes do que `$LOGFILE`**.

Para inspecionar este arquivo, você pode usar a ferramenta [**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv).

Filtrando pelo nome do arquivo, é possível ver **todas as ações realizadas em relação a um arquivo**. Além disso, você pode encontrar a `MFTReference` na pasta pai. Em seguida, olhando para essa `MFTReference`, você pode encontrar **informações da pasta pai**.

![](<../../../.gitbook/assets/image (516).png>)

### $I30

Cada **diretório** no sistema de arquivos contém um **atributo `$I30`** que deve ser mantido sempre que houver alterações no conteúdo do diretório. Quando arquivos ou pastas são removidos do diretório, os registros do índice `$I30` são reorganizados de acordo. No entanto, **a reorganização dos registros do índice pode deixar remanescentes da entrada de arquivo/pasta excluída dentro do espaço livre**. Isso pode ser útil na análise forense para identificar arquivos que podem ter existido no disco.

Você pode obter o arquivo `$I30` de um diretório do **FTK Imager** e inspecioná-lo com a ferramenta [Indx2Csv](https://github.com/jschicht/Indx2Csv).

![](<../../../.gitbook/assets/image (519).png>)

Com esses dados, você pode encontrar **informações sobre as alterações de arquivos realizadas dentro da pasta**, mas observe que o tempo de exclusão de um arquivo não é salvo dentro deste log. No entanto, você pode ver que a **última data modificada** do arquivo **`$I30`**, e se a **última ação realizada** sobre o diretório é a **exclusão** de um arquivo, os tempos podem ser os mesmos.

### $Bitmap

O **`$BitMap`** é um arquivo especial dentro do sistema de arquivos NTFS. Este arquivo mantém **o controle de todos os clusters usados e não utilizados** em um volume NTFS. Quando um arquivo ocupa espaço no volume NTFS, a localização usada é marcada no `$BitMap`.

![](<../../../.gitbook/assets/image (523).png>)

### ADS (fluxo de dados alternativo)

Fluxos de dados alternativos permitem que os arquivos contenham mais de um fluxo de dados. Todo arquivo tem pelo menos um fluxo de dados. No Windows, este fluxo de dados padrão é chamado de `:$DATA`.\
Nesta [página, você pode ver diferentes maneiras de criar/acessar/descobrir fluxos de dados alternativos](../../../windows-hardening/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream) do console. No passado, isso causou uma vulnerabilidade no IIS, pois as pessoas conseguiam acessar o código-fonte de uma página acessando o fluxo `:$DATA` como `http://www.alternate-data-streams.com/default.asp::$DATA`.

Usando a ferramenta [**AlternateStreamView**](https://www.nirsoft.net/utils/alternate\_data\_streams.html), você pode pesquisar e exportar todos os arquivos com algum ADS.

![](<../../../.gitbook/assets/image (518).png>)

Usando o FTK imager e clicando duas vezes em um arquivo com ADS, você pode **acessar os dados do ADS**:

![](<../../../.gitbook/assets/image (517).png>)

Se você encontrar um ADS chamado **`Zone.Identifier`** (veja a imagem acima), isso geralmente contém **informações sobre como o arquivo foi baixado**. Haveria um campo "ZoneId" com as seguintes informações:

* Zone ID = 0 -> Meu computador
* Zone ID = 1 -> Intranet
* Zone ID = 2 -> Confiável
* Zone ID = 3 -> Internet
* Zone ID = 4 -> Não confiável

Além disso, diferentes softwares podem armazenar informações adicionais:

| Software                                                            | Informação                                                                   |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Google Chrome, Opera, Vivaldi,                                      | ZoneId=3, ReferrerUrl, HostUrl                                               |
| Microsoft Edge                                                      | ZoneId=3, LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox, Tor browser, Outlook2016, Thunderbird, Windows Mail, Skype | ZoneId=3                                                                     |
| μTorrent                                                            | ZoneId=3, HostUrl=about:internet                                             |

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
