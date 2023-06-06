# Armazenamento Local na Nuvem

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas da comunidade mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

No Windows, você pode encontrar a pasta do OneDrive em `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E dentro de `logs\Personal`, é possível encontrar o arquivo `SyncDiagnostics.log`, que contém alguns dados interessantes sobre os arquivos sincronizados:

* Tamanho em bytes
* Data de criação
* Data de modificação
* Número de arquivos na nuvem
* Número de arquivos na pasta
* **CID**: ID exclusivo do usuário do OneDrive
* Hora de geração do relatório
* Tamanho do HD do sistema operacional

Depois de encontrar o CID, é recomendável **procurar arquivos que contenham este ID**. Você pode ser capaz de encontrar arquivos com o nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ que podem conter informações interessantes, como os nomes dos arquivos sincronizados com o OneDrive.

## Google Drive

No Windows, você pode encontrar a pasta principal do Google Drive em `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta pasta contém um arquivo chamado Sync\_log.log com informações como o endereço de e-mail da conta, nomes de arquivos, carimbos de data/hora, hashes MD5 dos arquivos, etc. Até mesmo arquivos excluídos aparecem no arquivo de log com seu MD5 correspondente.

O arquivo **`Cloud_graph\Cloud_graph.db`** é um banco de dados sqlite que contém a tabela **`cloud_graph_entry`**. Nesta tabela, você pode encontrar o **nome** dos **arquivos sincronizados**, hora de modificação, tamanho e o checksum MD5 dos arquivos.

Os dados da tabela do banco de dados **`Sync_config.db`** contêm o endereço de e-mail da conta, o caminho das pastas compartilhadas e a versão do Google Drive.

## Dropbox

O Dropbox usa **bancos de dados SQLite** para gerenciar os arquivos. Neste\
Você pode encontrar os bancos de dados nas pastas:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

E os principais bancos de dados são:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

A extensão ".dbx" significa que os **bancos de dados** são **criptografados**. O Dropbox usa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Para entender melhor a criptografia que o Dropbox usa, você pode ler [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

No entanto, as principais informações são:

* **Entropia**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritmo**: PBKDF2
* **Iterações**: 1066

Além dessas informações, para descriptografar os bancos de dados, você ainda precisa de:

* A **chave DPAPI criptografada**: Você pode encontrá-la no registro dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporte esses dados como binário)
* Os arquivos **`SYSTEM`** e **`SECURITY`**
* As **chaves mestras DPAPI**: Que podem ser encontradas em `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* O **nome de usuário** e a **senha** do usuário do Windows

Em seguida, você pode usar a ferramenta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Se tudo correr como esperado, a ferramenta indicará a **chave primária** que você precisa **usar para recuperar a original**. Para recuperar a original, basta usar este [recibo do cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) colocando a chave primária como a "senha" dentro do recibo.

O resultado em hexadecimal é a chave final usada para criptografar os bancos de dados que podem ser descriptografados com:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
O banco de dados **`config.dbx`** contém:

* **Email**: O e-mail do usuário
* **usernamedisplayname**: O nome do usuário
* **dropbox\_path**: O caminho onde a pasta do Dropbox está localizada
* **Host\_id: Hash** usado para autenticar na nuvem. Isso só pode ser revogado pela web.
* **Root\_ns**: Identificador do usuário

O banco de dados **`filecache.db`** contém informações sobre todos os arquivos e pastas sincronizados com o Dropbox. A tabela `File_journal` é a que contém mais informações úteis:

* **Server\_path**: O caminho onde o arquivo está localizado dentro do servidor (este caminho é precedido pelo `host_id` do cliente).
* **local\_sjid**: A versão do arquivo
* **local\_mtime**: Data de modificação
* **local\_ctime**: Data de criação

Outras tabelas dentro deste banco de dados contêm informações mais interessantes:

* **block\_cache**: Hash de todos os arquivos e pastas do Dropbox
* **block\_ref**: Relaciona o ID de hash da tabela `block_cache` com o ID do arquivo na tabela `file_journal`
* **mount\_table**: Compartilhamento de pastas do Dropbox
* **deleted\_fields**: Arquivos excluídos do Dropbox
* **date\_added**

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
