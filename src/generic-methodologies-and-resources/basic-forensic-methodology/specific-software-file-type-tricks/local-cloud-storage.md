# Armazenamento em Nuvem Local

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

No Windows, você pode encontrar a pasta do OneDrive em `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E dentro de `logs\Personal` é possível encontrar o arquivo `SyncDiagnostics.log` que contém alguns dados interessantes sobre os arquivos sincronizados:

- Tamanho em bytes
- Data de criação
- Data de modificação
- Número de arquivos na nuvem
- Número de arquivos na pasta
- **CID**: ID único do usuário do OneDrive
- Hora de geração do relatório
- Tamanho do HD do SO

Uma vez que você tenha encontrado o CID, é recomendado **procurar arquivos contendo esse ID**. Você pode ser capaz de encontrar arquivos com o nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ que podem conter informações interessantes como os nomes dos arquivos sincronizados com o OneDrive.

## Google Drive

No Windows, você pode encontrar a pasta principal do Google Drive em `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta pasta contém um arquivo chamado Sync_log.log com informações como o endereço de e-mail da conta, nomes de arquivos, timestamps, hashes MD5 dos arquivos, etc. Até arquivos deletados aparecem nesse arquivo de log com seu correspondente MD5.

O arquivo **`Cloud_graph\Cloud_graph.db`** é um banco de dados sqlite que contém a tabela **`cloud_graph_entry`**. Nesta tabela, você pode encontrar o **nome** dos **arquivos sincronizados**, hora de modificação, tamanho e o checksum MD5 dos arquivos.

Os dados da tabela do banco de dados **`Sync_config.db`** contêm o endereço de e-mail da conta, o caminho das pastas compartilhadas e a versão do Google Drive.

## Dropbox

O Dropbox usa **bancos de dados SQLite** para gerenciar os arquivos. Neste\
Você pode encontrar os bancos de dados nas pastas:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

E os principais bancos de dados são:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

A extensão ".dbx" significa que os **bancos de dados** estão **criptografados**. O Dropbox usa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Para entender melhor a criptografia que o Dropbox usa, você pode ler [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

No entanto, as principais informações são:

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iterações**: 1066

Além dessas informações, para descriptografar os bancos de dados, você ainda precisa:

- A **chave DPAPI criptografada**: Você pode encontrá-la no registro dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporte esses dados como binário)
- Os **hives** **`SYSTEM`** e **`SECURITY`**
- As **chaves mestras DPAPI**: Que podem ser encontradas em `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- O **nome de usuário** e **senha** do usuário do Windows

Então você pode usar a ferramenta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

Se tudo correr como esperado, a ferramenta indicará a **chave primária** que você precisa **usar para recuperar a original**. Para recuperar a original, basta usar esta [receita do cyber_chef](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) colocando a chave primária como a "senha" dentro da receita.

O hex resultante é a chave final usada para criptografar os bancos de dados que pode ser descriptografada com:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
O **`config.dbx`** banco de dados contém:

- **Email**: O email do usuário
- **usernamedisplayname**: O nome do usuário
- **dropbox_path**: Caminho onde a pasta do dropbox está localizada
- **Host_id: Hash** usado para autenticar no cloud. Isso só pode ser revogado pela web.
- **Root_ns**: Identificador do usuário

O **`filecache.db`** banco de dados contém informações sobre todos os arquivos e pastas sincronizados com Dropbox. A tabela `File_journal` é a que contém mais informações úteis:

- **Server_path**: Caminho onde o arquivo está localizado dentro do servidor (este caminho é precedido pelo `host_id` do cliente).
- **local_sjid**: Versão do arquivo
- **local_mtime**: Data de modificação
- **local_ctime**: Data de criação

Outras tabelas dentro deste banco de dados contêm informações mais interessantes:

- **block_cache**: hash de todos os arquivos e pastas do Dropbox
- **block_ref**: Relaciona o ID do hash da tabela `block_cache` com o ID do arquivo na tabela `file_journal`
- **mount_table**: Pastas compartilhadas do dropbox
- **deleted_fields**: Arquivos deletados do Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
