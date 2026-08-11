# Armazenamento Local na Nuvem

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

No Windows, você pode encontrar a pasta do OneDrive em `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E dentro de `logs\Personal`, é possível encontrar o arquivo `SyncDiagnostics.log`, que contém alguns dados interessantes sobre os arquivos sincronizados:<sup>[[3]](#references)</sup>

- Tamanho em bytes
- Data de criação
- Data de modificação
- Número de arquivos na nuvem
- Número de arquivos na pasta
- **CID**: ID exclusivo do usuário do OneDrive
- Hora de geração do relatório
- Tamanho do HD do sistema operacional

Depois de encontrar o CID, é recomendado **procurar arquivos que contenham esse ID**. Você poderá encontrar arquivos com os nomes: _**\<CID>.ini**_ e _**\<CID>.dat**_, que podem conter informações interessantes, como os nomes dos arquivos sincronizados com o OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

No Windows, você pode encontrar a pasta principal do Google Drive em `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Essa pasta contém um arquivo chamado Sync_log.log, que registra sessões de sincronização do cliente do Google Drive e eventos de criação, modificação e exclusão de arquivos.<sup>[[4]](#references)[[6]](#references)</sup>

O arquivo **`Cloud_graph\Cloud_graph.db`** é um banco de dados sqlite.<sup>[[6]](#references)</sup> Ele contém a tabela **`cloud_graph_entry`**. Nessa tabela, você pode encontrar o **nome** dos **arquivos** **sincronizados**, a hora de modificação, o tamanho e o checksum MD5 dos arquivos.

A tabela **`cloud_entry`** do banco de dados relacionado **`snapshot.db`** pode reter registros removidos com nomes de arquivos, timestamps, tamanhos e checksums.<sup>[[4]](#references)</sup>

Os dados da tabela do banco de dados **`Sync_config.db`** contêm o endereço de e-mail da conta, o caminho das pastas compartilhadas e a versão do Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

O Dropbox usa **bancos de dados SQLite** para gerenciar os arquivos.<sup>[[2]](#references)</sup> Neste\
Você pode encontrar os bancos de dados nas pastas:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

E os principais bancos de dados são:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

A extensão ".dbx" significa que os **bancos de dados** são **criptografados**. O Dropbox usa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Para entender melhor a criptografia usada pelo Dropbox, você pode ler [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

No entanto, as informações principais são:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iterações**: 1066

Além dessas informações, para descriptografar os bancos de dados, você ainda precisa de:<sup>[[2]](#references)</sup>

- A **chave DPAPI criptografada**: você pode encontrá-la no registro, dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporte esses dados como binário)
- As hives **`SYSTEM`** e **`SECURITY`**
- As **chaves mestras DPAPI**: que podem ser encontradas em `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- O **nome de usuário** e a **senha** do usuário do Windows

Em seguida, você pode usar a ferramenta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Em seguida, você pode usar a ferramenta DataProtectionDecryptor](<../../../images/image (443).png>)

Se tudo ocorrer conforme esperado, a ferramenta indicará a **chave primária** que você precisa **usar para recuperar a original**. Para recuperar a chave original, basta usar esta [receita do cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) inserindo a chave primária como a "passphrase" dentro da receita.

O hex resultante é a chave final usada para criptografar os bancos de dados, que podem ser descriptografados com:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
A base de dados **`config.dbx`** contém:

- **Email**: O email do utilizador
- **usernamedisplayname**: O nome do utilizador
- **dropbox_path**: Caminho onde a pasta do dropbox está localizada
- **Host_id: Hash** utilizado para autenticar na cloud. Isto só pode ser revogado a partir da web.
- **Root_ns**: Identificador do utilizador

A base de dados **`filecache.db`** contém informações sobre todos os ficheiros e pastas sincronizados com o Dropbox. A tabela `File_journal` é a que contém informações mais úteis:<sup>[[5]](#references)</sup>

- **Server_path**: Caminho onde o ficheiro está localizado dentro do servidor (este caminho é precedido pelo `host_id` do cliente).
- **local_sjid**: Versão do ficheiro
- **local_mtime**: Data de modificação
- **local_ctime**: Data de criação

Outras tabelas dentro desta base de dados contêm informações mais interessantes:

- **block_cache**: hash de todos os ficheiros e pastas do Dropbox
- **block_ref**: Relaciona o ID do hash da tabela `block_cache` com o ID do ficheiro na tabela `file_journal`
- **mount_table**: Pastas partilhadas do dropbox
- **deleted_fields**: Ficheiros eliminados do Dropbox
- **date_added**

## References

- [1] [Uma análise crítica da segurança do software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Revisão da desencriptação do Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Análise forense de Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Caso de fuga de dados NIST CFReDS: Respostas sobre a fuga](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Análise forense do Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefactos da utilização do Google Drive no Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
