# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Windowsでは、OneDriveフォルダーは `\Users\<username>\AppData\Local\Microsoft\OneDrive` にあります。また、`logs\Personal` 内には、同期されたファイルに関する興味深いデータを含む `SyncDiagnostics.log` ファイルがあります。

- バイト単位のサイズ
- 作成日時
- 更新日時
- cloud内のファイル数
- フォルダー内のファイル数
- **CID**: OneDriveユーザーの一意のID
- レポート生成時刻
- OSのHDのサイズ

CIDを見つけたら、**このIDを含むファイルを検索する**ことを推奨します。_**\<CID>.ini**_ や _**\<CID>.dat**_ という名前のファイルが見つかる可能性があり、これらにはOneDriveと同期されたファイル名などの興味深い情報が含まれている場合があります。

## Google Drive

Windowsでは、Google Driveのメインフォルダーは `\Users\<username>\AppData\Local\Google\Drive\user_default`\
にあります。このフォルダーには `Sync_log.log` というファイルがあり、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報が含まれています。削除されたファイルも、対応するMD5とともにこのログファイルに記録されています。

**`Cloud_graph\Cloud_graph.db`** ファイルは、**`cloud_graph_entry`** テーブルを含むsqliteデータベースです。このテーブルには、**同期された** **ファイル**の**名前**、更新時刻、サイズ、ファイルのMD5チェックサムがあります。

データベース **`Sync_config.db`** のテーブルデータには、アカウントのメールアドレス、共有フォルダーのパス、Google Driveのバージョンが含まれています。

## Dropbox

Dropboxはファイルを管理するために **SQLite databases** を使用します。この\
データベースは以下のフォルダーにあります。

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主なデータベースは以下のとおりです。

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

「.dbx」拡張子は、**databases** が**暗号化**されていることを意味します。Dropboxは **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)) を使用します。

Dropboxが使用する暗号化について詳しく理解するには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) を参照してください。<sup>[[1]](#references)[[2]](#references)</sup>

ただし、主な情報は次のとおりです。<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

この情報とは別に、データベースを復号するには、引き続き以下が必要です。<sup>[[2]](#references)</sup>

- **暗号化されたDPAPI key**: レジストリ内の `NTUSER.DAT\Software\Dropbox\ks\client` にあります（このデータをバイナリとしてエクスポートします）
- **`SYSTEM`** および **`SECURITY`** ハイブ
- **DPAPI master keys**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
- Windowsユーザーの**ユーザー名**と**パスワード**

次に、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: 次にDataProtectionDecryptorツールを使用します](<../../../images/image (443).png>)

すべてが期待どおりに進めば、このツールは、**元のkeyを復元するために使用する**必要がある**primary key**を表示します。元のkeyを復元するには、この [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) を使用し、receipt内の「passphrase」としてprimary keyを入力します。

結果として得られるhexが、databasesの暗号化に使用される最終keyです。これは次の方法で復号できます。
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** データベースには、以下の情報が含まれています。

- **Email**: ユーザーのメールアドレス
- **usernamedisplayname**: ユーザー名
- **dropbox_path**: Dropbox フォルダーの場所
- **Host_id: Hash** クラウドへの認証に使用される Hash。これは Web からのみ revoke できます。
- **Root_ns**: ユーザー識別子

**`filecache.db`** データベースには、Dropbox と同期されたすべてのファイルおよびフォルダーに関する情報が含まれています。`File_journal` テーブルには、より有用な情報が含まれています。

- **Server_path**: server 内でファイルが配置されているパス（このパスの前にはクライアントの `host_id` が付加されます）。
- **local_sjid**: ファイルのバージョン
- **local_mtime**: 変更日時
- **local_ctime**: 作成日時

このデータベース内のその他のテーブルには、さらに興味深い情報が含まれています。

- **block_cache**: Dropbox のすべてのファイルおよびフォルダーの Hash
- **block_ref**: `block_cache` テーブルの Hash ID と、`file_journal` テーブルのファイル ID の関連付け
- **mount_table**: Dropbox の共有フォルダー
- **deleted_fields**: Dropbox で削除されたファイル
- **date_added**

## References

- [1] [Dropbox ソフトウェアセキュリティの重大な分析（hack.lu 2012）](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption の復習](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
