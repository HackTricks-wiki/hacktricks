# ローカルクラウドストレージ

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windowsでは、OneDriveフォルダーは `\Users\<username>\AppData\Local\Microsoft\OneDrive` にあります。そして `logs\Personal` 内には、同期されたファイルに関する興味深いデータを含む `SyncDiagnostics.log` ファイルがあります：

- バイト単位のサイズ
- 作成日
- 修正日
- クラウド内のファイル数
- フォルダー内のファイル数
- **CID**: OneDriveユーザーのユニークID
- レポート生成時間
- OSのHDのサイズ

CIDを見つけたら、**このIDを含むファイルを検索することをお勧めします**。_**\<CID>.ini**_ や _**\<CID>.dat**_ という名前のファイルが見つかるかもしれません。これらのファイルには、OneDriveと同期されたファイルの名前などの興味深い情報が含まれている可能性があります。

## Google Drive

Windowsでは、主要なGoogle Driveフォルダーは `\Users\<username>\AppData\Local\Google\Drive\user_default` にあります。このフォルダーには、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報を含む `Sync_log.log` というファイルがあります。削除されたファイルも、そのログファイルに対応するMD5と共に表示されます。

**`Cloud_graph\Cloud_graph.db`** ファイルはsqliteデータベースで、**`cloud_graph_entry`** テーブルを含んでいます。このテーブルには、**同期された** **ファイル**の**名前**、修正時間、サイズ、ファイルのMD5チェックサムが含まれています。

データベース **`Sync_config.db`** のテーブルデータには、アカウントのメールアドレス、共有フォルダーのパス、Google Driveのバージョンが含まれています。

## Dropbox

Dropboxは**SQLiteデータベース**を使用してファイルを管理しています。この中で、データベースは以下のフォルダーにあります：

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主要なデータベースは次のとおりです：

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx"拡張子は、**データベース**が**暗号化されている**ことを意味します。Dropboxは**DPAPI**を使用しています（[https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropboxが使用している暗号化をよりよく理解するには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を読むことができます。

しかし、主な情報は次のとおりです：

- **エントロピー**: d114a55212655f74bd772e37e64aee9b
- **ソルト**: 0D638C092E8B82FC452883F95F355B8E
- **アルゴリズム**: PBKDF2
- **反復回数**: 1066

その情報に加えて、データベースを復号化するには、次のものが必要です：

- **暗号化されたDPAPIキー**: レジストリ内の `NTUSER.DAT\Software\Dropbox\ks\client` で見つけることができます（このデータをバイナリとしてエクスポート）
- **`SYSTEM`** および **`SECURITY`** ハイブ
- **DPAPIマスタキー**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
- Windowsユーザーの**ユーザー名**と**パスワード**

その後、ツール [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**を使用できます：**

![](<../../../images/image (443).png>)

すべてが期待通りに進めば、ツールは**元のものを復元するために使用する必要がある主キー**を示します。元のものを復元するには、この[cyber_chefレシピ](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)を使用し、主キーをレシピ内の「パスフレーズ」として入力します。

得られた16進数は、データベースを暗号化するために使用される最終キーであり、次のように復号化できます：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** データベースには以下が含まれています：

- **Email**: ユーザーのメール
- **usernamedisplayname**: ユーザーの名前
- **dropbox_path**: Dropboxフォルダがあるパス
- **Host_id: Hash**: クラウドへの認証に使用されるハッシュ。このハッシュはウェブからのみ取り消すことができます。
- **Root_ns**: ユーザー識別子

**`filecache.db`** データベースには、Dropboxと同期されたすべてのファイルとフォルダに関する情報が含まれています。`File_journal` テーブルが最も有用な情報を持っています：

- **Server_path**: サーバー内のファイルがあるパス（このパスはクライアントの `host_id` によって前置されます）。
- **local_sjid**: ファイルのバージョン
- **local_mtime**: 修正日
- **local_ctime**: 作成日

このデータベース内の他のテーブルには、さらに興味深い情報が含まれています：

- **block_cache**: Dropboxのすべてのファイルとフォルダのハッシュ
- **block_ref**: `block_cache` テーブルのハッシュIDと `file_journal` テーブルのファイルIDを関連付ける
- **mount_table**: Dropboxの共有フォルダ
- **deleted_fields**: Dropboxで削除されたファイル
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
