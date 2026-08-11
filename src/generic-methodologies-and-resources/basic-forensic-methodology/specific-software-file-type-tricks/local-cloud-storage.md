# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windowsでは、OneDriveフォルダを `\Users\<username>\AppData\Local\Microsoft\OneDrive` で確認できます。また、`logs\Personal` 内には、同期されたファイルに関する興味深いデータを含む `SyncDiagnostics.log` ファイルがあります:<sup>[[3]](#references)</sup>

- バイト単位のサイズ
- 作成日時
- 更新日時
- cloud内のファイル数
- フォルダ内のファイル数
- **CID**: OneDriveユーザーの一意のID
- レポート生成時刻
- OSのHDのサイズ

CIDを見つけたら、**このIDを含むファイルを検索する**ことを推奨します。ファイル名が _**\<CID>.ini**_ や _**\<CID>.dat**_ のファイルを見つけられる可能性があり、これらにはOneDriveと同期されたファイル名などの興味深い情報が含まれている場合があります。<sup>[[3]](#references)</sup>

## Google Drive

Windowsでは、Google Driveのメインフォルダを `\Users\<username>\AppData\Local\Google\Drive\user_default` で確認できます\
このフォルダには、Google Driveクライアントの同期セッション、およびファイルの作成、変更、削除イベントを記録する Sync_log.log というファイルがあります。<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** ファイルはsqlite databaseです。<sup>[[6]](#references)</sup> これには **`cloud_graph_entry`** テーブルが含まれています。このテーブルでは、**同期された** **ファイル**の**名前**、変更時刻、サイズ、ファイルのMD5 checksumを確認できます。

関連する **`snapshot.db`** databaseの **`cloud_entry`** テーブルには、ファイル名、タイムスタンプ、サイズ、checksumとともに削除されたレコードが保持される場合があります。<sup>[[4]](#references)</sup>

**`Sync_config.db`** databaseのテーブルデータには、アカウントのメールアドレス、共有フォルダのパス、Google Driveのバージョンが含まれています。<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropboxはファイルを管理するために **SQLite databases** を使用します。<sup>[[2]](#references)</sup> この\
databasesは次のフォルダにあります:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主なdatabasesは次のとおりです:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

「.dbx」拡張子は、**databases** が **暗号化**されていることを意味します。Dropboxは **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))を使用します。<sup>[[1]](#references)</sup>

Dropboxが使用する暗号化について詳しく理解するには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を参照してください。<sup>[[1]](#references)[[2]](#references)</sup>

ただし、主な情報は次のとおりです:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

この情報に加えて、databasesを復号するには、次のものも必要です:<sup>[[2]](#references)</sup>

- **暗号化されたDPAPI key**: registry内の `NTUSER.DAT\Software\Dropbox\ks\client` にあります（このデータをbinaryとしてexportします）
- **`SYSTEM`** および **`SECURITY`** hives
- **DPAPI master keys**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
- Windowsユーザーの**ユーザー名**と**パスワード**

次に、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**というtoolを使用できます:**

![Google Drive - Dropbox: 次に、DataProtectionDecryptorというtoolを使用できます](<../../../images/image (443).png>)

すべてが期待どおりに進めば、toolは、**元のkeyを復元するために使用する**必要がある**primary key**を示します。元のkeyを復元するには、この [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)を使用し、receipt内の「passphrase」としてprimary keyを入力します。

生成されたhexは、databasesの暗号化に使用される最終keyであり、次の方法で復号できます:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database には以下が含まれます。

- **Email**: ユーザーのメールアドレス
- **usernamedisplayname**: ユーザーの名前
- **dropbox_path**: Dropbox フォルダーが配置されているパス
- **Host_id: Hash**: cloud への認証に使用される Hash。これは Web からのみ revoke できます。
- **Root_ns**: ユーザー識別子

**`filecache.db`** database には、Dropbox と同期されたすべてのファイルおよびフォルダーに関する情報が含まれます。`File_journal` table が最も有用な情報を持っています。<sup>[[5]](#references)</sup>

- **Server_path**: server 内でファイルが配置されているパス（このパスの前には client の `host_id` が付加されます）。
- **local_sjid**: ファイルのバージョン
- **local_mtime**: 変更日時
- **local_ctime**: 作成日時

この database 内のその他の table には、さらに興味深い情報が含まれています。

- **block_cache**: Dropbox 内のすべてのファイルおよびフォルダーの hash
- **block_ref**: `block_cache` table の hash ID と `file_journal` table の file ID を関連付ける
- **mount_table**: Dropbox の共有フォルダー
- **deleted_fields**: Dropbox で削除されたファイル
- **date_added**

## References

- [1] [Dropbox software security の重大な分析 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption の復習](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Leakage Answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artifacts of Google Drive Usage in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
