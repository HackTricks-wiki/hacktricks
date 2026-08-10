# Local Cloud Storage

## OneDrive

Windows では、OneDrive フォルダーは `\Users\<username>\AppData\Local\Microsoft\OneDrive` にあります。また、`logs\Personal` 内には、同期されたファイルに関する興味深いデータを含む `SyncDiagnostics.log` ファイルがあります:<sup>[[3]](#references)</sup>

- バイト単位のサイズ
- 作成日時
- 更新日時
- cloud 内のファイル数
- フォルダー内のファイル数
- **CID**: OneDrive ユーザーの一意の ID
- レポート生成時刻
- OS の HD のサイズ

CID を見つけたら、**この ID を含むファイルを検索する**ことを推奨します。_**\<CID>.ini**_ や _**\<CID>.dat**_ という名前のファイルが見つかる可能性があり、OneDrive と同期されたファイル名などの興味深い情報が含まれている場合があります。<sup>[[3]](#references)</sup>

## Google Drive

Windows では、Google Drive のメインフォルダーは `\Users\<username>\AppData\Local\Google\Drive\user_default` にあります\
このフォルダーには Sync_log.log というファイルがあり、Google Drive client の同期セッション、ならびにファイルの作成、変更、削除イベントが記録されています。<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** ファイルは sqlite database です。<sup>[[6]](#references)</sup> このファイルには **`cloud_graph_entry`** table が含まれています。この table では、**synchronized** **files** の **name**、変更時刻、サイズ、ファイルの MD5 checksum を確認できます。

関連する **`snapshot.db`** database の **`cloud_entry`** table には、ファイル名、timestamp、サイズ、checksum とともに削除されたレコードが保持されている場合があります。<sup>[[4]](#references)</sup>

**`Sync_config.db`** database の table data には、account の email address、shared folders の path、Google Drive version が含まれています。<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox はファイルを管理するために **SQLite databases** を使用します。<sup>[[2]](#references)</sup> この\
databases は次の folders にあります:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主な databases は次のとおりです:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

「.dbx」extension は、**databases** が **encrypted** であることを意味します。Dropbox は **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)) を使用します。<sup>[[1]](#references)</sup>

Dropbox が使用する encryption をより詳しく理解するには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) を参照してください。<sup>[[1]](#references)[[2]](#references)</sup>

ただし、主な情報は次のとおりです:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

この情報とは別に、databases を decrypt するには、次のものも必要です:<sup>[[2]](#references)</sup>

- **encrypted DPAPI key**: registry の `NTUSER.DAT\Software\Dropbox\ks\client` 内にあります（この data を binary として export します）
- **`SYSTEM`** および **`SECURITY`** hives
- **DPAPI master keys**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
- Windows user の **username** と **password**

次に、tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: 次に、tool DataProtectionDecryptor を使用します](<../../../images/image (443).png>)

すべてが期待どおりに進めば、tool は、**original one を recover するために使用する必要がある** **primary key** を示します。original one を recover するには、この [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) を使用し、receipt 内の「passphrase」として primary key を入力します。

生成された hex は databases の暗号化に使用された final key であり、次の方法で decrypt できます:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** データベースには以下が含まれます。

- **Email**: ユーザーのメールアドレス
- **usernamedisplayname**: ユーザー名
- **dropbox_path**: Dropbox フォルダーの場所
- **Host_id: Hash**: cloud への認証に使用される Hash。これは web からのみ revoke できます。
- **Root_ns**: ユーザー識別子

**`filecache.db`** データベースには、Dropbox と同期されたすべてのファイルおよびフォルダーに関する情報が含まれます。`File_journal` テーブルには、より有用な情報が含まれています。<sup>[[5]](#references)</sup>

- **Server_path**: server 内でファイルが存在するパス（このパスの前には client の `host_id` が付加されます）。
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

- [1] [Dropbox software security の批判的分析 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption の復習](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Leakage Answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows における Google Drive Usage の痕跡](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
