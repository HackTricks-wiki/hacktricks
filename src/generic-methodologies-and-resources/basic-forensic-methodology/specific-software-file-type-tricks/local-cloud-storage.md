# ローカルクラウドストレージ

{{#include ../../../banners/hacktricks-training.md}}

## ローカルストレージエミュレーターとアカウントキー

コンテナー内で動作する Azure 互換の Blob エミュレーターは、ストレージサービスが外部に公開されていなくても、ホストまたはブリッジネットワークから到達できる場合があります。読み取り可能なローカル設定やバックアップファイルのメタデータを確認し、アカウント名とキーを調べましょう。通常の列挙時にキーを表示するのは避けてください。[Azurite はカスタムのローカルアカウントキーに対応しています](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key 認証](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access)により、該当アカウントのデータへ広範なアクセスが許可される可能性があります。キーのファイルが見つかっただけでは、権限昇格が成立したことにはなりません。エンドポイントに到達できること、アカウントとキーが受け入れられること、そして対象の blob に、より高い権限を持つ ID の認証情報が実際に含まれていることを確認してください。SSH 秘密鍵が含まれている場合、その ID で対応する公開鍵が認可されており、SSH アクセスが許可されている必要があります。キーの漏えいが確認されたら、適切に保護し、ローテーションしてください。

## OneDrive

Windows では、OneDrive フォルダーは `\Users\<username>\AppData\Local\Microsoft\OneDrive` にあります。また、`logs\Personal` 内にある `SyncDiagnostics.log` ファイルには、同期されたファイルに関する興味深いデータが含まれている場合があります:<sup>[[3]](#references)</sup>

- バイト単位のサイズ
- 作成日時
- 更新日時
- クラウド内のファイル数
- フォルダー内のファイル数
- **CID**: OneDrive ユーザーの一意の ID
- レポート生成時刻
- OS の HD のサイズ

CID が見つかったら、**この ID を含むファイルを検索する**ことをおすすめします。_**\<CID>.ini**_ や _**\<CID>.dat**_ という名前のファイルが見つかり、OneDrive と同期されたファイル名などの興味深い情報が含まれている可能性があります。<sup>[[3]](#references)</sup>

## Google Drive

Windows では、Google Drive のメインフォルダーは `\Users\<username>\AppData\Local\Google\Drive\user_default` にあります。\
このフォルダーには `Sync_log.log` というファイルがあり、Google Drive クライアントの同期セッションや、ファイルの作成、変更、削除のイベントが記録されています。<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** ファイルは sqlite データベースです。<sup>[[6]](#references)</sup> このデータベースには **`cloud_graph_entry`** テーブルがあります。このテーブルでは、**同期された** **ファイル**の**名前**、更新日時、サイズ、MD5 チェックサムを確認できます。

関連する **`snapshot.db`** データベースの **`cloud_entry`** テーブルには、ファイル名、タイムスタンプ、サイズ、チェックサムが記録された削除済みのレコードが残っている場合があります。<sup>[[4]](#references)</sup>

**`Sync_config.db`** データベースのテーブルデータには、アカウントのメールアドレス、共有フォルダーのパス、Google Drive のバージョンが含まれています。<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox はファイル管理に **SQLite データベース**を使用します。<sup>[[2]](#references)</sup> この場合、\
データベースは次のフォルダーにあります。

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主なデータベースは次のとおりです。

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

「.dbx」拡張子は、**データベース**が**暗号化されている**ことを意味します。Dropbox は **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)) を使用します。<sup>[[1]](#references)</sup>

Dropbox が使用する暗号化について詳しく知るには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) を参照してください。<sup>[[1]](#references)[[2]](#references)</sup>

ただし、主な情報は次のとおりです。<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

これらの情報に加えて、データベースを復号するには、次のものが必要です。<sup>[[2]](#references)</sup>

- **暗号化された DPAPI キー**: レジストリの `NTUSER.DAT\Software\Dropbox\ks\client` にあります（このデータをバイナリとしてエクスポートしてください）
- **`SYSTEM`** ハイブと **`SECURITY`** ハイブ
- **DPAPI マスターキー**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
- Windows ユーザーの**ユーザー名**と**パスワード**

次に、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** ツールを使用できます。**

![Google Drive - Dropbox: 次に、DataProtectionDecryptor ツールを使用できます](<../../../images/image (443).png>)

すべてが想定どおりに進めば、このツールは**元のキーの復元に使用する**必要がある**プライマリキー**を表示します。元のキーを復元するには、この [cyber_chef レシピ](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) を使用し、レシピの「passphrase」にプライマリキーを入力してください。

結果として得られる hex がデータベースの暗号化に使われた最終キーです。次の方法で復号できます。<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

**`config.dbx`**データベースには、次の情報が含まれています。

- **Email**: ユーザーのメールアドレス
- **usernamedisplayname**: ユーザー名
- **dropbox_path**: Dropboxフォルダーの保存場所
- **Host_id: Hash**: クラウドへの認証に使用されるハッシュ。これはWebからのみ失効できます。
- **Root_ns**: ユーザー識別子

**`filecache.db`**データベースには、Dropboxと同期されたすべてのファイルとフォルダーに関する情報が含まれています。`File_journal`テーブルには、最も有用な情報が含まれています。<sup>[[5]](#references)</sup>

- **Server_path**: サーバー内でのファイルの保存場所（このパスの前にはクライアントの`host_id`が付加されます）。
- **local_sjid**: ファイルのバージョン
- **local_mtime**: 更新日時
- **local_ctime**: 作成日時

このデータベース内のその他のテーブルには、さらに興味深い情報が含まれています。

- **block_cache**: Dropbox内のすべてのファイルとフォルダーのハッシュ
- **block_ref**: `block_cache`テーブルのハッシュIDと`file_journal`テーブルのファイルIDを関連付けます
- **mount_table**: Dropboxの共有フォルダー
- **deleted_fields**: Dropboxで削除されたファイル
- **date_added**

## References

- [1] [Dropboxソフトウェアセキュリティの批判的分析 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBXの復号について再確認する](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [クラウドストレージのフォレンジック分析 (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDSデータ漏えい事例: 漏えいに関する回答](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropboxのフォレンジック](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [WindowsにおけるGoogle Drive利用の痕跡](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
