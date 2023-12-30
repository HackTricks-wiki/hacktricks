# ローカルクラウドストレージ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールを搭載したワークフローを簡単に**自動化**する。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windowsでは、OneDriveフォルダは`\Users\<username>\AppData\Local\Microsoft\OneDrive`にあります。そして、`logs\Personal`内にある`SyncDiagnostics.log`ファイルには、同期されたファイルに関する興味深いデータが含まれています：

* バイト単位のサイズ
* 作成日
* 変更日
* クラウド内のファイル数
* フォルダ内のファイル数
* **CID**: OneDriveユーザーのユニークID
* レポート生成時間
* OSのHDのサイズ

CIDを見つけたら、このIDを含むファイルを**検索する**ことをお勧めします。_**\<CID>.ini**_ と _**\<CID>.dat**_ という名前のファイルを見つけることができるかもしれません。これらのファイルには、OneDriveと同期されたファイルの名前などの興味深い情報が含まれている可能性があります。

## Google Drive

Windowsでは、メインのGoogle Driveフォルダは`\Users\<username>\AppData\Local\Google\Drive\user_default`にあります。\
このフォルダにはSync\_log.logというファイルが含まれており、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報が含まれています。削除されたファイルもその対応するMD5と共にログファイルに表示されます。

ファイル**`Cloud_graph\Cloud_graph.db`**はsqliteデータベースであり、このデータベースには**`cloud_graph_entry`**というテーブルが含まれています。このテーブルでは、**同期された** **ファイル**の**名前**、変更時間、サイズ、ファイルのMD5チェックサムを見つけることができます。

データベース**`Sync_config.db`**のテーブルデータには、アカウントのメールアドレス、共有フォルダのパス、Google Driveのバージョンが含まれています。

## Dropbox

Dropboxは**SQLiteデータベース**を使用してファイルを管理します。この\
データベースは以下のフォルダにあります：

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

そして、主なデータベースは以下の通りです：

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx"拡張子は、**データベース**が**暗号化されている**ことを意味します。Dropboxは**DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))を使用しています。

Dropboxが使用している暗号化についてよりよく理解するためには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を読むことができます。

しかし、主な情報は以下の通りです：

* **エントロピー**: d114a55212655f74bd772e37e64aee9b
* **ソルト**: 0D638C092E8B82FC452883F95F355B8E
* **アルゴリズム**: PBKDF2
* **反復回数**: 1066

それらの情報に加えて、データベースを復号化するにはまだ必要です：

* **暗号化されたDPAPIキー**: `NTUSER.DAT\Software\Dropbox\ks\client`のレジストリ内で見つけることができます（このデータをバイナリとしてエクスポートします）
* **`SYSTEM`** と **`SECURITY`** ハイブ
* **DPAPIマスターキー**: `\Users\<username>\AppData\Roaming\Microsoft\Protect`で見つけることができます
* Windowsユーザーの**ユーザー名**と**パスワード**

その後、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**を使用できます：

![](<../../../.gitbook/assets/image (448).png>)

すべてが期待通りに進むと、ツールは元のものを回復するために使用する必要がある**プライマリキー**を示します。元のものを回復するには、この[cyber_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D))を使用し、レシート内の"passphrase"としてプライマリキーを入れます。

結果として得られる16進数は、データベースを暗号化するために使用される最終キーであり、以下で復号化できます：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** データベースには以下が含まれます:

* **Email**: ユーザーのメールアドレス
* **usernamedisplayname**: ユーザーの名前
* **dropbox\_path**: Dropboxフォルダのパス
* **Host\_id: Hash**: クラウドへの認証に使用される。これはウェブからのみ無効にできる。
* **Root\_ns**: ユーザー識別子

**`filecache.db`** データベースにはDropboxと同期された全てのファイルとフォルダに関する情報が含まれます。`File_journal` テーブルには特に有用な情報があります:

* **Server\_path**: サーバー内のファイルのパス（このパスはクライアントの `host_id` によって先行される）。
* **local\_sjid**: ファイルのバージョン
* **local\_mtime**: 変更日
* **local\_ctime**: 作成日

このデータベース内の他のテーブルにはさらに興味深い情報が含まれます:

* **block\_cache**: Dropboxの全ファイルとフォルダのハッシュ
* **block\_ref**: `block_cache` テーブルのハッシュIDを `file_journal` テーブルのファイルIDと関連付ける
* **mount\_table**: Dropboxの共有フォルダ
* **deleted\_fields**: Dropboxの削除されたファイル
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も先進的なコミュニティツールを駆使した **ワークフローを簡単に構築し自動化** します。\
今すぐアクセス:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい**、または **HackTricksをPDFでダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**テレグラムグループ**](https://t.me/peass) に参加する、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** のGitHubリポジトリ [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) にPRを提出して、あなたのハッキングのコツを共有する。

</details>
