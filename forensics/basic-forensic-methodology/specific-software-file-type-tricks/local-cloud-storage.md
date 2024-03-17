# ローカルクラウドストレージ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windowsでは、OneDriveフォルダを`\Users\<username>\AppData\Local\Microsoft\OneDrive`で見つけることができます。そして、`logs\Personal`内にある`SyncDiagnostics.log`ファイルには、次のような興味深いデータが含まれています：

- バイト単位のサイズ
- 作成日
- 変更日
- クラウド内のファイル数
- フォルダ内のファイル数
- **CID**：OneDriveユーザーのユニークID
- レポート生成時刻
- OSのHDのサイズ

CIDを見つけたら、**このIDを含むファイルを検索**することが推奨されます。OneDriveと同期されたファイルの名前が含まれている可能性がある_**\<CID>.ini**_および_**\<CID>.dat**_という名前のファイルを見つけることができるかもしれません。

## Google Drive

Windowsでは、メインのGoogle Driveフォルダを`\Users\<username>\AppData\Local\Google\Drive\user_default`で見つけることができます。\
このフォルダには、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報が含まれたSync\_log.logというファイルが含まれています。削除されたファイルも、その対応するMD5とともにそのログファイルに表示されます。

ファイル**`Cloud_graph\Cloud_graph.db`**は、**`cloud_graph_entry`**というテーブルを含むsqliteデータベースで、このテーブルでは、**同期されたファイル**の**名前**、変更時間、サイズ、およびファイルのMD5チェックサムを見つけることができます。

データベース**`Sync_config.db`**のテーブルデータには、アカウントのメールアドレス、共有フォルダのパス、Google Driveのバージョンが含まれています。

## Dropbox

Dropboxはファイルを管理するために**SQLiteデータベース**を使用しています。\
これらのデータベースは次のフォルダにあります：

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

そして、主要なデータベースは次のとおりです：

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx"拡張子は、これらのデータベースが**暗号化**されていることを意味します。Dropboxは**DPAPI**を使用しています（[https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN)）

Dropboxが使用する暗号化をよりよく理解するためには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を読んでください。

ただし、主な情報は次のとおりです：

- **エントロピー**：d114a55212655f74bd772e37e64aee9b
- **ソルト**：0D638C092E8B82FC452883F95F355B8E
- **アルゴリズム**：PBKDF2
- **反復回数**：1066

その情報以外に、データベースを復号化するには以下が必要です：

- **暗号化されたDPAPIキー**：これは、`NTUSER.DAT\Software\Dropbox\ks\client`内のレジストリで見つけることができます（このデータをバイナリとしてエクスポートします）
- **`SYSTEM`**および**`SECURITY`**ハイブ
- **DPAPIマスターキー**：これは`\Users\<username>\AppData\Roaming\Microsoft\Protect`で見つけることができます
- Windowsユーザーの**ユーザー名**と**パスワード**

その後、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)****ツールを使用できます：

![](<../../../.gitbook/assets/image (448).png>)

すべてが予想通りに進むと、ツールは復元するために必要な**プライマリキー**を示します。元のキーを復元するには、この[cyber\_chefレシピ](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)を使用し、プライマリキーを受け取った「パスフレーズ」として設定します。

結果の16進数は、データベースを復号化するために使用される最終キーであり、次のように復号化できます：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`**データベースには次の情報が含まれています：

- **Email**: ユーザーのメールアドレス
- **usernamedisplayname**: ユーザーの名前
- **dropbox\_path**: Dropboxフォルダが配置されているパス
- **Host\_id**: クラウドへの認証に使用されるハッシュ。これはWebからのみ取り消すことができます。
- **Root\_ns**: ユーザー識別子

**`filecache.db`**データベースには、Dropboxと同期されたすべてのファイルとフォルダに関する情報が含まれています。最も有用な情報を持つテーブルは`File_journal`です：

- **Server\_path**: サーバー内のファイルが配置されているパス（このパスはクライアントの`host_id`で先行します）。
- **local\_sjid**: ファイルのバージョン
- **local\_mtime**: 修正日
- **local\_ctime**: 作成日

このデータベース内の他のテーブルには、さらに興味深い情報が含まれています：

- **block\_cache**: Dropboxのすべてのファイルとフォルダのハッシュ
- **block\_ref**: テーブル`block_cache`のハッシュIDをテーブル`file_journal`のファイルIDに関連付ける
- **mount\_table**: Dropboxの共有フォルダ
- **deleted\_fields**: Dropboxで削除されたファイル
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**できます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローしてください
- ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください

</details>
