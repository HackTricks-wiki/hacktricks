# ローカルクラウドストレージ

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windowsでは、OneDriveフォルダは`\Users\<username>\AppData\Local\Microsoft\OneDrive`にあります。そして、`logs\Personal`の中には、同期されたファイルに関するいくつかの興味深いデータが含まれている`SyncDiagnostics.log`というファイルがあります：

* バイト単位のサイズ
* 作成日
* 変更日
* クラウド内のファイル数
* フォルダ内のファイル数
* **CID**：OneDriveユーザーの一意のID
* レポート生成時間
* OSのHDのサイズ

CIDを見つけたら、**このIDを含むファイルを検索**することをお勧めします。OneDriveと同期されたファイルの名前が_**\<CID>.ini**_と_**\<CID>.dat**_のようなファイルを見つけることができるかもしれません。これらのファイルには、OneDriveと同期されたファイルの名前など、興味深い情報が含まれている可能性があります。

## Google Drive

Windowsでは、メインのGoogle Driveフォルダは`\Users\<username>\AppData\Local\Google\Drive\user_default`にあります。\
このフォルダには、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報が含まれるSync\_log.logというファイルがあります。削除されたファイルも、対応するMD5とともにそのログファイルに表示されます。

ファイル**`Cloud_graph\Cloud_graph.db`**は、テーブル**`cloud_graph_entry`**を含むsqliteデータベースです。このテーブルには、**同期されたファイル**の**名前**、変更時間、サイズ、およびファイルのMD5チェックサムが含まれています。

データベース**`Sync_config.db`**のテーブルデータには、アカウントのメールアドレス、共有フォルダのパス、およびGoogle Driveのバージョンが含まれています。

## Dropbox

Dropboxは**SQLiteデータベース**を使用してファイルを管理します。これには、次のフォルダにデータベースがあります。

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

そして、主なデータベースは次のとおりです。

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx"拡張子は、データベースが**暗号化**されていることを意味します。Dropboxは**DPAPI**を使用します ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropboxが使用する暗号化をよりよく理解するために、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を読んでください。

ただし、主な情報は次のとおりです。

* **エントロピー**：d114a55212655f74bd772e37e64aee9b
* **ソルト**：0D638C092E8B82FC452883F95F355B8E
* **アルゴリズム**：PBKDF2
* **イテレーション**：1066

その情報に加えて、データベースを復号化するには、次のものが必要です。

* **暗号化されたDPAPIキー**：これは、レジストリ内の`NTUSER.DAT\Software\Dropbox\ks\client`にあります（このデータをバイナリ形式でエクスポートします）
* **`SYSTEM`**および**`SECURITY`**ハイブ
* **DPAPIマスターキー**：これは`\Users\<username>\AppData\Roaming\Microsoft\Protect`に見つけることができます
* Windowsユーザーの**ユーザー名**と**パスワード**

その後、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)****ツールを使用できます。

![](<../../../.gitbook/assets/image (448).png>)

すべてが予想どおりに進むと、ツールは**元のキーを回復するために使用する主キー**を示します。元のキーを回復するには、この[cyber\_chefレシピ](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))を使用し、主キーをレシピの「パスフレーズ」として入力します。

結果の16進数が、データベースを復号化するために使用される最終キーです。
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`**データベースには以下の情報が含まれています：

* **Email**: ユーザーのメールアドレス
* **usernamedisplayname**: ユーザーの名前
* **dropbox\_path**: Dropboxフォルダが配置されているパス
* **Host\_id: Hash**: クラウドへの認証に使用されるハッシュ。これはウェブからのみ取り消すことができます。
* **Root\_ns**: ユーザー識別子

**`filecache.db`**データベースには、Dropboxと同期されたすべてのファイルとフォルダに関する情報が含まれています。テーブル`File_journal`には、より多くの有用な情報があります：

* **Server\_path**: サーバー内のファイルの場所（このパスはクライアントの`host_id`で先行します）。
* **local\_sjid**: ファイルのバージョン
* **local\_mtime**: 変更日時
* **local\_ctime**: 作成日時

このデータベース内の他のテーブルには、より興味深い情報が含まれています：

* **block\_cache**: Dropboxのすべてのファイルとフォルダのハッシュ
* **block\_ref**: テーブル`block_cache`のハッシュIDをテーブル`file_journal`のファイルIDと関連付ける
* **mount\_table**: Dropboxの共有フォルダ
* **deleted\_fields**: Dropboxの削除されたファイル
* **date\_added**

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
