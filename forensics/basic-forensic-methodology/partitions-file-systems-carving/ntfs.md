# NTFS

## NTFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有**するには、[**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## **NTFS**

**NTFS**（**New Technology File System**）は、Microsoftによって開発されたプロプライエタリなジャーナリングファイルシステムです。

NTFSでは、クラスタが最小のサイズ単位であり、クラスタのサイズはパーティションのサイズに依存します。

| パーティションのサイズ | クラスタあたりのセクタ数 | クラスタのサイズ |
| ------------------------ | ------------------- | ------------ |
| 512MB以下            | 1                   | 512バイト    |
| 513MB-1024MB（1GB）       | 2                   | 1KB          |
| 1025MB-2048MB（2GB）      | 4                   | 2KB          |
| 2049MB-4096MB（4GB）      | 8                   | 4KB          |
| 4097MB-8192MB（8GB）      | 16                  | 8KB          |
| 8193MB-16,384MB（16GB）   | 32                  | 16KB         |
| 16,385MB-32,768MB（32GB） | 64                  | 32KB         |
| 32,768MBより大きい    | 128                 | 64KB         |

### **スラックスペース**

NTFSの最小のサイズ単位はクラスタです。各ファイルは複数の完全なクラスタを占有します。そのため、各ファイルが必要以上のスペースを占有している可能性が非常に高いです。ファイルによって予約されたこれらの未使用のスペースは、スラックスペースと呼ばれ、人々はこの領域を利用して情報を隠すことができます。

![](<../../../.gitbook/assets/image (498).png>)

### **NTFSブートセクタ**

NTFSボリュームをフォーマットすると、フォーマットプログラムは最初の16セクタをブートメタデータファイルに割り当てます。最初のセクタはブートセクタであり、「ブートストラップ」コードが含まれており、次の15セクタはブートセクタのIPL（Initial Program Loader）です。ファイルシステムの信頼性を高めるために、NTFSパーティションの最後のセクタにはブートセクタの予備コピーが含まれています。

### **マスターファイルテーブル（MFT）**

NTFSファイルシステムには、マスターファイルテーブル（MFT）と呼ばれるファイルが含まれています。NTFSファイルシステムボリューム上のすべてのファイルには、MFT自体を含む少なくとも1つのエントリがあります。ファイルのすべての情報（サイズ、時刻と日付のスタンプ、アクセス許可、データ内容など）は、MFTエントリまたはMFTエントリによって記述されるMFTの外部のスペースに格納されます。

NTFSファイルシステムボリュームにファイルが追加されると、MFTにはさらにエントリが追加され、MFTのサイズが増加します。NTFSファイルシステムボリュームからファイルが削除されると、そのMFTエントリは無料とマークされ、再利用される可能性があります。ただし、これらのエントリに割り当てられたディスクスペースは再割り当てされず、MFTのサイズは減少しません。

NTFSファイルシステムは、MFTをできるだけ連続した状態に保つために、MFTのためにスペースを予約します。各ボリュームのNTFSファイルシステムによってMFTのために予約されたスペースは、MFTゾーンと呼ばれます。ファイルとディレクトリのスペースもこのスペースから割り当てられますが、MFTゾーンの外側のボリュームスペースがすべて割り当てられた後にのみ割り当てられます。

平均ファイルサイズやその他の変数に応じて、ディスクが容量いっぱいになると、予約されたMFTゾーンまたはディスク上の未予約スペースのどちらかが最初に割り当てられます。比較的大きな数のファイルを持つボリュームは、未予約スペースを最初に割り当てますが、比較的小さな数のファイルを持つボリュームは、MFTゾーンを最初に割り当てます。いずれの場合でも、MFTの断片化は、いずれかの領域が完全に割り当てられると始まります。未予約スペースが完全に割り当てられる場合、ユーザーファイルとディレクトリのスペースはMFTゾーンから割り当てられます。MFTゾーンが完全に割り当てられる場合、新しいMFTエントリのスペースは未予約スペースから割り当てられます。

NTFSファイルシステムは、**$MFTMirror**も生成します。これはMFTの最初
| ブートセクター         | $Boot     | 7          | ボリュームをマウントするために使用されるBPBと、ボリュームがブート可能な場合に使用される追加のブートストラップローダーコードを含みます。                                                                                                                |
| バッドクラスターファイル | $BadClus  | 8          | ボリュームのバッドクラスターを含みます。                                                                                                                                                                                         |
| セキュリティファイル   | $Secure   | 9          | ボリューム内のすべてのファイルに対する固有のセキュリティディスクリプタを含みます。                                                                                                                                                           |
| 大文字変換テーブル     | $Upcase   | 10         | 小文字の文字を対応するUnicodeの大文字に変換します。                                                                                                                                                       |
| NTFS拡張ファイル       | $Extend   | 11         | クォータ、リパースポイントデータ、オブジェクト識別子などのさまざまなオプションの拡張機能に使用されます。                                                                                                                              |
|                       |           | 12-15      | 将来の使用のために予約されています。                                                                                                                                                                                                      |
| クォータ管理ファイル   | $Quota    | 24         | ボリュームスペースに対するユーザーによるクォータ制限を含みます。                                                                                                                                                                      |
| オブジェクトIDファイル | $ObjId    | 25         | ファイルオブジェクトIDを含みます。                                                                                                                                                                                                     |
| リパースポイントファイル | $Reparse  | 26         | このファイルには、リパースポイントデータを含むボリューム上のファイルとフォルダに関する情報が含まれています。                                                                                                                            |

### MFTの各エントリは次のようになります：

![](<../../../.gitbook/assets/image (499).png>)

各エントリは「FILE」で始まることに注意してください。各エントリは1024ビットを占有します。したがって、MFTエントリの開始から1024ビット後に次のエントリが見つかります。

[**Active Disk Editor**](https://www.disk-editor.org/index.html)を使用すると、MFT内のファイルのエントリを簡単に検査できます。ファイルを右クリックし、「Inspect File Record」をクリックします。

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

**「In use」**フラグをチェックすることで、ファイルが削除されたかどうかを簡単に判断できます（**0x0の値は削除されたことを意味します**）。

![](<../../../.gitbook/assets/image (510).png>)

FTKImagerを使用して削除されたファイルを回復することも可能です：

![](<../../../.gitbook/assets/image (502).png>)

### MFT属性

各MFTエントリには、次の画像に示すように、いくつかの属性があります：

![](<../../../.gitbook/assets/image (506).png>)

各属性は、次のようにタイプによって識別されるエントリ情報を示します：

| タイプ識別子 | 名前                     | 説明                                                                                                             |
| --------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| 16              | $STANDARD\_INFORMATION   | フラグ、最終アクセス、書き込み、作成時刻、所有者、セキュリティIDなどの一般情報。 |
| 32              | $ATTRIBUTE\_LIST         | ファイルの他の属性が見つかるリスト。                                                              |
| 48              | $FILE\_NAME              | ファイル名（Unicode）、最終アクセス、書き込み、作成時刻。                                         |
| 64              | $VOLUME\_VERSION         | ボリューム情報。バージョン1.2（Windows NT）のみ存在します。                                                      |
| 64              | $OBJECT\_ID              | ファイルまたはディレクトリの16バイトの一意の識別子。バージョン3.0以降（Windows 2000以降）のみ存在します。    |
| 80              | $SECURITY\_ DESCRIPTOR   | ファイルのアクセス制御とセキュリティプロパティ。                                                           |
| 96              | $VOLUME\_NAME            | ボリューム名。                                                                                                      |
| 112             | $VOLUME\_ INFORMATION    | ファイルシステムのバージョンとその他のフラグ。                                                                              |
| 128             | $DATA                    | ファイルの内容。                                                                                                    |
| 144             | $INDEX\_ROOT             | インデックスツリーのルートノード。                                                                                       |
| 160             | $INDEX\_ALLOCATION       | $INDEX\_ROOT属性にルートされたインデックスツリーのノード。                                                          |
| 176             | $BITMAP                  | $MFTファイルおよびインデックスのためのビットマップ。                                                                       |
| 192             | $SYMBOLIC\_LINK          | ソフトリンク情報。バージョン1.2（Windows NT）のみ存在します。                                                   |
| 192             | $REPARSE\_POINT          | リパースポイントに関するデータが含まれており、バージョン3.0以降（Windows 2000以降）でソフトリンクとして使用されます。                |
| 208             | $EA\_INFORMATION         | OS/2アプリケーション（HPFS）との後方互換性のために使用されます。                                                    |
| 224             | $EA                      | OS/2アプリケーション（HPFS）との後方互換性のために使用されます。                                                    |
| 256             | $LOGGED\_UTILITY\_STREAM | バージョン3.0以降（Windows 2000以降）で暗号化属性に関するキーと情報が含まれています。                         |

たとえば、**タイプ48（0x30）**は**ファイル名**を識別します：

![](<../../../.gitbook/assets/image (508).png>)

また、これらの属性が**resident（MFTレコード内に存在する）**か**nonresident（MFTレコード内の他の場所に存在し、レコード内で参照されるだけ）**であることを理解することも役立ちます。たとえば、属性**$Dataがresident**である場合、これは**ファイル全体がMFTに保存されている**ことを意味します。nonresidentの場合、ファイルの内容はファイルシステムの別の場所にあります。

いくつかの興味深い属性：

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html)（他にもあります）：
* 作成日時
* 変更日時
* アクセス日時
* MFT更新日時
* DOSファイルの許可
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html)（他にもあります）：
* ファイル名
* 作成日時
* 変更日時
* アクセス日時
* MFT更新日時
* 割り当てられたサイズ
* 実際のサイズ
* 親ディレクトリへの[ファイル参照](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html)。
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html)（他にもあります）：
* ファイルのデータまたはデータが存在するセクターの指示を含みます。次の例では、属性データがresidentでないため、属性はデータが存在するセクターに関する情報を提供します。

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)
### NTFSタイムスタンプ

![](<../../../.gitbook/assets/image (512).png>)

MFTを分析するための便利なツールとして、[**MFT2csv**](https://github.com/jschicht/Mft2Csv)があります（mftファイルまたはイメージを選択し、すべてをダンプして抽出してオブジェクトを抽出します）。\
このプログラムは、すべてのMFTデータを抽出し、CSV形式で表示します。また、ファイルのダンプにも使用できます。

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

**`$LOGFILE`**ファイルには、**ファイルに対して実行されたアクションに関するログ**が含まれています。また、**やり直し**が必要なアクションと、**前の状態に戻る**ために必要なアクションも**保存**されます。\
これらのログは、MFTがファイルシステムを再構築するために使用されます。このファイルの最大サイズは**65536KB**です。

`$LOGFILE`を調査するには、[**MFT2csv**](https://github.com/jschicht/Mft2Csv)を使用して、事前に`$MFT`を抽出して調査します。\
次に、[**LogFileParser**](https://github.com/jschicht/LogFileParser)をこのファイルに対して実行し、エクスポートされた`$LOGFILE`ファイルと`$MFT`の検査のCSVを選択します。`$LOGFILE`ログによって記録されたファイルシステムのアクティビティのログが含まれたCSVファイルが生成されます。

![](<../../../.gitbook/assets/image (515).png>)

ファイル名でフィルタリングすると、**ファイルに対して実行されたすべてのアクション**を確認できます。

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

ファイル`$EXTEND/$USNJnrl/$J`は、ファイル`$EXTEND$USNJnrl`の代替データストリームです。このアーティファクトには、`$LOGFILE`よりも詳細なNTFSボリューム内で発生した変更のレジストリが含まれています。

このファイルを調査するには、ツール[**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv)を使用できます。

ファイル名でフィルタリングすると、**ファイルに対して実行されたすべてのアクション**を確認できます。また、親フォルダの`MFTReference`を見つけることもできます。その`MFTReference`を見ることで、親フォルダの情報を取得できます。

![](<../../../.gitbook/assets/image (516).png>)

### $I30

ファイルシステムのすべてのディレクトリには、ディレクトリの内容に変更がある場合に維持する必要がある**`$I30`属性**があります。ディレクトリからファイルまたはフォルダが削除されると、**`$I30`インデックスレコードが適切に再配置されます**。ただし、**インデックスレコードの再配置により、削除されたファイル/フォルダのエントリの残骸がスラックスペースに残ることがあります**。これは、ドライブ上に存在した可能性のあるファイルを特定するためのフォレンジック分析に役立ちます。

ディレクトリの`$I30`ファイルを**FTK Imager**から取得し、ツール[Indx2Csv](https://github.com/jschicht/Indx2Csv)で調査できます。

![](<../../../.gitbook/assets/image (519).png>)

このデータを使用すると、フォルダ内で実行されたファイルの変更に関する情報を見つけることができますが、ファイルの削除時刻はこのログに保存されません。ただし、**`$I30`ファイル**の**最終変更日**を見ることができ、ディレクトリで実行された**最後のアクション**がファイルの**削除**である場合、時刻は同じである可能性があります。

### $Bitmap

**`$BitMap`**は、NTFSファイルシステム内の特別なファイルです。このファイルは、NTFSボリューム上のすべての使用済みおよび未使用のクラスタを追跡します。ファイルがNTFSボリューム上のスペースを占有すると、使用される場所は`$BitMap`でマークされます。

![](<../../../.gitbook/assets/image (523).png>)

### ADS（代替データストリーム）

代替データストリームを使用すると、ファイルに複数のデータストリームを含めることができます。すべてのファイルには少なくとも1つのデータストリームがあります。Windowsでは、このデフォルトのデータストリームは`:$DATA`と呼ばれます。\
この[ページ](../../../windows-hardening/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream)では、コンソールから代替データストリームを作成/アクセス/発見するさまざまな方法を確認できます。過去には、これがIISの脆弱性を引き起こし、人々が`http://www.alternate-data-streams.com/default.asp::$DATA`のように`:$DATA`ストリームにアクセスすることでページのソースコードにアクセスできるようになりました。

ツール[**AlternateStreamView**](https://www.nirsoft.net/utils/alternate\_data\_streams.html)を使用すると、いくつかのADSを持つすべてのファイルを検索してエクスポートできます。

![](<../../../.gitbook/assets/image (518).png>)

FTKイメージャを使用してADSを持つファイルをダブルクリックすると、ADSデータにアクセスできます。

![](<../../../.gitbook/assets/image (517).png>)

上記の画像で**`Zone.Identifier`**というADSが見つかった場合、これには通常、ファイルのダウンロード方法に関する情報が含まれています。以下の情報が含まれます。

* ゾーンID = 0 -> マイコンピュータ
* ゾーンID = 1 -> イントラネット
* ゾーンID = 2 -> 信頼済み
* ゾーンID = 3 -> インターネット
* ゾーンID = 4 -> 信頼されていない

さらに、異なるソフトウェアは追加の情報を保存する場合があります。

| ソフトウェア                                                      | 情報                                                                         |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Google Chrome、Opera、Vivaldi、                                      | ZoneId=3、ReferrerUrl、HostUrl                                               |
| Microsoft Edge                                                      | ZoneId=3、LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox、Torブラウザ、Outlook2016、Thunderbird、Windows Mail、Skype | ZoneId=3                                                                     |
| μTorrent                                                            | ZoneId=3、HostUrl=about:internet                                             |

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></
* [💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、Twitterで私をフォローする[🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks\_live)。
* ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
