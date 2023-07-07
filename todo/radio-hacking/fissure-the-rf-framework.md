# FISSURE - RFフレームワーク

**周波数に依存しないSDRベースの信号理解と逆向きエンジニアリング**

FISSUREは、信号の検出と分類、プロトコルの発見、攻撃の実行、IQの操作、脆弱性分析、自動化、AI/MLのためのフックを備えたオープンソースのRFおよび逆向きエンジニアリングフレームワークです。このフレームワークは、ソフトウェアモジュール、ラジオ、プロトコル、信号データ、スクリプト、フローグラフ、リファレンス資料、サードパーティツールの迅速な統合を促進するために構築されました。FISSUREは、ソフトウェアを1つの場所に保持し、特定のLinuxディストリビューションのための同じ確立されたベースライン設定を共有しながら、チームが簡単にスピードアップできるようにするワークフローエンエーラーです。

FISSUREに含まれるフレームワークとツールは、RFエネルギーの存在を検出し、信号の特性を理解し、サンプルを収集して分析し、送信および/またはインジェクション技術を開発し、カスタムのペイロードやメッセージを作成するために設計されています。FISSUREには、識別、パケットの作成、およびファジングを支援するためのプロトコルと信号情報の成長するライブラリが含まれています。オンラインアーカイブ機能を使用して、信号ファイルをダウンロードし、トラフィックをシミュレートしてシステムをテストするためのプレイリストを作成することもできます。

フレンドリーなPythonコードベースとユーザーインターフェースにより、初心者はRFおよび逆向きエンジニアリングに関する人気のあるツールと技術についてすばやく学ぶことができます。サイバーセキュリティとエンジニアリングの教育者は、組み込まれた教材を活用するか、フレームワークを使用して独自の実世界アプリケーションをデモンストレーションすることができます。開発者や研究者は、FISSUREを日常のタスクや最先端のソリューションを広い範囲のユーザーに公開するために使用することができます。FISSUREのコミュニティでの認識と使用が広がるにつれて、その機能の範囲と包括する技術の幅も拡大していきます。

**追加情報**

* [AISページ](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22スライド](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22論文](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22ビデオ](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [ハックチャットの記録](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## はじめに

**サポートされているもの**

FISSUREには3つのブランチがあり、ファイルのナビゲーションを容易にし、コードの冗長性を減らしています。Python2\_maint-3.7ブランチは、Python2、PyQt4、およびGNU Radio 3.7をベースにしたコードベースを含みます。Python3\_maint-3.8ブランチは、Python3、PyQt5、およびGNU Radio 3.8をベースにしたコードベースを含みます。Python3\_maint-3.10ブランチは、Python3、PyQt5、およびGNU Radio 3.10をベースにしたコードベースを含みます。

|   オペレーティングシステム   |   FISSUREブランチ   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**進行中（ベータ版）**

これらのオペレーティングシステムはまだベータ版です。開発中であり、いくつかの機能が欠落していることが知られています。インストーラ内のアイテムは既存のプログラムと競合する可能性があり、ステータスが削除されるまでインストールに失敗する可能性があります。

|     オペレーティングシステム     |    FISSUREブランチ   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

注意：特定のソフトウェアツールはすべてのOSで動作しない場合があります。[ソフトウェアと競合の詳細](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)を参照してください。

**インストール**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
これにより、インストールGUIを起動するために必要なPyQtソフトウェアの依存関係がインストールされます（見つからない場合）。

次に、オペレーティングシステムに最も適合するオプションを選択します（OSがオプションに一致する場合は自動的に検出されます）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

既存の競合を避けるために、クリーンなオペレーティングシステムにFISSUREをインストールすることをお勧めします。FISSURE内のさまざまなツールを操作する際にエラーを回避するために、すべての推奨チェックボックス（デフォルトボタン）を選択してください。インストール中には、昇格された権限とユーザー名を求めるプロンプトが複数回表示されます。アイテムに「Verify」セクションが含まれている場合、インストーラは後続のコマンドを実行し、コマンドによってエラーが生成されるかどうかに応じてチェックボックスアイテムを緑または赤で強調表示します。インストール後、"Verify"セクションのないチェック済みアイテムは黒のままです。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用方法**

ターミナルを開き、次のコマンドを入力します：
```
fissure
```
## 詳細

**コンポーネント**

* ダッシュボード
* セントラルハブ（HIPRFISR）
* ターゲット信号識別（TSI）
* プロトコルの発見（PD）
* フローグラフ＆スクリプトエグゼキュータ（FGE）

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**機能**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**シグナル検出器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ操作**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**シグナル検索**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**パターン認識**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**攻撃**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**シグナルプレイリスト**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**画像ギャラリー**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**パケット作成**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy統合**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC計算機**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**ログ**_            |

**ハードウェア**

以下は、統合レベルの異なる「サポートされている」ハードウェアのリストです。

* USRP: X3xx、B2xx、B20xmini、USRP2、N2xx
* HackRF
* RTL2832U
* 802.11アダプタ
* LimeSDR
* bladeRF、bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## レッスン

FISSUREには、さまざまな技術とテクニックに慣れるための役立つガイドがいくつか付属しています。多くのガイドでは、FISSUREに統合されたさまざまなツールの使用手順が含まれています。

* [レッスン1：OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [レッスン2：Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [レッスン3：Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [レッスン4：ESPボード](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [レッスン5：ラジオソンド追跡](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [レッスン6：RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [レッスン7：データ型](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [レッスン8：カスタムGNU Radioブロック](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [レッスン9：TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [レッスン10：ハムラジオ試験](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [レッスン11：Wi-Fiツール](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## ロードマップ

* [ ] より多くのハードウェアタイプ、RFプロトコル、信号パラメータ、分析ツールを追加する
* [ ] より多くのオペレーティングシステムをサポートする
* [ ] FISSUREに関連するクラス資料を開発する（RF攻撃、Wi-Fi、GNU Radio、PyQtなど）
* [ ] 選択可能なAI/ML技術を使用したシグナルコンディショナ、特徴抽出、およびシグナル分類器を作成する
* [ ] 不明な信号からビットストリームを生成するための再帰的な復調メカニズムを実装する
* [ ] 主要なFISSUREコンポーネントを一般的なセンサーノード展開スキームに移行する

## 貢献

FISSUREの改善に関する提案は強く推奨されています。以下の点について、[Discussions](https://github.com/ainfosec/FISSURE/discussions)ページまたはDiscordサーバーでコメントを残してください。

* 新機能の提案とデザインの変更
* インストール手順を伴うソフトウェアツール
* 新しいレッスンまたは既存のレッスンの追加資料
* 興味のあるRFプロトコル
* 統合するハードウェアとSDRの種類の追加
* PythonでのIQ分析スクリプト
* インストールの修正と改善

FISSUREの改善に寄与することは、その開発を迅速化するために重要です。あなたが行う貢献は非常に感謝されます。コード開発を通じて貢献したい場合は、リポジトリをフォークしてプルリクエストを作成してください。

1. プロジェクトをフォークする
2. フィーチャーブランチを作成する（`git checkout -b feature/AmazingFeature`）
3. 変更内容をコミットする（`git commit -m 'Add some AmazingFeature'`）
4. ブランチにプッシュする（`git push origin feature/AmazingFeature`）
5. プルリクエストを作成する

バグに注意を喚起するために[Issues](https://github.com/ainfosec/FISSURE/issues)を作成することも歓迎されています。
## 協力

FISSUREの協力の機会を提案し、形式化するために、Assured Information Security, Inc. (AIS)のビジネス開発部門に連絡してください。それは、ソフトウェアの統合に時間を費やすこと、AISの優れた人材が技術的な課題のためのソリューションを開発すること、またはFISSUREを他のプラットフォーム/アプリケーションに統合することなど、さまざまな形で行われるかもしれません。

## ライセンス

GPL-3.0

ライセンスの詳細については、LICENSEファイルを参照してください。

## 連絡先

Discordサーバーに参加する：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitterでフォローする：[@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

ビジネス開発 - Assured Information Security, Inc. - bd@ainfosec.com

## クレジット

以下の開発者に感謝し、謝意を表します：

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 謝辞

このプロジェクトへの貢献に対して、Dr. Samuel MantravadiとJoseph Reithに特別な感謝を表します。
