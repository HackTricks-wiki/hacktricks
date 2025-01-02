# FISSURE - The RF Framework

**周波数に依存しないSDRベースの信号理解とリバースエンジニアリング**

FISSUREは、信号検出と分類、プロトコル発見、攻撃実行、IQ操作、脆弱性分析、自動化、AI/MLのためのフックを備えた、すべてのスキルレベル向けに設計されたオープンソースのRFおよびリバースエンジニアリングフレームワークです。このフレームワークは、ソフトウェアモジュール、ラジオ、プロトコル、信号データ、スクリプト、フローベース、参考資料、サードパーティツールの迅速な統合を促進するために構築されました。FISSUREは、ソフトウェアを1か所に保持し、特定のLinuxディストリビューションのための同じ実証済みのベースライン構成を共有しながら、チームがスムーズに作業を開始できるようにするワークフローの促進者です。

FISSUREに含まれるフレームワークとツールは、RFエネルギーの存在を検出し、信号の特性を理解し、サンプルを収集・分析し、送信および/または注入技術を開発し、カスタムペイロードやメッセージを作成するために設計されています。FISSUREには、識別、パケット作成、ファジングを支援するためのプロトコルおよび信号情報の成長するライブラリが含まれています。オンラインアーカイブ機能があり、信号ファイルをダウンロードし、トラフィックをシミュレートしてシステムをテストするためのプレイリストを構築できます。

フレンドリーなPythonコードベースとユーザーインターフェースにより、初心者はRFおよびリバースエンジニアリングに関する人気のツールや技術を迅速に学ぶことができます。サイバーセキュリティやエンジニアリングの教育者は、組み込みの資料を活用したり、フレームワークを利用して自分の実世界のアプリケーションを示すことができます。開発者や研究者は、日常のタスクにFISSUREを使用したり、最先端のソリューションをより広いオーディエンスに公開するために利用できます。FISSUREの認知度と使用がコミュニティで高まるにつれて、その能力の範囲と包含する技術の幅も広がります。

**追加情報**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**サポートされている**

FISSURE内には、ファイルナビゲーションを容易にし、コードの冗長性を減らすために3つのブランチがあります。Python2\_maint-3.7ブランチは、Python2、PyQt4、およびGNU Radio 3.7を中心に構築されたコードベースを含み、Python3\_maint-3.8ブランチは、Python3、PyQt5、およびGNU Radio 3.8を中心に構築され、Python3\_maint-3.10ブランチは、Python3、PyQt5、およびGNU Radio 3.10を中心に構築されています。

|   オペレーティングシステム   |   FISSUREブランチ   |
| :--------------------------: | :----------------: |
|  Ubuntu 18.04 (x64)        | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)       | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)       | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)       | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)       | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)       | Python3\_maint-3.8 |

**進行中（ベータ）**

これらのオペレーティングシステムはまだベータステータスです。開発中であり、いくつかの機能が欠けていることが知られています。インストーラー内の項目は、既存のプログラムと競合する可能性があるか、ステータスが削除されるまでインストールに失敗することがあります。

|     オペレーティングシステム     |    FISSUREブランチ   |
| :-------------------------------: | :-----------------: |
| DragonOS Focal (x86\_64)        |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)           | Python3\_maint-3.10 |

注：特定のソフトウェアツールはすべてのOSで動作しません。[Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)を参照してください。

**インストール**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
これにより、インストールGUIを起動するために必要なPyQtソフトウェア依存関係が見つからない場合にインストールされます。

次に、オペレーティングシステムに最も適したオプションを選択します（OSがオプションに一致する場合は自動的に検出されるはずです）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

既存の競合を避けるために、クリーンなオペレーティングシステムにFISSUREをインストールすることをお勧めします。FISSURE内のさまざまなツールを操作する際のエラーを避けるために、すべての推奨チェックボックス（デフォルトボタン）を選択してください。インストール中に複数のプロンプトが表示され、主に昇格された権限とユーザー名を要求されます。項目の最後に「Verify」セクションが含まれている場合、インストーラーはその後のコマンドを実行し、コマンドによってエラーが発生したかどうかに応じてチェックボックス項目を緑または赤で強調表示します。「Verify」セクションのないチェック済み項目は、インストール後も黒のままになります。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用法**

ターミナルを開いて、次のように入力します：
```
fissure
```
FISSUREの使用方法の詳細については、ヘルプメニューを参照してください。

## 詳細

**コンポーネント**

* ダッシュボード
* セントラルハブ (HIPRFISR)
* ターゲット信号識別 (TSI)
* プロトコル発見 (PD)
* フローペグラフ & スクリプトエグゼキュータ (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**機能**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**信号検出器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ操作**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**信号ルックアップ**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**パターン認識**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**攻撃**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**ファジング**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**信号プレイリスト**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**画像ギャラリー**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**パケット作成**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy統合**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC計算機**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**ログ記録**_            |

**ハードウェア**

以下は、さまざまな統合レベルを持つ「サポートされている」ハードウェアのリストです：

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11アダプタ
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## レッスン

FISSUREには、さまざまな技術や手法に慣れるためのいくつかの役立つガイドが付属しています。多くは、FISSUREに統合されたさまざまなツールの使用手順を含んでいます。

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Luaディセクタ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESPボード](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: ラジオソン追跡](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: データ型](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: カスタムGNU Radioブロック](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: アマチュア無線試験](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fiツール](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## ロードマップ

* [ ] さらなるハードウェアタイプ、RFプロトコル、信号パラメータ、分析ツールを追加
* [ ] より多くのオペレーティングシステムをサポート
* [ ] FISSUREに関するクラス資料を開発 (RF攻撃、Wi-Fi、GNU Radio、PyQtなど)
* [ ] 選択可能なAI/ML技術を用いた信号コンディショナー、特徴抽出器、信号分類器を作成
* [ ] 不明な信号からビットストリームを生成するための再帰的変調メカニズムを実装
* [ ] FISSUREの主要コンポーネントを一般的なセンサーノード展開スキームに移行

## 貢献

FISSUREの改善に関する提案は大いに歓迎されます。以下の点について考えがある場合は、[Discussions](https://github.com/ainfosec/FISSURE/discussions)ページまたはDiscordサーバーにコメントを残してください：

* 新機能の提案やデザイン変更
* インストール手順を含むソフトウェアツール
* 新しいレッスンや既存のレッスンの追加資料
* 興味のあるRFプロトコル
* 統合のためのさらなるハードウェアやSDRタイプ
* PythonでのIQ分析スクリプト
* インストールの修正と改善

FISSUREの改善に向けた貢献は、その開発を加速させるために重要です。あなたの貢献は大変感謝されます。コード開発を通じて貢献したい場合は、リポジトリをフォークしてプルリクエストを作成してください：

1. プロジェクトをフォーク
2. フィーチャーブランチを作成 (`git checkout -b feature/AmazingFeature`)
3. 変更をコミット (`git commit -m 'Add some AmazingFeature'`)
4. ブランチにプッシュ (`git push origin feature/AmazingFeature`)
5. プルリクエストを開く

バグに注意を促すための[Issues](https://github.com/ainfosec/FISSURE/issues)の作成も歓迎されます。

## コラボレーション

Assured Information Security, Inc. (AIS)のビジネス開発に連絡し、FISSUREのコラボレーション機会を提案し、正式化してください。ソフトウェアの統合に時間を割くこと、AISの才能ある人々があなたの技術的課題の解決策を開発すること、またはFISSUREを他のプラットフォーム/アプリケーションに統合することなどです。

## ライセンス

GPL-3.0

ライセンスの詳細については、LICENSEファイルを参照してください。

## 連絡先

Discordサーバーに参加: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitterでフォロー: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

ビジネス開発 - Assured Information Security, Inc. - bd@ainfosec.com

## クレジット

これらの開発者に感謝します：

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 謝辞

このプロジェクトへの貢献に対して、Dr. Samuel MantravadiとJoseph Reithに特別な感謝を申し上げます。
