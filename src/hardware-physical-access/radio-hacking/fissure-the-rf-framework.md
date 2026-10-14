# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSUREは、あらゆるスキルレベルのユーザー向けに設計されたオープンソースのRFおよびリバースエンジニアリングフレームワークです。信号の検出と分類、プロトコルの発見、攻撃の実行、IQ操作、脆弱性分析、自動化、AI/MLのための機能を備えています。このフレームワークは、ソフトウェアモジュール、無線機、プロトコル、信号データ、スクリプト、フローグラフ、参考資料、サードパーティ製ツールを迅速に統合できるように開発されました。FISSUREはワークフローを支援し、ソフトウェアを一か所にまとめることで、チームが特定のLinuxディストリビューション向けの実証済みベースライン設定を共有し、すぐに作業を開始できるようにします。<sup>[[1]](#references)[[2]](#references)</sup>

FISSUREに含まれるフレームワークとツールは、RFエネルギーの検出、信号の特性評価、サンプルの収集と分析、送信またはインジェクション手法の開発、カスタムペイロードやメッセージの作成を目的としています。また、識別、パケット作成、fuzzingに役立つプロトコルと信号の情報に加え、トラフィックのシミュレーションやテスト用のアーカイブとプレイリストも提供します。<sup>[[1]](#references)[[2]](#references)</sup>

Pythonコードベースとグラフィカルインターフェースにより、初心者はRFおよびリバースエンジニアリングのツールを学ぶことができます。教育者は組み込みのレッスンを利用でき、開発者や研究者は独自のモジュールやワークフローを統合できます。現在のリリースでは、分散センサーノード、TAK統合、ジオロケーションのワークフロー、役割別のApptainerデプロイメントもサポートされています。<sup>[[1]](#references)[[3]](#references)</sup>

**追加情報**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**サポート対象**

現在のFISSUREでは、PyQt5およびGNU Radio 3.8または3.10を使用する開発用に、**`Python3`**ブランチが使われています。非推奨の**`Python2_maint-3.7`**ブランチも、古いオペレーティングシステムやGNU Radio 3.7を必要とするサードパーティ製ツール向けに引き続き利用できます。以前の`Python3_maint-3.8`および`Python3_maint-3.10`というブランチ名は過去のものです。GNU Radioのメンテナンスバージョンの選択は、現在`Python3`ブランチから行います。<sup>[[1]](#references)[[3]](#references)</sup>

| オペレーティングシステム | FISSUREブランチ | デフォルトのGNU Radioブランチ |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | サポート対象のLinuxバージョンを使用 | 対応するバージョンを使用 |

**開発中（ベータ版）**

これらのオペレーティングシステムは、まだベータ版です。開発中のため、いくつかの機能が欠けていることがわかっています。インストーラーの項目が既存のプログラムと競合したり、ベータ版のステータスが解除されるまでインストールに失敗したりする場合があります。

| オペレーティングシステム | FISSUREブランチ | デフォルトのGNU Radioブランチ |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

一部のサードパーティ製ツールは、すべてのOSで動作するわけではありません。インストール前に、最新の[既知の競合とサードパーティ製ソフトウェア](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts)のドキュメントを確認してください。<sup>[[3]](#references)</sup>

**インストール**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

サブモジュールのステップでは、FISSUREで使用するGNU Radio out-of-tree modulesをダウンロードします。これらのモジュールをインストールする際に必要です。また、インストーラーはインストール用GUIの起動に必要なPyQtの不足している依存関係もインストールします。<sup>[[3]](#references)</sup>

次に、お使いのオペレーティングシステムに最も合ったオプションを選択します（OSがいずれかのオプションに一致する場合は、自動的に検出されるはずです）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

既存の競合を避けるため、クリーンなオペレーティングシステムにFISSUREをインストールすることを推奨します。FISSURE内の各種ツールの使用中にエラーが発生しないよう、推奨されるチェックボックスをすべて選択してください（Defaultボタン）。インストール中には複数のプロンプトが表示され、その多くは昇格した権限やユーザー名を尋ねるものです。項目の最後に「Verify」セクションがある場合、インストーラーはその後に続くコマンドを実行し、コマンドでエラーが発生したかどうかに応じて、チェックボックスの項目を緑または赤で強調表示します。「Verify」セクションのないチェック済み項目は、インストール後も黒色のままです。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用方法**

ターミナルを開き、次を入力します。

```
fissure
```

使用方法の詳細については、FISSURE の Help メニューを参照してください。

## 詳細

**コンポーネント**

* ダッシュボード
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![コンポーネント](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**機能**

| ![Signal Detector アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**信号検出器**_ | ![IQ Manipulation アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ操作**_      | ![Signal Lookup アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**信号検索**_          | ![Pattern Recognition アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**パターン認識**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**信号プレイリスト**_       | ![Image Gallery アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**画像ギャラリー**_  |
| ![Packet Crafting アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**パケット作成**_   | ![Scapy Integration アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy連携**_ | ![CRC Calculator アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC計算機**_ | ![Logging アイコン](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**ログ記録**_            |

**ハードウェア**

以下のハードウェアは、FISSURE との統合レベルがそれぞれ異なります。<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 アダプター
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## レッスン

FISSURE には、さまざまな技術や手法に慣れるための便利なガイドが用意されています。多くのガイドには、FISSURE に統合されている各種ツールの使用手順が含まれています。

* [レッスン1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [レッスン2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [レッスン3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [レッスン4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [レッスン5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [レッスン6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [レッスン7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [レッスン8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [レッスン9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [レッスン10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [レッスン11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [レッスン12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [レッスン13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [レッスン14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## ロードマップ

* [ ] ハードウェアの種類、RFプロトコル、信号パラメーター、解析ツールを追加
* [ ] 対応するオペレーティングシステムを拡大
* [ ] FISSURE に関する授業教材（RF Attacks、Wi-Fi、GNU Radio、PyQt など）を開発
* [ ] 選択可能なAI/ML手法を用いて、信号調整器、特徴抽出器、信号分類器を作成
* [ ] 未知の信号からビットストリームを生成する再帰的復調機構を実装
* [ ] FISSURE の主要コンポーネントを汎用センサーノードの展開方式へ移行

## 貢献

FISSURE の改善に関する提案を歓迎します。以下の内容についてご意見があれば、[Discussions](https://github.com/ainfosec/FISSURE/discussions) ページまたは Discord Server にコメントを残してください。

* 新機能の提案や設計変更
* インストール手順付きのソフトウェアツール
* 新しいレッスン、または既存のレッスン用の追加資料
* 関心のあるRFプロトコル
* 統合するハードウェアやSDRの追加
* PythonによるIQ解析スクリプト
* インストール手順の修正や改善

FISSURE の改善への貢献は、開発の加速に不可欠です。皆様からの貢献に心より感謝します。コード開発を通じて貢献する場合は、リポジトリを fork して pull request を作成してください。

1. プロジェクトを fork する
2. 機能ブランチを作成する (`git checkout -b feature/AmazingFeature`)
3. 変更を commit する (`git commit -m 'Add some AmazingFeature'`)
4. ブランチに push する (`git push origin feature/AmazingFeature`)
5. pull request を作成する

バグの報告には、[Issues](https://github.com/ainfosec/FISSURE/issues) の作成も歓迎します。

## 協業

FISSURE の協業機会について提案し、正式に進める場合は、Assured Information Security, Inc. (AIS) の Business Development までご連絡ください。ご自身のソフトウェアの統合に時間を充てる、AIS の優秀な人材に技術的課題の解決を依頼する、または FISSURE を他のプラットフォームやアプリケーションに統合するといった方法があります。

## ライセンス

GPL-3.0

ライセンスの詳細については、LICENSE ファイルを参照してください。

## お問い合わせ

Discord Server に参加: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter をフォロー: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## クレジット

以下の開発者に謝意を表します。

[クレジット](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 謝辞

このプロジェクトに貢献してくださった Dr. Samuel Mantravadi と Joseph Reith に心より感謝します。

## References

- [1] [FISSURE - RFフレームワーク (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE 論文 (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE ドキュメント - インストール](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
