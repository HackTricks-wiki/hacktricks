# FISSURE - RFフレームワーク

{{#include ../../banners/hacktricks-training.md}}

**周波数非依存のSDRベース信号理解およびリバースエンジニアリング**

FISSUREは、あらゆるスキルレベルに対応するオープンソースのRFおよびリバースエンジニアリングフレームワークであり、信号の検出と分類、プロトコルの発見、攻撃の実行、IQ操作、脆弱性分析、自動化、AI/MLのための機能を備えています。このフレームワークは、ソフトウェアモジュール、無線機、プロトコル、信号データ、スクリプト、フローグラフ、参考資料、サードパーティツールを迅速に統合できるよう設計されています。FISSUREはワークフローを支援するツールであり、ソフトウェアを1か所にまとめ、特定のLinuxディストリビューション向けに検証済みの同一ベースライン設定をチームで共有しながら、容易に利用を開始できるようにします。<sup>[[1]](#references)[[2]](#references)</sup>

FISSUREに含まれるフレームワークとツールは、RFエネルギーの検出、信号の特性解析、サンプルの収集と分析、送信またはインジェクション技術の開発、カスタムペイロードやメッセージの作成を目的として設計されています。FISSUREは、識別、パケット作成、fuzzingに使用できるプロトコルおよび信号情報に加え、トラフィックのシミュレーションとテストのためのアーカイブやプレイリストも提供します。<sup>[[1]](#references)[[2]](#references)</sup>

Pythonコードベースとグラフィカルインターフェースにより、初心者はRFおよびリバースエンジニアリングツールを学習できます。教育者は組み込みレッスンを利用でき、開発者や研究者は独自のモジュールやワークフローを統合できます。現在のリリースでは、分散センサーノード、TAK統合、地理位置情報ワークフロー、役割別のApptainerデプロイメントもサポートされています。<sup>[[1]](#references)[[3]](#references)</sup>

**追加情報**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**サポート対象**

現在のFISSUREでは、PyQt5およびGNU Radio 3.8または3.10を使用したアクティブな開発に**`Python3`**ブランチを使用しています。非推奨の**`Python2_maint-3.7`**ブランチは、古いオペレーティングシステムやGNU Radio 3.7を必要とするサードパーティツール向けに引き続き利用できます。以前の`Python3_maint-3.8`および`Python3_maint-3.10`というブランチ名は履歴上のものであり、GNU Radioのメンテナンス版の選択は現在、`Python3`ブランチから行われます。<sup>[[1]](#references)[[3]](#references)</sup>

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

**開発中（beta）**

これらのオペレーティングシステムはまだbetaステータスです。開発中であり、いくつかの機能が不足していることが確認されています。インストーラーに含まれる項目が既存のプログラムと競合したり、ステータスが解除されるまでインストールに失敗したりする可能性があります。

| オペレーティングシステム | FISSUREブランチ | デフォルトのGNU Radioブランチ |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

一部のサードパーティツールは、すべてのOSで動作するわけではありません。インストール前に、最新の[既知の競合とサードパーティソフトウェア](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts)ドキュメントを確認してください。<sup>[[3]](#references)</sup>

**インストール**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
サブモジュールのステップでは、FISSURE が使用する GNU Radio の out-of-tree modules をダウンロードします。これらのモジュールをインストールする場合は必須です。インストーラーは、インストール用 GUI の起動に必要な不足している PyQt の依存関係もインストールします。<sup>[[3]](#references)</sup>

次に、ご使用の operating system に最も適したオプションを選択します（OS がいずれかのオプションに一致する場合は自動的に検出されるはずです）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

既存の競合を避けるため、クリーンな operating system に FISSURE をインストールすることを推奨します。FISSURE 内の各種ツールの操作中にエラーが発生しないよう、推奨されるチェックボックスをすべて選択します（Default ボタン）。インストール中には複数のプロンプトが表示され、その多くは昇格された権限とユーザー名を尋ねるものです。項目の末尾に "Verify" セクションがある場合、インストーラーはその後に続くコマンドを実行し、コマンドによってエラーが発生したかどうかに応じて、チェックボックス項目を緑または赤で強調表示します。"Verify" セクションのないチェック済みの項目は、インストール後も黒のままです。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**利用方法**

ターミナルを開き、次を入力します。
```
fissure
```
詳細な使用方法については、FISSURE Help menuを参照してください。

## Details

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![コンポーネント](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

以下のhardwareは、FISSUREとの統合レベルがそれぞれ異なります:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lessons

FISSUREには、さまざまなtechnologyやtechniqueに慣れるための役立つguideが複数用意されています。多くのguideには、FISSUREに統合された各種toolの使用手順が含まれています。

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lesson12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lesson13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lesson14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] hardware type、RF protocol、signal parameter、analysis toolを追加
* [ ] より多くのoperating systemをサポート
* [ ] FISSUREを中心としたclass materialを開発（RF Attacks、Wi-Fi、GNU Radio、PyQtなど）
* [ ] 選択可能なAI/ML techniqueを用いたsignal conditioner、feature extractor、signal classifierを作成
* [ ] unknown signalからbitstreamを生成するrecursive demodulation mechanismを実装
* [ ] FISSUREの主要Componentsをgeneric sensor node deployment schemeへ移行

## Contributing

FISSUREの改善に関する提案を強く歓迎します。以下について意見がある場合は、[Discussions](https://github.com/ainfosec/FISSURE/discussions) pageまたはDiscord Serverにコメントを残してください。

* 新しいfeatureの提案とdesign変更
* installation手順を含むsoftware tool
* 新しいlessonまたは既存lesson向けの追加material
* 関心のあるRF protocol
* 統合対象とするhardwareおよびSDR typeの追加
* PythonによるIQ analysis script
* installationの修正および改善

FISSUREの改善へのcontributionは、開発を加速するために不可欠です。皆様からのcontributionに深く感謝します。code developmentを通じてcontributeする場合は、repoをforkしてpull requestを作成してください。

1. projectをforkする
2. feature branchを作成する（`git checkout -b feature/AmazingFeature`）
3. 変更をcommitする（`git commit -m 'Add some AmazingFeature'`）
4. branchへpushする（`git push origin feature/AmazingFeature`）
5. pull requestを開く

bugに注意を向けるための[Issues](https://github.com/ainfosec/FISSURE/issues)の作成も歓迎します。

## Collaborating

Assured Information Security, Inc.（AIS）のBusiness Developmentに連絡し、FISSURE collaborationの機会を提案・正式化してください。これには、softwareの統合に時間を充てること、AISの優秀な人材にtechnical challenge向けのsolutionを開発してもらうこと、FISSUREを他のplatform/applicationに統合することなどが含まれます。

## License

GPL-3.0

Licenseの詳細については、LICENSE fileを参照してください。

## Contact

Discord Serverに参加: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitterをフォロー: [@FissureRF](https://twitter.com/fissurerf)、[@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

以下のdeveloperに謝意を表します。

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

このprojectへのcontributionについて、Dr. Samuel MantravadiおよびJoseph Reithに特別な謝意を表します。

## References

- [1] [FISSURE - RF Framework（GitHub）](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper（GRCon22）](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
