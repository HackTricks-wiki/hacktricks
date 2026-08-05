# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSUREは、あらゆるスキルレベルを対象に設計されたオープンソースのRFおよびリバースエンジニアリングフレームワークであり、signal detectionとclassification、protocol discovery、attack execution、IQ manipulation、vulnerability analysis、automation、AI/MLのためのhooksを備えています。このframeworkは、software modules、radios、protocols、signal data、scripts、flow graphs、reference material、third-party toolsを迅速に統合できるように設計されています。FISSUREはworkflow enablerとして、ソフトウェアを1か所にまとめ、特定のLinux distributions向けに実証済みの同一のbaseline configurationを共有しながら、チームが簡単に準備を整えられるようにします。<sup>[[1]](#references)[[2]](#references)</sup>

FISSUREに含まれるframeworkとtoolsは、RF energyの存在を検出し、signalの特性を理解し、samplesを収集・分析し、transmitおよび/またはinjection techniquesを開発し、custom payloadsまたはmessagesを作成するために設計されています。FISSUREには、identification、packet crafting、fuzzingを支援するprotocolおよびsignal informationのlibraryが増え続けています。signal filesをdownloadし、trafficをsimulateしてsystemsをtestするためのplaylistsを作成できるオンラインarchive機能もあります。

扱いやすいPython codebaseとuser interfaceにより、beginnerでもRFおよびリバースエンジニアリングに関わるpopular toolsとtechniquesをすぐに学べます。cybersecurityおよびengineeringのeducatorsは、組み込みのmaterialを活用したり、frameworkを使用して自身のreal-world applicationsを実演したりできます。developersとresearchersは、日常のtaskにFISSUREを使用したり、最先端のsolutionsをより広いaudienceに公開したりできます。communityにおけるFISSUREの認知度と利用が高まるにつれて、そのcapabilitiesの範囲と、包含するtechnologyの広がりも増していきます。

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

FISSUREには、file navigationを容易にし、code redundancyを削減するため、3つのbranchがあります。Python2\_maint-3.7 branchには、Python2、PyQt4、GNU Radio 3.7を中心に構築されたcodebaseが含まれています。Python3\_maint-3.8 branchは、Python3、PyQt5、GNU Radio 3.8を中心に構築されています。Python3\_maint-3.10 branchは、Python3、PyQt5、GNU Radio 3.10を中心に構築されています。

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Progress (beta)**

これらのoperating systemsは、まだbeta statusです。現在もdevelopment中で、いくつかのfeaturesが不足していることが確認されています。installer内のitemsは、既存のprogramsとconflictしたり、statusが解除されるまでinstallに失敗したりする可能性があります。

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

注: 一部のsoftware toolsは、すべてのOSで動作するわけではありません。[Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)を参照してください。

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
これは、見つからない場合にインストールGUIの起動に必要なPyQtソフトウェア依存関係をインストールします。

次に、お使いのオペレーティングシステムに最も適したオプションを選択します（OSがいずれかのオプションに該当する場合は、自動的に検出されるはずです）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

既存の競合を避けるため、クリーンなオペレーティングシステムにFISSUREをインストールすることを推奨します。FISSURE内のさまざまなツールを操作する際のエラーを避けるため、推奨されているチェックボックスをすべて選択してください（Defaultボタン）。インストール中には複数のプロンプトが表示されます。主に、昇格された権限とユーザー名の入力を求められます。項目の末尾に「Verify」セクションがある場合、インストーラーはその後に続くコマンドを実行し、コマンドによってエラーが発生したかどうかに応じて、チェックボックス項目を緑色または赤色で強調表示します。「Verify」セクションのないチェック済み項目は、インストール後も黒色のままです。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**使用方法**

ターミナルを開き、次のように入力します。
```
fissure
```
詳細な使用方法については、FISSURE の Help メニューを参照してください。

## 詳細

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

以下は、統合レベルがそれぞれ異なる「supported」Hardware の一覧です。

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lessons

FISSURE には、さまざまなテクノロジーや技術に慣れるための便利なガイドが複数用意されています。多くのガイドには、FISSURE に統合された各種ツールの使用手順が含まれています。

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

## Roadmap

* [ ] Hardware の種類、RF protocols、signal parameters、analysis tools を追加
* [ ] より多くの operating systems をサポート
* [ ] FISSURE を中心とした授業用教材を作成（RF Attacks、Wi-Fi、GNU Radio、PyQt など）
* [ ] 選択可能な AI/ML techniques を使用した signal conditioner、feature extractor、signal classifier を作成
* [ ] unknown signals から bitstream を生成する recursive demodulation mechanisms を実装
* [ ] 主要な FISSURE components を generic sensor node deployment scheme へ移行

## Contributing

FISSURE の改善に関する提案を強く歓迎します。以下について意見がある場合は、[Discussions](https://github.com/ainfosec/FISSURE/discussions) page または Discord Server にコメントを残してください。

* New feature suggestions and design changes
* installation steps を含む Software tools
* New lessons または既存 lessons の追加資料
* 関心のある RF protocols
* 統合対象となる、より多くの hardware および SDR types
* Python による IQ analysis scripts
* Installation corrections and improvements

FISSURE の改善に対する Contributions は、開発を迅速化するうえで不可欠です。皆様からの Contributions に深く感謝します。code development を通じて貢献する場合は、repo を fork して pull request を作成してください。

1. プロジェクトを fork
2. feature branch を作成（`git checkout -b feature/AmazingFeature`）
3. 変更を commit（`git commit -m 'Add some AmazingFeature'`）
4. branch に push（`git push origin feature/AmazingFeature`）
5. pull request を作成

バグへの注意を促す [Issues](https://github.com/ainfosec/FISSURE/issues) の作成も歓迎します。

## Collaborating

Assured Information Security, Inc. (AIS) の Business Development に連絡し、FISSURE の collaboration opportunities を提案・正式化してください。これには、software の統合に時間を割くこと、AIS の優秀な人材に technical challenges 向けの solutions を開発してもらうこと、FISSURE を他の platforms/applications に統合することなどが含まれます。

## License

GPL-3.0

License の詳細については、LICENSE file を参照してください。

## Contact

Discord Server に参加: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter をフォロー: [@FissureRF](https://twitter.com/fissurerf)、[@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

以下の developers に謝意を表します。

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

この project に貢献してくださった Dr. Samuel Mantravadi と Joseph Reith に特別な感謝を表します。

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
