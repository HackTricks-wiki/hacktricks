# SPI

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>

## 基本情報

SPI（Serial Peripheral Interface）は、組み込みシステムで使用される同期シリアル通信プロトコルであり、IC（集積回路）間の短距離通信に使用されます。SPI通信プロトコルは、クロックとチップ選択信号によってオーケストレートされるマスター-スレーブアーキテクチャを使用します。マスター-スレーブアーキテクチャには、通常、EEPROM、センサー、制御デバイスなどの外部ペリフェラルを管理するマスター（通常はマイクロプロセッサ）が含まれ、これらはスレーブと見なされます。

複数のスレーブをマスターに接続できますが、スレーブ同士は通信できません。スレーブは、クロックとチップ選択の2つのピンによって管理されます。SPIは同期通信プロトコルであるため、入力および出力ピンはクロック信号に従います。チップ選択は、マスターがスレーブを選択してそれとやり取りするために使用されます。チップ選択が高い場合、スレーブデバイスは選択されず、低い場合はチップが選択され、マスターがスレーブとやり取りします。

MOSI（Master Out, Slave In）およびMISO（Master In, Slave Out）はデータの送信と受信に責任があります。データは、MOSIピンを介してスレーブデバイスに送信され、チップ選択が低い状態で保持されます。入力データには、スレーブデバイスのベンダーのデータシートに従って命令、メモリアドレス、またはデータが含まれます。有効な入力後、MISOピンはデータをマスターに送信する責任があります。出力データは、入力が終了した直後の次のクロックサイクルで送信されます。MISOピンは、データが完全に送信されるか、マスターがチップ選択ピンを高に設定するまでデータを送信し続けます（その場合、スレーブは送信を停止し、マスターはそのクロックサイクル以降にリッスンしません）。

## EEPROMからファームウェアをダンプする

ファームウェアをダンプすることは、ファームウェアを分析し、その中の脆弱性を見つけるのに役立ちます。ファームウェアがインターネット上で利用できないか、モデル番号、バージョンなどの要因の変化により関連性がない場合がよくあります。したがって、物理デバイスからファームウェアを直接抽出することは、脅威を探す際に特定性を持たせるのに役立ちます。

シリアルコンソールを取得することは役立ちますが、ファイルが読み取り専用であることがよくあります。これは、さまざまな理由により分析が制約される原因となります。たとえば、パッケージの送受信に必要なツールがファームウェアに含まれていない場合があります。そのため、バイナリを抽出してリバースエンジニアリングすることは実現不可能です。したがって、ファームウェア全体をシステムにダンプし、分析のためにバイナリを抽出することは非常に役立ちます。

また、レッドチーム活動やデバイスへの物理アクセスを取得する際に、ファームウェアをダンプすることでファイルを変更したり、悪意のあるファイルを注入してからそれをメモリに再フラッシュすることができ、デバイスにバックドアを埋め込むのに役立ちます。したがって、ファームウェアのダンプによって解除される可能性がある数多くの可能性があります。

### CH341A EEPROMプログラマーおよびリーダー

このデバイスは、EEPROMからファームウェアをダンプし、ファームウェアファイルでそれらを再フラッシュするための安価なツールです。これは、コンピュータのBIOSチップ（単なるEEPROM）で作業するための人気のある選択肢となっています。このデバイスはUSB経由で接続され、開始するのに最小限のツールが必要です。また、通常、タスクを迅速に完了するため、物理デバイスアクセスでも役立つことがあります。

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

EEPROMメモリをCH341aプログラマーに接続し、デバイスをコンピュータに接続します。デバイスが検出されない場合は、コンピュータにドライバをインストールしてみてください。また、EEPROMが適切な向きで接続されていることを確認してください（通常、VCCピンをUSBコネクタの逆向きに配置します）。そうでないと、ソフトウェアがチップを検出できません。必要に応じて図を参照してください：

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

最後に、ファームウェアをダンプするためにflashrom、G-Flash（GUI）などのソフトウェアを使用します。G-Flashは、最小限のGUIツールであり、高速でEEPROMを自動的に検出します。これは、ドキュメントをあまりいじらずに迅速にファームウェアを抽出する必要がある場合に役立ちます。

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

ファームウェアをダンプした後、バイナリファイルで分析を行うことができます。strings、hexdump、xxd、binwalkなどのツールを使用して、ファームウェアやファイルシステム全体に関する多くの情報を抽出することができます。

ファームウェアからコンテンツを抽出するには、binwalkを使用できます。Binwalkは16進数のシグネチャを分析し、バイナリファイル内のファイルを識別し、それらを抽出することができます。
```
binwalk -e <filename>
```
ファイルは、使用されるツールと構成に応じて、.binまたは.rom形式である可能性があります。

{% hint style="danger" %}
ファームウェアの抽出は繊細なプロセスであり、多くの忍耐が必要です。誤った取り扱いはファームウェアを破損させる可能性があり、デバイスを完全に消去して使用不能にすることさえあります。ファームウェアを抽出しようとする前に、特定のデバイスを研究することをお勧めします。
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Pirate BusのPINOUTが**MOSI**と**MISO**のためのピンを示している場合でも、一部のSPIはピンをDIとDOとして示す場合があることに注意してください。**MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

WindowsまたはLinuxでは、[**`flashrom`**](https://www.flashrom.org/Flashrom)プログラムを使用して、次のようにフラッシュメモリの内容をダンプできます：
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
