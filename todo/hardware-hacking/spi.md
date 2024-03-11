<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**する
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してください。

</details>


# 基本情報

SPI（Serial Peripheral Interface）は、IC（組み込みシステム用の短距離通信に使用される同期シリアル通信プロトコル）であります。SPI通信プロトコルは、クロックとチップセレクト信号によってオーケストレートされるマスター-スレーブアーキテクチャを使用します。マスター-スレーブアーキテクチャには、通常、EEPROM、センサー、制御デバイスなどの外部ペリフェラルを管理するマスター（通常はマイクロプロセッサ）が含まれ、これらはスレーブと見なされます。

複数のスレーブをマスターに接続できますが、スレーブ同士は通信できません。スレーブは、クロックとチップセレクトの2つのピンによって管理されます。SPIは同期通信プロトコルであるため、入力および出力ピンはクロック信号に従います。チップセレクトは、マスターがスレーブを選択してそれとやり取りするために使用されます。チップセレクトが高い場合、スレーブデバイスは選択されておらず、低い場合はチップが選択され、マスターがスレーブとやり取りします。

MOSI（Master Out, Slave In）およびMISO（Master In, Slave Out）はデータの送信と受信に責任があります。データは、MOSIピンを介してチップセレクトが低い状態でスレーブデバイスに送信されます。入力データには、スレーブデバイスのベンダーのデータシートに従って、命令、メモリアドレス、またはデータが含まれます。有効な入力後、MISOピンはデータをマスターに送信する責任があります。出力データは、入力が終了した直後の次のクロックサイクルで送信されます。MISOピンは、データが完全に送信されるか、マスターがチップセレクトピンを高に設定するまでデータを送信します（その場合、スレーブは送信を停止し、マスターはそのクロックサイクル以降にリッスンしません）。

# フラッシュのダンプ

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Pirate BusのPINOUTにはSPIに接続するための**MOSI**と**MISO**のピンが示されていますが、一部のSPIはDIとDOとしてピンを示す場合があります。**MOSI -> DI、MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

WindowsまたはLinuxでは、次のように実行して、フラッシュメモリの内容をダンプするためにプログラム[**`flashrom`**](https://www.flashrom.org/Flashrom)を使用できます：
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**してください
- **HackTricks**（https://github.com/carlospolop/hacktricks）および**HackTricks Cloud**（https://github.com/carlospolop/hacktricks-cloud）のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください

</details>
