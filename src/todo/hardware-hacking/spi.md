# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

SPI（Serial Peripheral Interface）は、組み込みシステムでIC（Integrated Circuits）間の短距離通信に使用される同期シリアル通信プロトコルです。SPI Communication Protocolは、ClockとChip Select Signalによって制御されるmaster-slave architectureを使用します。master-slave architectureは、EEPROM、センサー、制御デバイスなどの外部周辺機器を管理するmaster（通常はマイクロプロセッサ）で構成され、これらの周辺機器がslaveとみなされます。

複数のslaveを1つのmasterに接続できますが、slave同士は通信できません。slaveは、clockとchip selectという2つのピンによって管理されます。SPIは同期通信プロトコルであるため、入力ピンと出力ピンはclock信号に従います。chip selectは、masterがslaveを選択して通信するために使用されます。chip selectがhighの場合、slave deviceは選択されていません。一方、lowの場合はchipが選択され、masterはslaveと通信します。

MOSI（Master Out, Slave In）とMISO（Master In, Slave Out）は、データの送受信を担当します。chip selectがlowに保持されている間、MOSIピンを通じてslave deviceにデータが送信されます。入力データには、slave deviceのベンダーが提供するdatasheetに基づき、命令、メモリアドレス、またはデータが含まれます。有効な入力を受け取ると、MISOピンがmasterへのデータ送信を担当します。出力データは、入力が終了した直後の次のclock cycleで正確に送信されます。MISOピンは、データの送信が完全に完了するまで、またはmasterがchip select pinをhighに設定するまでデータを送信します（その場合、slaveは送信を停止し、masterはそのclock cycle以降を受信しません）。

## EEPROMからのFirmwareのDump

Firmwareのdumpは、firmwareを分析して脆弱性を発見する際に役立ちます。多くの場合、firmwareはインターネット上で入手できないか、model number、versionなどの要因の違いにより利用できません。そのため、物理deviceから直接firmwareを抽出することは、脅威を調査する際に対象を正確に絞り込むうえで役立ちます。

Serial Consoleを取得できると便利ですが、ファイルがread-onlyであることも少なくありません。これにはさまざまな理由があり、分析が制限されます。たとえば、パッケージの送受信に必要なtoolがfirmware内に存在しない場合があります。そのため、binaryを抽出してreverse engineerすることは現実的ではありません。そこで、システム上にfirmware全体をdumpし、分析のためにbinaryを抽出できるようにすると非常に役立ちます。

また、red teamingやdeviceへの物理アクセスを行う際、firmwareをdumpしてファイルを変更したり、malicious fileをinjectしたりしたうえでmemoryにreflashすることもできます。これはdeviceにbackdoorをimplantするのに役立ちます。そのため、firmware dumpingによって多数の可能性が開かれます。

### CH341A EEPROM Programmer and Reader

このdeviceは、EEPROMからfirmwareをdumpしたり、firmware fileをreflashしたりするための安価なtoolです。computerのBIOS chip（単なるEEPROMです）を扱う際によく利用されます。このdeviceはUSB経由で接続し、使用開始に必要なtoolも最小限です。また、通常は作業を短時間で完了できるため、物理deviceへのアクセス時にも役立ちます。

![drawing](../../images/board_image_ch341a.jpg)

EEPROM memoryをCH341a Programmerに接続し、deviceをcomputerに接続します。deviceが検出されない場合は、computerにdriverをインストールしてみてください。また、EEPROMが正しい向きで接続されていることを確認してください（通常は、VCC PinをUSB connectorに対して逆向きに配置します）。そうしないと、softwareがchipを検出できません。必要に応じて、次のdiagramを参照してください。

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

最後に、flashrom、G-Flash（GUI）などのsoftwareを使用してfirmwareをdumpします。G-Flashは最小限のGUI toolで高速に動作し、EEPROMを自動的に検出します。documentationを詳しく確認せずにfirmwareを素早く抽出する必要がある場合に役立ちます。

![drawing](../../images/connected_status_ch341a.jpg)

firmwareをdumpした後は、binary fileを分析できます。strings、hexdump、xxd、binwalkなどのtoolを使用すると、firmwareだけでなく、file system全体からも多くの情報を抽出できます。

firmwareの内容を抽出するには、binwalkを使用できます。Binwalkはhex signatureを分析してbinary file内のfileを特定し、それらをextractできます。
```
binwalk -e <filename>
```
使用するツールや設定に応じて、`.bin` または `.rom` になります。

> [!CAUTION]
> ファームウェアの抽出は繊細な作業であり、多くの忍耐を必要とします。取り扱いを誤ると、ファームウェアが破損したり、完全に消去されたりして、デバイスが使用不能になる可能性があります。ファームウェアの抽出を試みる前に、対象デバイスについて十分に調査することを推奨します。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Pirate Bus の PINOUT に SPI 接続用の **MOSI** および **MISO** のピンが示されていても、SPI によってはピンが DI および DO と示されている場合があることに注意してください。**MOSI -> DI、MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Bus の PINOUT に MOSI および MISO のピンが示されていても、SPI によってはピンが MOSI および MISO と示されている場合があります。](<../../images/image (360).png>)

Windows または Linux では、[**`flashrom`**](https://www.flashrom.org/Flashrom) プログラムを使用して、次のようなコマンドを実行し、flash memory の内容を dump できます:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
