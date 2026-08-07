# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAGではboundary scanを実行できます。boundary scanは、各ピンに対応するembedded boundary-scan cellsやregisterなど、特定の回路を解析します。

JTAG standardでは、**boundary scanを実行するための特定のcommands**が定義されており、次のものが含まれます。

- **BYPASS**を使用すると、他のchipを経由するオーバーヘッドなしに、特定のchipをテストできます。
- **SAMPLE/PRELOAD**は、deviceが通常の動作モードにあるときに、deviceへ入力およびdeviceから出力されるdataをサンプルします。
- **EXTEST**はpinの状態を設定および読み取ります。

次のような他のcommandsもサポートできます。

- deviceを識別する**IDCODE**
- device内部のテストを行う**INTEST**

JTAGulatorのようなtoolを使用すると、これらのinstructionsに遭遇することがあります。

### The Test Access Port

Boundary scanには、4線式の**Test Access Port (TAP)**のテストが含まれます。これは、componentに組み込まれた**JTAG test support**機能へのアクセスを提供する汎用portです。TAPは次の5つのsignalsを使用します。

- Test clock input (**TCK**) TCKは、TAP controllerが1つのactionを実行する頻度（つまり、state machineの次のstateへ移行する頻度）を定義する**clock**です。
- Test mode select (**TMS**) input TMSは**finite state machine**を制御します。clockの各beatで、deviceのJTAG TAP controllerはTMS pinのvoltageを確認します。voltageが特定のthreshold未満の場合、signalはlowとみなされて0として解釈されます。一方、voltageが特定のthresholdを超えている場合、signalはhighとみなされて1として解釈されます。
- Test data input (**TDI**) TDIは、**scan cellsを通じてchipにdataを送る**pinです。JTAGはこのpin上のcommunication protocolを定義していないため、各vendorが定義する必要があります。
- Test data output (**TDO**) TDOは、**chipからdataを送る**pinです。
- Test reset (**TRST**) input オプションのTRSTは、finite state machineを**既知の正常なstate**にresetします。また、TMSを5回連続するclock cyclesの間1に保持すると、TRST pinと同じようにresetが実行されるため、TRSTはオプションです。

これらのpinsがPCB上に表示されている場合もあります。それ以外の場合は、**見つける**必要があります。

### Identifying JTAG pins

JTAG portsを検出する最も速く、ただし最も高価な方法は、この目的専用に作られたdeviceである**JTAGulator**を使用することです（ただし、**UART pinoutsも検出できます**）。

JTAGulatorには、boardのpinsに接続できる**24 channels**があります。その後、**BF attack**を実行し、可能なすべての組み合わせに対して**IDCODE**および**BYPASS**のboundary scan commandsを送信します。応答を受信すると、各JTAG signalに対応するchannelを表示します。

JTAG pinoutsを識別する、より安価ですがはるかに遅い方法は、Arduino-compatible microcontrollerにロードした[**JTAGenum**](https://github.com/cyphunk/JTAGenum/)を使用することです。

**JTAGenum**を使用する場合、まずenumerationに使用する**probing deviceのpinsを定義**します。deviceのpinout diagramを参照し、これらのpinsをtarget deviceのtest pointsに接続する必要があります。

JTAG pinsを識別する**3つ目の方法**は、PCBを**pinoutがないかinspectする**ことです。場合によっては、PCBに**Tag-Connect interface**が用意されていることがあります。これは、boardにJTAG connectorもあることを明確に示します。このinterfaceの外観は、[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)で確認できます。さらに、**PCB上のchipsetsのdatasheetsをinspectする**ことで、JTAG interfacesを示すpinout diagramsが見つかる場合があります。

## SDW

SWDは、debugging用に設計されたARM-specific protocolです。

SWD interfaceには**2つのpins**が必要です。双方向の**SWDIO** signalは、JTAGの**TDIおよびTDO pinsとclock**に相当し、**SWCLK**はJTAGの**TCK**に相当します。多くのdevicesは**Serial Wire or JTAG Debug Port (SWJ-DP)**をサポートしています。これはJTAGとSWDを組み合わせたinterfaceで、targetにSWD probeまたはJTAG probeのいずれかを接続できます。

{{#include ../../banners/hacktricks-training.md}}
