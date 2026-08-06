# Modbusプロトコル

{{#include ../../banners/hacktricks-training.md}}

## Modbusプロトコルの概要

Modbusプロトコルは、Industrial Automation and Control Systemsで広く使用されているプロトコルです。Modbusを使用すると、programmable logic controllers（PLCs）、センサー、アクチュエーター、その他の産業用デバイスなど、さまざまなデバイス間で通信できます。Modbusプロトコルを理解することは非常に重要です。これはICSで最も使用されている通信プロトコルであり、sniffingや、さらにはPLCsへのコマンドのinjectingに対して、大きなattack surfaceを持っているためです。

ここでは、プロトコルの概要と動作の性質を説明するため、概念をポイントごとに示します。ICS system securityにおける最大の課題は、実装とアップグレードのコストです。これらのプロトコルと標準は80年代および90年代初頭に設計されたもので、現在も広く使用されています。1つの産業環境には多数のデバイスと接続が存在するため、デバイスのアップグレードは非常に困難です。そのため、hackersは古いプロトコルを扱ううえで有利な立場にあります。Modbusへの攻撃は、実質的に避けられません。産業の運用において重要である限り、アップグレードされないまま使用され続けるためです。

## Client-Serverアーキテクチャ

Modbusプロトコルは通常、Client-Serverアーキテクチャで使用されます。この構成では、master device（client）が1つ以上のslave devices（servers）との通信を開始します。これはMaster-Slaveアーキテクチャとも呼ばれ、SPIやI2Cなどを使用するelectronicsやIoTで広く利用されています。

## SerialおよびEthernetバージョン

Modbusプロトコルは、Serial CommunicationとEthernet Communicationsの両方に対応するよう設計されています。Serial Communicationはlegacy systemsで広く使用されている一方、modern devicesは高速なデータレートを提供し、modern industrial networksにより適したEthernetをサポートしています。

## データ表現

Modbusプロトコルでは、データはASCIIまたはBinaryとして送信されます。ただし、古いデバイスとの互換性が高く、コンパクトであるため、Binary形式が使用されています。

## Function Codes

Modbusプロトコルは、PLCsやさまざまなcontrol devicesを操作するために使用される、特定のfunction codesの送信によって動作します。この部分を理解することは重要です。function codesを再送信することで、replay attacksを実行できるためです。Legacy devicesはデータ送信に対する暗号化をサポートしておらず、通常はそれらを接続する長い配線が存在します。その結果、配線のtamperingや、データのcapturing/injectingが可能になります。

## Modbusのアドレス指定

ネットワーク上の各デバイスには、デバイス間の通信に不可欠な固有のアドレスがあります。Modbus RTUやModbus TCPなどのプロトコルは、アドレス指定を実装するために使用され、データ送信におけるtransport layerのように機能します。転送されるデータは、メッセージを含むModbusプロトコル形式になっています。

さらに、Modbusは送信データのintegrityを確保するためにerror checksも実装しています。しかし何よりも、ModbusはOpen Standardであり、誰でも自分のデバイスに実装できます。このことにより、Modbusプロトコルはglobal standardとなり、industrial automation industryで広く普及しました。

大規模に使用されている一方で、アップグレードが不足しているため、Modbusへの攻撃は、そのattack surfaceによって大きな優位性をもたらします。ICSはデバイス間の通信に大きく依存しており、デバイスに対する攻撃はindustrial systemsの運用に危険を及ぼす可能性があります。攻撃者が通信媒体を特定できれば、replay、data injection、data sniffing、leak、Denial of Service、data forgeryなどの攻撃を実行できます。

{{#include ../../banners/hacktricks-training.md}}
