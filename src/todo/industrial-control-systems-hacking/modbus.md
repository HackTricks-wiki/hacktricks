# Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Modbus の概要

Modbus は、PLC、センサー、アクチュエーター、その他の産業用デバイスで広く実装されているオープンなアプリケーション層プロトコルです。その request/response モデルでは、function code を通じて coil と register を公開します。そのため security testing では、単に TCP port 502 を発見するだけでなく、不正な読み取り・書き込み、トラフィックの観察、replay、安全でないデバイス動作に焦点を当てます。<sup>[[1]](#references)</sup>

多くの導入環境では、アップグレードに停止、再認証、またはフィールドデバイスの交換が必要となるため、legacy のシリアル機器が使い続けられています。従来の Modbus は confidentiality も peer authentication も提供しません。Modbus Security は、X.509 証明書と TCP port 802 を使用する、TLS ベースの別個の profile です。仕様が公開され、独立して実装可能であるため、vendor の動作や optional function のサポート状況は異なります。したがって、想定するのではなく fingerprinting を行うべきです。<sup>[[1]](#references)[[2]](#references)</sup>

## Client-Server アーキテクチャ

現在の用語では、**client** が transaction を開始し、**server** が response を返します。古いドキュメントでは **master/slave** という用語が使われています。このアプリケーション上の関係を SPI や I2C と混同しないでください。これらは異なる bus protocol です。<sup>[[1]](#references)</sup>

## シリアルおよび Ethernet トランスポート

同じ Modbus application data を、シリアル variant（RTU または ASCII framing）および Modbus TCP で転送できます。Modbus TCP は MBAP header を追加し、通常 TCP port 502 を使用します。シリアル RTU は compact binary framing と CRC を使用する一方、シリアル ASCII は byte を hexadecimal character として表現し、LRC を使用します。<sup>[[1]](#references)[[3]](#references)</sup>

## データ表現

data model は、single-bit の coil/discrete input と、16-bit の input/holding register で構成されます。複数 register の値、byte order、scaling、意味は device-specific であり、vendor の register map と照合して確認する必要があります。<sup>[[1]](#references)</sup>

## Function code

Function code は、coil の読み取り（`0x01`）、holding register の読み取り（`0x03`）、単一の coil/register の書き込み（`0x05`/`0x06`）、複数の coil/register の書き込み（`0x0F`/`0x10`）などの操作を選択します。capture した write request は、導入環境に compensating authentication や process-state check がない場合、replay 可能なことがあります。長いシリアル配線に対して authorized physical access がある場合、assessor は electrical interface、termination、安全な接続方法を特定した後、配線上で直接 frame を capture または inject することもできます。いずれの操作も physical process に影響を与える可能性があるため、lab 環境または明示的な operational authorization を使用してください。<sup>[[1]](#references)[[3]](#references)</sup>

## アドレス指定

シリアルデバイスは unit address を使用します。Modbus TCP は IP addressing に加えて MBAP header 内の Unit Identifier を使用します。これは、TCP-to-serial gateway が downstream unit に request をルーティングする場合に特に重要です。製品ドキュメントに示される register reference は one-based（`40001`）である一方、protocol address は zero-based の場合があり、これは off-by-one error の一般的な原因です。<sup>[[1]](#references)[[3]](#references)</sup>

シリアル framing には transmission-error check（RTU では CRC、ASCII では LRC）が含まれ、TCP は通常の transport checksum を提供します。これらは偶発的な破損を検出するものであり、cryptographic integrity や origin authentication ではありません。<sup>[[3]](#references)</sup>

authorized assessment では、exposure、許可された function code、書き込み可能な address range、exception handling、rate limit、さらに network segmentation や Modbus-aware firewall が client を制限しているかどうかをテストします。関連する threat には、passive disclosure、unauthorized command injection、replay、data forgery、denial of service があります。一見小さな register の変更でも physical process を変化させる可能性があるため、すべての active test を process owner と調整してください。

## References

- [1] [Modbus Organization — Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol および implementation guide](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus over Serial Line Specification and Implementation Guide V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
