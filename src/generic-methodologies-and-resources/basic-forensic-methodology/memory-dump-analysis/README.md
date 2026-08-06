# メモリダンプ解析

{{#include ../../../banners/hacktricks-training.md}}

## 開始

pcap 内で **malware** を **検索** することから始めます。[**Malware Analysis**](../malware-analysis.md) で説明されている **tools** を使用してください。

## [Volatility](volatility-cheatsheet.md)

**Volatility はメモリダンプ解析用の主要なオープンソース framework です**。この Python tool は、外部ソースまたは VMware VM から取得した dump を解析し、dump の OS profile に基づいてプロセスやパスワードなどのデータを特定します。plugin によって拡張可能であり、forensic investigation において非常に汎用性の高い tool です。

[**cheatsheet はこちら**](volatility-cheatsheet.md)

## ミニダンプのクラッシュレポート

dump のサイズが小さい場合（数 KB、場合によっては数 MB 程度）、memory dump ではなく、mini dump のクラッシュレポートである可能性が高いです。

![Volatility - ミニダンプのクラッシュレポート: dump のサイズが小さい場合（数 KB、場合によっては数 MB 程度）、memory dump ではなく、mini dump のクラッシュレポートである可能性が高い](<../../../images/image (532).png>)

Visual Studio がインストールされている場合、このファイルを開いて、プロセス名、architecture、exception 情報、実行中の module などの基本情報を確認できます。

![Volatility - ミニダンプのクラッシュレポート: Visual Studio がインストールされている場合、このファイルを開いて、プロセス名、architecture、exception 情報などの基本情報を確認できます](<../../../images/image (263).png>)

exception を読み込み、decompiled された instruction を確認することもできます。

![Volatility - ミニダンプのクラッシュレポート: exception を読み込み、decompiled された instruction を確認することもできます](<../../../images/image (142).png>)

![Volatility - ミニダンプのクラッシュレポート: exception を読み込み、decompiled された instruction を確認することもできます](<../../../images/image (610).png>)

いずれにせよ、Visual Studio は dump を詳細に解析するための最適な tool ではありません。

**IDA** または **Radare** を使用して **開き**、**詳細に** 検査する必要があります。

{{#include ../../../banners/hacktricks-training.md}}
