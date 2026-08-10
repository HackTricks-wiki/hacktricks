# メモリダンプ解析

## 開始

pcap 内で **malware** の**検索を開始**します。[**Malware Analysis**](../malware-analysis.md) で言及されている **tools** を使用してください。

## [Volatility](volatility-cheatsheet.md)

**Volatility はメモリダンプ解析用のオープンソースフレームワークです**。この Python tool は、外部ソースまたは VMware VM から取得したダンプを解析し、ダンプの OS profile に基づいてプロセスやパスワードなどのデータを特定します。plugin による拡張が可能で、forensic investigations において非常に汎用性があります。<sup>[[1]](#references)[[2]](#references)</sup>

[**cheatsheet はこちら**](volatility-cheatsheet.md)

## ミニダンプのクラッシュレポート

ダンプが小さい場合（数 KB 程度、場合によっては数 MB）、完全なメモリダンプではなく、ミニダンプのクラッシュレポートである可能性があります。<sup>[[3]](#references)</sup>

![Volatility - ミニダンプのクラッシュレポート: Mini DuMP クラッシュレポートとして識別された小さなダンプファイル](<../../../images/image (532).png>)

Visual Studio がインストールされている場合、このファイルを開いて、プロセス名、アーキテクチャ、例外の詳細、ロードされたモジュールなどの基本情報を確認できます。<sup>[[4]](#references)</sup>

![Volatility - ミニダンプのクラッシュレポート: Visual Studio がインストールされている場合、このファイルを開いて、プロセス名、アーキテクチャ、例外情報などの基本情報を確認できます](<../../../images/image (263).png>)

例外を調査し、モジュールの逆アセンブリを表示することもできます。<sup>[[4]](#references)</sup>

![Visual Studio の minidump Actions パネル。ネイティブデバッグとシンボルパスの設定オプション](<../../../images/image (142).png>)

![minidump の例外に含まれる命令を Visual Studio で逆アセンブルした画面](<../../../images/image (610).png>)

いずれにせよ、Visual Studio はダンプを詳細に解析するのに最適な tool ではありません。

**IDA** または **Radare** を使用して**開き**、**詳細に**調査する必要があります。

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Files](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Use dump files in the Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
