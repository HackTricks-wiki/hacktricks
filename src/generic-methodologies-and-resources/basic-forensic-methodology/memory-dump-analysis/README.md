# メモリダンプ解析

{{#include ../../../banners/hacktricks-training.md}}

## 開始

pcap 内の **malware** の **検索**を開始します。[**Malware Analysis**](../malware-analysis.md) で説明されている **tools** を使用してください。

## [Volatility](volatility-cheatsheet.md)

**Volatility はメモリダンプ解析用のオープンソースフレームワークです**。この Python ツールは、外部ソースや VMware VM のダンプを解析し、ダンプの OS プロファイルに基づいてプロセスやパスワードなどのデータを特定します。プラグインによって拡張可能であり、forensic investigation において非常に汎用性の高いツールです。<sup>[[1]](#references)[[2]](#references)</sup>

[**cheatsheetはこちら**](volatility-cheatsheet.md)

## ミニダンプクラッシュレポート

ダンプが小さい場合（数 KB、場合によっては数 MB 程度）、完全なメモリダンプではなく、ミニダンプクラッシュレポートである可能性があります。<sup>[[3]](#references)</sup>

![Volatility - ミニダンプクラッシュレポート: Mini DuMP crash report として識別された小さなダンプファイル](<../../../images/image (532).png>)

Visual Studio がインストールされている場合、このファイルを開いて、プロセス名、アーキテクチャ、例外の詳細、ロードされたモジュールなどの基本情報を確認できます。<sup>[[4]](#references)</sup>

![Volatility - ミニダンプクラッシュレポート: Visual Studio がインストールされている場合、このファイルを開いてプロセス名、アーキテクチャ、例外情報などの基本情報を確認できます](<../../../images/image (263).png>)

例外を検査し、モジュールの逆アセンブリを表示することもできます。<sup>[[4]](#references)</sup>

![Visual Studio の minidump Actions パネル。ネイティブデバッグとシンボルパスの設定オプションを表示](<../../../images/image (142).png>)

![minidump の例外に含まれる命令を Visual Studio で逆アセンブルした画面](<../../../images/image (610).png>)

いずれにしても、Visual Studio はダンプを詳細に解析するための最適なツールではありません。

**IDA** または **Radare** を使用して **開き**、**詳細に**検査する必要があります。

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Files](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Use dump files in the Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
