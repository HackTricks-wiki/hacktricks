# メモリダンプ分析

{{#include ../../../banners/hacktricks-training.md}}

## 開始

**マルウェア**をpcap内で**検索**し始めます。[**マルウェア分析**](../malware-analysis.md)で言及されている**ツール**を使用してください。

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatilityはメモリダンプ分析のための主要なオープンソースフレームワークです**。このPythonツールは、外部ソースやVMware VMからのダンプを分析し、ダンプのOSプロファイルに基づいてプロセスやパスワードなどのデータを特定します。プラグインで拡張可能であり、法医学的調査に非常に柔軟です。

**[ここにチートシートがあります](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## ミニダンプクラッシュレポート

ダンプが小さい場合（数KB、場合によっては数MB）これはおそらくミニダンプクラッシュレポートであり、メモリダンプではありません。

![](<../../../images/image (216).png>)

Visual Studioがインストールされている場合、このファイルを開いてプロセス名、アーキテクチャ、例外情報、実行中のモジュールなどの基本情報をバインドできます：

![](<../../../images/image (217).png>)

例外をロードしてデコンパイルされた命令を見ることもできます

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

いずれにせよ、Visual Studioはダンプの深さの分析を行うための最良のツールではありません。

**IDA**または**Radare**を使用して**深く**検査するべきです。

​

{{#include ../../../banners/hacktricks-training.md}}
