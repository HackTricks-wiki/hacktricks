# 基本的なフォレンジック手法

{{#include ../../banners/hacktricks-training.md}}

## イメージの作成とマウント

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## マルウェア分析

これは**イメージを取得した後に最初に行うべきステップではありません**。しかし、ファイル、ファイルシステムイメージ、メモリイメージ、pcapなどがある場合は、このマルウェア分析技術を独立して使用できますので、これらのアクションを**念頭に置いておくことが重要です**：

{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの検査

デバイスの**フォレンジックイメージ**が与えられた場合、**パーティションやファイルシステム**を**分析し**、潜在的に**興味深いファイル**（削除されたものも含む）を**回復する**ことができます。方法を学ぶには：

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されるOSやプラットフォームによって、異なる興味深いアーティファクトを検索する必要があります：

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## 特定のファイルタイプとソフトウェアの深い検査

非常に**疑わしい****ファイル**がある場合、**ファイルタイプやそれを作成したソフトウェア**に応じて、いくつかの**トリック**が役立つかもしれません。\
興味深いトリックを学ぶには、以下のページをお読みください：

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に言及したいページがあります：

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの検査

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcapの検査

{{#ref}}
pcap-inspection/
{{#endref}}

## **アンチフォレンジック技術**

アンチフォレンジック技術の使用の可能性を念頭に置いてください：

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 脅威ハンティング

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
