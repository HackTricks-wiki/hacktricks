# 基本的なフォレンジック手法

{{#include ../../banners/hacktricks-training.md}}

## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## マルウェア解析

これは**イメージを取得したら必ず最初に行うべき手順ではありません**。ただし、ファイル、ファイルシステムイメージ、メモリイメージ、pcapなどを持っている場合、これらのマルウェア解析手法を独立して使用できます。したがって、これらの操作を**念頭に置いておく**と良いです：


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの調査

デバイスの**forensic image**が与えられた場合、使用されている**パーティションやファイルシステム**を解析し、潜在的に**興味深いファイル**（削除済みのものも含む）を**復元**することから始められます。方法は以下を参照してください：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# 基本的なフォレンジック手法



## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## マルウェア解析

これは**イメージを取得したら必ず最初に行うべき手順ではありません**。ただし、ファイル、ファイルシステムイメージ、メモリイメージ、pcapなどを持っている場合、これらのマルウェア解析手法を独立して使用できます。したがって、これらの操作を**念頭に置いておく**と良いです：


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの調査

デバイスの**forensic image**が与えられた場合、使用されている**パーティションやファイルシステム**を解析し、潜在的に**興味深いファイル**（削除済みのものも含む）を**復元**することから始められます。方法は以下を参照してください：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されているOSやプラットフォームによって、検索すべき興味深いアーティファクトは異なります：


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## 特定のファイルタイプやソフトウェアの詳細解析

非常に**疑わしい****ファイル**がある場合、そのファイルを作成した**ファイルタイプやソフトウェア**に応じて、いくつかの**トリック**が有効な場合があります。\
興味深いトリックを学ぶには次のページを読んでください：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に以下のページを挙げておきます：


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの解析


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcapの解析


{{#ref}}
pcap-inspection/
{{#endref}}

## **アンチフォレンジック技術**

アンチフォレンジック技術の使用が考えられることを念頭に置いてください：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 脅威ハンティング


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## 特定のファイルタイプやソフトウェアの詳細解析

非常に**疑わしい****ファイル**がある場合、そのファイルを作成した**ファイルタイプやソフトウェア**に応じて、いくつかの**トリック**が有効な場合があります。\
興味深いトリックを学ぶには次のページを読んでください：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に以下のページを挙げておきます：


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの解析


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcapの解析


{{#ref}}
pcap-inspection/
{{#endref}}

## **アンチフォレンジック技術**

アンチフォレンジック技術の使用が考えられることを念頭に置いてください：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 脅威ハンティング


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
