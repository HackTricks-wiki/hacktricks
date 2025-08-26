# 基本的なフォレンジック手法

{{#include ../../banners/hacktricks-training.md}}

## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## マルウェア解析

この作業は **イメージを入手した直後に必ず最初に行う必要があるわけではありません**。しかし、ファイル、ファイルシステムイメージ、メモリイメージ、pcap... を持っている場合は、これらのマルウェア解析手法を独立して使用できます。したがって、これらの操作を**念頭に置いておく**ことが有用です：


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの検査

デバイスの**フォレンジックイメージ**が与えられた場合、使用されている**パーティションやファイルシステムの解析**を開始し、潜在的に**興味深いファイル**（削除されたものも含む）の**復元**を行うことができます。方法は次を参照してください：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# 基本的なフォレンジック手法



## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## マルウェア解析

この作業は **イメージを入手した直後に必ず最初に行う必要があるわけではありません**。しかし、ファイル、ファイルシステムイメージ、メモリイメージ、pcap... を持っている場合は、これらのマルウェア解析手法を独立して使用できます。したがって、これらの操作を**念頭に置いておく**ことが有用です：


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの検査

デバイスの**フォレンジックイメージ**が与えられた場合、使用されている**パーティションやファイルシステムの解析**を開始し、潜在的に**興味深いファイル**（削除されたものも含む）の**復元**を行うことができます。方法は次を参照してください：


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されている OS やプラットフォームによって、検索すべき興味深いアーティファクトは異なります：


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

## 特定のファイルタイプやソフトウェアの詳細な解析

非常に**疑わしい****ファイル**を持っている場合、そのファイルを作成した**ファイルタイプやソフトウェア**に応じて、いくつかの**トリック**が有効な場合があります。\
次のページを読んで、いくつかの興味深いトリックを学んでください：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に次のページを推奨します：


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの解析


{{#ref}}
memory-dump-analysis/
{{#endref}}

## pcap の解析


{{#ref}}
pcap-inspection/
{{#endref}}

## **アンチフォレンジック技術**

アンチフォレンジック技術が使用されている可能性を念頭に置いてください：


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 脅威ハンティング


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## 特定のファイルタイプやソフトウェアの詳細な解析

非常に**疑わしい****ファイル**を持っている場合、そのファイルを作成した**ファイルタイプやソフトウェア**に応じて、いくつかの**トリック**が有効な場合があります。\
次のページを読んで、いくつかの興味深いトリックを学んでください：


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に次のページを推奨します：


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの解析


{{#ref}}
memory-dump-analysis/
{{#endref}

## pcap の解析


{{#ref}}
pcap-inspection/
{{#endref}

## **アンチフォレンジック技術**

アンチフォレンジック技術が使用されている可能性を念頭に置いてください：


{{#ref}}
anti-forensic-techniques.md
{{#endref}

## 脅威ハンティング


{{#ref}}
file-integrity-monitoring.md
{{#endref}

{{#include ../../banners/hacktricks-training.md}}
