# 基本的なフォレンジック手法

{{#include ../../banners/hacktricks-training.md}}

## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

これは、**イメージを取得した後に必ずしも最初に実行する必要はありません**。ただし、ファイル、ファイルシステムイメージ、メモリイメージ、pcap などがある場合は、これらの malware analysis techniques を個別に使用できます。そのため、以下の**アクションを念頭に置いておく**とよいでしょう。


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの調査

デバイスの**フォレンジックイメージ**を受け取った場合は、使用されている**パーティションやファイルシステムを分析**し、潜在的に**興味深いファイル**（削除されたものも含む）を**復元**できます。方法については、以下を参照してください。


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されている OS やプラットフォームによって、調査すべき興味深いアーティファクトは異なります。


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

## 特定のファイルタイプと Software の詳細な調査

非常に**不審な** **file** がある場合、**ファイルタイプとそれを作成した software に応じて**、いくつかの**trick**が役立つ可能性があります。\
興味深い trick については、以下のページを参照してください。


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に以下のページを紹介します:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの調査


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap の調査


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques が使用される可能性を考慮してください:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
