# 基本的なForensic Methodology

## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

これは、**イメージを取得した後に最初に実行する必要が必ずしもあるわけではありません**。ただし、ファイル、ファイルシステムイメージ、メモリイメージ、pcapなどがあれば、これらのMalware Analysis techniquesを個別に使用できます。そのため、以下の**アクションを念頭に置いておく**とよいでしょう。


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの検査

デバイスの**forensic image**が与えられた場合、使用されている**パーティションやfile-systemを分析**し、潜在的に**興味深いファイル**（削除されたものも含む）を**復元**できます。方法については、以下を参照してください。


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されているOSやプラットフォームによって、調査すべき興味深いartifactも異なります。


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

## 特定のfile-typesとSoftwareの詳細な検査

非常に**疑わしい** **ファイル**がある場合、**ファイルタイプと、それを作成したSoftwareに応じて**、いくつかの**tricks**が役立つことがあります。\
興味深いtricksについては、以下のページを参照してください:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

次のページについては、特に言及しておきたいと思います:


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

## **Anti-Forensic Techniques**

Anti-Forensic Techniquesが使用される可能性を考慮してください:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
