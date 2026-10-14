# 基本的なフォレンジック手法

{{#include ../../banners/hacktricks-training.md}}

## イメージの作成とマウント


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

**イメージを入手した後、最初に行う必要があるとは限りません**。ただし、ファイル、ファイルシステムのイメージ、メモリイメージ、pcap などがあれば、これらの malware analysis techniques を個別に利用できます。そのため、**こうした作業を覚えておくとよいでしょう**。


{{#ref}}
malware-analysis.md
{{#endref}}

## イメージの調査

デバイスの**フォレンジックイメージ**を渡された場合は、使用されている**パーティションやファイルシステムを分析**し、興味を引く可能性のある**ファイルを復元**するところから始められます（削除済みファイルも含む）。方法については、こちらを参照してください。


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

使用されているOSやプラットフォームによって、調査すべき興味深いアーティファクトは異なります。


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

ロックされたAndroidデバイス、取得方法、メモリイメージの作成については、[Android forensics](android-forensics.md)を参照してください。

## 特定のファイルタイプとソフトウェアの詳細な調査

非常に**疑わしい** **ファイル**がある場合、そのファイルを作成した**ファイルタイプやソフトウェアに応じて**、いくつかの**テクニック**が役立つことがあります。\
興味深いテクニックについては、次のページを参照してください。


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

特に次のページをおすすめします。


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## メモリダンプの調査


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcapの調査


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques が使われている可能性に注意してください。


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
