# Temel Adli Bilişim Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Bir İmaj Oluşturma ve Bağlama


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analizi

Bu, **imaja sahip olduğunuzda gerçekleştirilecek ilk adım olmak zorunda değildir**. Ancak bir dosyanız, dosya sistemi imajınız, bellek imajınız, pcap'iniz... varsa bu malware analizi tekniklerini bağımsız olarak kullanabilirsiniz; bu nedenle **bu işlemleri aklınızda tutmanız iyi olacaktır**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Bir İmajı İnceleme

Size bir cihazın **adli bilişim imajı** verildiyse, kullanılan **bölümleri ve dosya sistemini analiz etmeye** ve potansiyel olarak **ilginç dosyaları** (silinmiş olanlar dahil) **kurtarmaya** başlayabilirsiniz. Nasıl yapılacağını şuradan öğrenin:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kullanılan işletim sistemlerine ve hatta platforma bağlı olarak farklı ilginç artifact'ler aranmalıdır:


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

## Belirli Dosya Türlerinin ve Yazılımların Derinlemesine İncelenmesi

Çok **şüpheli** bir **dosyanız** varsa, dosyayı oluşturan **dosya türüne ve yazılıma bağlı olarak** çeşitli **hileler** faydalı olabilir.\
Bazı ilginç hileleri öğrenmek için aşağıdaki sayfayı okuyun:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Şu sayfaya özellikle değinmek istiyorum:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Bellek Dökümünü İnceleme


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap İncelemesi


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Teknikler**

Anti-forensic tekniklerin olası kullanımını aklınızda bulundurun:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
