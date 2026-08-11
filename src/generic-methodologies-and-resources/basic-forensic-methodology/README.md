# Temel Adli Bilişim Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## İmaj Oluşturma ve Bağlama


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analizi

**İmajı aldıktan** sonra gerçekleştirilecek ilk adımın bu olması **gerekmez**. Ancak bir dosyanız, dosya sistemi imajınız, bellek imajınız, pcap'iniz varsa bu malware analizi tekniklerini bağımsız olarak kullanabilirsiniz. Bu nedenle **bu işlemleri aklınızda bulundurmanız** faydalıdır:


{{#ref}}
malware-analysis.md
{{#endref}}

## İmaj İnceleme

Bir cihazın **adli imajı** size verildiyse, **bölümleri ve kullanılan dosya sistemini analiz etmeye** ve potansiyel olarak **ilginç dosyaları** (silinmiş olanlar dahil) **kurtarmaya** başlayabilirsiniz. Nasıl yapılacağını burada öğrenin:


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

## Belirli Dosya Türleri ve Yazılımların Derinlemesine İncelenmesi

Elinizde çok **şüpheli** bir **dosya** varsa, onu oluşturan **dosya türüne ve yazılıma bağlı olarak** çeşitli **hileler** faydalı olabilir.\
Bazı ilginç hileleri öğrenmek için aşağıdaki sayfayı okuyun:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Şu sayfaya özellikle değinmek istiyorum:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Bellek Dökümü İncelemesi


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

## References

{{#include ../../banners/hacktricks-training.md}}
