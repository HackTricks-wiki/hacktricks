# Temel Adli Bilişim Metodolojisi

## İmaj Oluşturma ve Bağlama


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analizi

Bu, **imaja sahip olduktan sonra gerçekleştirilecek ilk adım olmak zorunda değildir**. Ancak bir dosyanız, file-system imajınız, memory imajınız, pcap'iniz varsa bu malware analysis tekniklerini bağımsız olarak kullanabilirsiniz... Bu nedenle **bu işlemleri aklınızda tutmanız** faydalı olacaktır:


{{#ref}}
malware-analysis.md
{{#endref}}

## İmaj İnceleme

Size bir cihazın **forensic imajı** verildiyse **partition'ları ve kullanılan file-system'ı analiz etmeye** ve potansiyel olarak **ilginç dosyaları** (silinmiş olanlar dahil) **kurtarmaya** başlayabilirsiniz. Nasıl yapılacağını burada öğrenin:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kullanılan OS'lere ve hatta platforma bağlı olarak farklı ilginç artifact'ler aranmalıdır:


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

## Belirli dosya türleri ve Software'lerin derinlemesine incelenmesi

Çok **şüpheli** bir **dosyanız** varsa, **dosya türüne ve onu oluşturan software'e** bağlı olarak bazı **trick'ler** faydalı olabilir.\
Bazı ilginç trick'leri öğrenmek için aşağıdaki sayfayı okuyun:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Özellikle şu sayfadan bahsetmek istiyorum:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump İncelemesi


{{#ref}}
memory-dump-analysis/
{{#endref}}

Pcap İncelemesi


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
