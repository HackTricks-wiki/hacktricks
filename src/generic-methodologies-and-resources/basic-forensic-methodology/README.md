# Temel Adli Bilişim Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## İmaj Oluşturma ve Bağlama


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analizi

**İmajı aldıktan sonra yapılacak ilk adımın bu olması şart değil.** Ancak elinizde bir dosya, dosya sistemi imajı, bellek imajı, pcap... varsa bu malware analiz tekniklerini bağımsız olarak kullanabilirsiniz; bu nedenle **bu işlemleri aklınızda bulundurmanız faydalı olacaktır**:


{{#ref}}
malware-analysis.md
{{#endref}}

## İmajı İnceleme

Bir cihazın **adli bilişim imajı** size verildiyse, kullanılan **bölümleri ve dosya sistemini analiz etmeye** ve potansiyel olarak **ilginç dosyaları** (silinenler dahil) **kurtarmaya** başlayabilirsiniz. Nasıl yapılacağını öğrenmek için:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kullanılan işletim sistemlerine ve hatta platforma bağlı olarak, aranması gereken farklı ilginç artefaktlar olabilir:


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

Kilitli bir Android cihaz, edinim yolları ve bellek imajı alma hakkında bilgi için [Android adli bilişimi](android-forensics.md) sayfasına bakın.

## Belirli Dosya Türlerinin ve Yazılımların Derinlemesine İncelenmesi

Elinizde çok **şüpheli** bir **dosya** varsa, dosya türüne ve dosyayı oluşturan yazılıma bağlı olarak çeşitli **hileler** faydalı olabilir.\
Bazı ilginç hileleri öğrenmek için aşağıdaki sayfayı okuyun:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Şu sayfayı özellikle belirtmek istiyorum:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Bellek Dökümünü İnceleme


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap İnceleme


{{#ref}}
pcap-inspection/
{{#endref}}

## **Adli Bilişimden Kaçınma Teknikleri**

Adli bilişimden kaçınma tekniklerinin olası kullanımını göz önünde bulundurun:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Tehdit Avcılığı


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
