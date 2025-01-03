# Temel Adli Metodoloji

{{#include ../../banners/hacktricks-training.md}}

## Bir Görüntü Oluşturma ve Bağlama

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Kötü Amaçlı Yazılım Analizi

Bu **görüntüyü aldıktan sonra gerçekleştirilecek ilk adım olmak zorunda değil**. Ancak bir dosyanız, bir dosya sistemi görüntüsü, bellek görüntüsü, pcap... varsa bu kötü amaçlı yazılım analiz tekniklerini bağımsız olarak kullanabilirsiniz, bu yüzden **bu eylemleri aklınızda bulundurmak iyi**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Bir Görüntüyü İnceleme

Eğer size bir **adli görüntü** verilirse, **bölümleri, kullanılan dosya sistemini** **analiz etmeye** ve potansiyel olarak **ilginç dosyaları** (silinmiş olanlar dahil) **geri kazanmaya** başlayabilirsiniz. Bunu nasıl yapacağınızı öğrenin:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kullanılan işletim sistemlerine ve hatta platforma bağlı olarak farklı ilginç artefaktlar aranmalıdır:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Belirli Dosya Türleri ve Yazılımlarının Derin İncelemesi

Eğer çok **şüpheli** bir **dosyanız** varsa, o zaman **dosya türüne ve onu oluşturan yazılıma** bağlı olarak birkaç **numara** faydalı olabilir.\
Bazı ilginç numaraları öğrenmek için aşağıdaki sayfayı okuyun:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Özel olarak şu sayfayı belirtmek istiyorum:

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

## **Anti-Adli Teknikler**

Anti-adli tekniklerin olası kullanımını aklınızda bulundurun:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Tehdit Avı

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
