# Bellek dökümü analizi

{{#include ../../../banners/hacktricks-training.md}}

## Başlangıç

**Kötü amaçlı yazılım** için pcap içinde **arama** yapmaya başlayın. [**Kötü Amaçlı Yazılım Analizi**](../malware-analysis.md) bölümünde belirtilen **araçları** kullanın.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility, bellek dökümü analizi için ana açık kaynak çerçevesidir**. Bu Python aracı, dış kaynaklardan veya VMware sanal makinelerinden gelen dökümleri analiz eder, dökümün işletim sistemi profiline dayalı olarak süreçler ve şifreler gibi verileri tanımlar. Eklentilerle genişletilebilir, bu da onu adli soruşturmalar için son derece çok yönlü hale getirir.

**[Buradan bir kılavuz bulabilirsiniz](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Mini döküm çökme raporu

Döküm küçükse (sadece birkaç KB, belki birkaç MB) muhtemelen bir mini döküm çökme raporudur ve bellek dökümü değildir.

![](<../../../images/image (216).png>)

Eğer Visual Studio yüklüyse, bu dosyayı açabilir ve süreç adı, mimari, istisna bilgisi ve yürütülen modüller gibi bazı temel bilgileri bağlayabilirsiniz:

![](<../../../images/image (217).png>)

Ayrıca istisnayı yükleyebilir ve decompile edilmiş talimatları görebilirsiniz.

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

Her neyse, Visual Studio, dökümün derinlemesine analizi için en iyi araç değildir.

Bunu **IDA** veya **Radare** kullanarak **derinlemesine** incelemek için **açmalısınız**.

​

{{#include ../../../banners/hacktricks-training.md}}
