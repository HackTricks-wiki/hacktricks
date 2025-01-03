{{#include ../../banners/hacktricks-training.md}}

# Temel

Bir temel, bir sistemin belirli bölümlerinin anlık görüntüsünü almayı içerir ve **değişiklikleri vurgulamak için gelecekteki bir durumla karşılaştırma yapar**.

Örneğin, dosya sistemindeki her dosyanın hash'ini hesaplayıp saklayarak hangi dosyaların değiştirildiğini bulabilirsiniz.\
Bu, oluşturulan kullanıcı hesapları, çalışan süreçler, çalışan hizmetler ve çok fazla değişmemesi gereken veya hiç değişmemesi gereken diğer şeyler için de yapılabilir.

## Dosya Bütünlüğü İzleme

Dosya Bütünlüğü İzleme (FIM), dosyalardaki değişiklikleri izleyerek BT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. İki ana adımı içerir:

1. **Temel Karşılaştırması:** Değişiklikleri tespit etmek için gelecekteki karşılaştırmalar için dosya özellikleri veya kriptografik kontrol toplamları (MD5 veya SHA-2 gibi) kullanarak bir temel oluşturun.
2. **Gerçek Zamanlı Değişiklik Bildirimi:** Dosyalar erişildiğinde veya değiştirildiğinde, genellikle OS çekirdek uzantıları aracılığıyla anında bildirim alın.

## Araçlar

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referanslar

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
