{{#include ../../banners/hacktricks-training.md}}

İnternette, **varsayılan/zayıf** oturum açma kimlik bilgileriyle yapılandırılmış yazıcıların tehlikelerini **vurgulayan** birkaç blog bulunmaktadır.\
Bu, bir saldırganın yazıcıyı **kötü niyetli bir LDAP sunucusuna kimlik doğrulaması yapmaya kandırabileceği** anlamına gelir (genellikle bir `nc -vv -l -p 444` yeterlidir) ve yazıcının **kimlik bilgilerini açık metin olarak** yakalayabilir.

Ayrıca, birçok yazıcı **kullanıcı adlarıyla günlükler** içerebilir veya hatta **Tüm kullanıcı adlarını** Domain Controller'dan indirebilir.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksiklikleri**, yazıcıları saldırganlar için çok ilginç hale getirir.

Konu hakkında bazı bloglar:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi şurada bulunur: `Network > LDAP Setting > Setting Up LDAP`.
- **Davranış**: Arayüz, kimlik bilgilerini yeniden girmeden LDAP sunucu değişikliklerine izin verir, bu kullanıcı kolaylığı için tasarlanmıştır ancak güvenlik riskleri taşır.
- **Sömürü**: Sömürü, LDAP sunucu adresini kontrol edilen bir makineye yönlendirmeyi ve kimlik bilgilerini yakalamak için "Bağlantıyı Test Et" özelliğini kullanmayı içerir.

## Kimlik Bilgilerini Yakalama

**Daha ayrıntılı adımlar için, orijinal [kaynağa](https://grimhacker.com/2018/03/09/just-a-printer/) bakın.**

### Yöntem 1: Netcat Dinleyici

Basit bir netcat dinleyici yeterli olabilir:
```bash
sudo nc -k -v -l -p 386
```
Ancak, bu yöntemin başarısı değişkenlik gösterir.

### Yöntem 2: Tam LDAP Sunucusu ile Slapd

Daha güvenilir bir yaklaşım, bir tam LDAP sunucusu kurmaktır çünkü yazıcı, kimlik bilgisi bağlamadan önce bir null bind ve ardından bir sorgu gerçekleştirir.

1. **LDAP Sunucu Kurulumu**: Kılavuz, [bu kaynaktan](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) adımları takip eder.
2. **Ana Adımlar**:
- OpenLDAP'ı kurun.
- Yönetici şifresini yapılandırın.
- Temel şemaları içe aktarın.
- LDAP DB üzerinde alan adını ayarlayın.
- LDAP TLS'yi yapılandırın.
3. **LDAP Servisi Çalıştırma**: Kurulduktan sonra, LDAP servisi şu şekilde çalıştırılabilir:
```bash
slapd -d 2
```
## Referanslar

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
