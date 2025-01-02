# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Bu tekniğin [tüm bilgileri için orijinal gönderiyi kontrol edin](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

**Özet**: Eğer bir kullanıcı/bilgisayarın **msDS-KeyCredentialLink** özelliğine yazabiliyorsanız, o nesnenin **NT hash'ini** alabilirsiniz.

Gönderide, hedefin NTLM hash'ini içeren benzersiz bir **Service Ticket** almak için **public-private key authentication credentials** kurma yöntemi özetlenmiştir. Bu süreç, şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL'in deşifre edilebileceği Privilege Attribute Certificate (PAC) içinde yer alır.

### Gereksinimler

Bu tekniği uygulamak için belirli koşulların sağlanması gerekmektedir:

- En az bir Windows Server 2016 Domain Controller gereklidir.
- Domain Controller'da bir sunucu kimlik doğrulama dijital sertifikası yüklü olmalıdır.
- Active Directory, Windows Server 2016 Fonksiyonel Seviyesinde olmalıdır.
- Hedef nesnenin msDS-KeyCredentialLink niteliğini değiştirmek için yetkilendirilmiş bir hesaba ihtiyaç vardır.

## Abuse

Bilgisayar nesneleri için Key Trust'ın kötüye kullanımı, Ticket Granting Ticket (TGT) ve NTLM hash'ini elde etmenin ötesinde adımları kapsamaktadır. Seçenekler şunlardır:

1. Hedef makinede ayrıcalıklı kullanıcılar olarak hareket etmek için bir **RC4 gümüş bileti** oluşturmak.
2. **S4U2Self** ile TGT'yi kullanarak **ayrıcalıklı kullanıcıların** taklit edilmesi, hizmet adını eklemek için Service Ticket'ta değişiklikler gerektirir.

Key Trust kötüye kullanımının önemli bir avantajı, saldırgan tarafından üretilen özel anahtarla sınırlı olmasıdır; bu, potansiyel olarak savunmasız hesaplara devredilmesini önler ve kaldırılması zor olabilecek bir bilgisayar hesabı oluşturulmasını gerektirmez.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Bu saldırı için bir C# arayüzü sağlayan DSInternals'a dayanmaktadır. Whisker ve Python karşılığı **pyWhisker**, Active Directory hesapları üzerinde kontrol sağlamak için `msDS-KeyCredentialLink` niteliğini manipüle etmeyi mümkün kılar. Bu araçlar, hedef nesneden anahtar kimlik bilgilerini ekleme, listeleme, kaldırma ve temizleme gibi çeşitli işlemleri destekler.

**Whisker** işlevleri şunlardır:

- **Ekle**: Bir anahtar çifti oluşturur ve bir anahtar kimlik bilgisi ekler.
- **Listele**: Tüm anahtar kimlik bilgisi girişlerini görüntüler.
- **Kaldır**: Belirtilen bir anahtar kimlik bilgisini siler.
- **Temizle**: Tüm anahtar kimlik bilgilerini siler, bu da meşru WHfB kullanımını potansiyel olarak kesintiye uğratabilir.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Whisker işlevselliğini **UNIX tabanlı sistemlere** genişleterek, KeyCredentials'ı listeleme, ekleme ve kaldırma gibi kapsamlı istismar yetenekleri için Impacket ve PyDSInternals'dan yararlanır; ayrıca bunları JSON formatında içe ve dışa aktarma işlemlerini de gerçekleştirir.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, **genel kullanıcı gruplarının alan nesneleri üzerinde sahip olabileceği GenericWrite/GenericAll izinlerini istismar etmeyi** amaçlar ve ShadowCredentials'ı geniş bir şekilde uygulamayı hedefler. Bu, alan adına giriş yapmayı, alanın işlevsel seviyesini doğrulamayı, alan nesnelerini listelemeyi ve TGT edinimi ve NT hash ifşası için KeyCredentials eklemeyi içerir. Temizlik seçenekleri ve yinelemeli istismar taktikleri, kullanımını artırır.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
