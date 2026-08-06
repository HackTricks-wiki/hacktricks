# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#3f17" id="3f17"></a>

**Bu teknik hakkındaki [tüm bilgiler için orijinal gönderiyi inceleyin](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

**Özet** olarak: bir kullanıcının/bilgisayarın **msDS-KeyCredentialLink** property'sine yazabiliyorsanız, **NT hash değerini** elde edebilirsiniz.<sup>[[1]](#references)</sup>

Gönderide, hedefin NTLM hash değerini içeren benzersiz bir **Service Ticket** elde etmek için **public-private key authentication credentials** ayarlamaya yönelik bir yöntem açıklanmaktadır. Bu süreç, Privilege Attribute Certificate (PAC) içindeki şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL değerini içerir ve bu değer decrypt edilebilir.<sup>[[1]](#references)</sup>

### Gereksinimler

Bu tekniği uygulamak için belirli koşulların karşılanması gerekir:<sup>[[1]](#references)</sup>

- En az bir Windows Server 2016 Domain Controller gereklidir.
- Domain Controller üzerinde server authentication digital certificate kurulu olmalıdır.
- Active Directory, Windows Server 2016 Functional Level seviyesinde olmalıdır.
- Hedef objenin msDS-KeyCredentialLink attribute değerini değiştirme yetkisine delegated olarak sahip bir hesap gereklidir.

## Abuse

Computer object'leri için Key Trust abuse, Ticket Granting Ticket (TGT) ve NTLM hash elde etmenin ötesinde adımlar içerir. Seçenekler şunlardır:<sup>[[1]](#references)</sup>

1. Hedef host üzerinde privileged user'lar olarak hareket etmek için bir **RC4 silver ticket** oluşturmak.
2. **Privileged user** impersonation'ı için TGT'yi **S4U2Self** ile kullanmak; bunun için Service Ticket'ın değiştirilerek service name'e bir service class eklenmesi gerekir.

Key Trust abuse'un önemli bir avantajı, yalnızca attacker tarafından oluşturulan private key ile sınırlı olmasıdır. Böylece potansiyel olarak zafiyetli hesaplara delegation yapılması önlenir ve kaldırılması zor olabilecek bir computer account oluşturulması gerekmez.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

DSInternals temel alınarak bu attack için bir C# interface sağlar. Whisker ve Python karşılığı olan **pyWhisker**, Active Directory hesaplarının kontrolünü ele geçirmek için `msDS-KeyCredentialLink` attribute değerinin manipüle edilmesini sağlar. Bu tools, hedef objeden key credential ekleme, listeleme, kaldırma ve temizleme gibi çeşitli işlemleri destekler.

**Whisker** işlevleri şunları içerir:

- **Add**: Bir key pair oluşturur ve bir key credential ekler.
- **List**: Tüm key credential entry'lerini görüntüler.
- **Remove**: Belirtilen key credential'ı siler.
- **Clear**: Tüm key credential'ları siler; bu işlem meşru WHfB kullanımını potansiyel olarak kesintiye uğratabilir.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Whisker işlevselliğini **UNIX tabanlı sistemlere** genişletir; kapsamlı exploitation yetenekleri için Impacket ve PyDSInternals'dan yararlanır. Bu yetenekler arasında KeyCredentials listeleme, ekleme ve kaldırmanın yanı sıra bunları JSON formatında içe ve dışa aktarma da bulunur.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, **geniş kullanıcı gruplarının domain nesneleri üzerinde sahip olabileceği GenericWrite/GenericAll izinlerini exploit ederek** ShadowCredentials'ı geniş kapsamda uygulamayı amaçlar. Domain'e giriş yapmayı, domain'in functional level'ını doğrulamayı, domain nesnelerini enumerate etmeyi ve TGT edinimi ile NT hash ifşası için KeyCredentials eklemeyi denemeyi kapsar. Cleanup seçenekleri ve recursive exploitation taktikleri, aracın kullanım alanını genişletir.

## References

- [1] [Shadow Credentials: Account Takeover için Key Trust Account Mapping'in Abuse Edilmesi](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink'i manipulate ederek AD hesaplarını ele geçirme aracı](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Shadow Credentials'ı bir domain genelinde spray etmek için araç](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials aracının Python sürümü](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
