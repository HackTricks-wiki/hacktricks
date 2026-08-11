# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#3f17" id="3f17"></a>

**[Bu teknik hakkındaki tüm bilgiler için orijinal gönderiyi](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) inceleyin.**<sup>[[1]](#references)</sup>

Özetle, bir kullanıcının veya bilgisayarın **`msDS-KeyCredentialLink`** özniteliğinin kontrolü, bir saldırganın bir key credential eklemesine, PKINIT ile bu nesne olarak authenticate olmasına ve—KDC ile hesabın gerekli akışları desteklemesi durumunda—elde edilen ticket'ı `S4U2Self`/user-to-user ile kullanarak nesnenin NT hash'ini kurtarmasına olanak tanıyabilir.<sup>[[1]](#references)</sup>

Gönderide, hedefin NTLM hash'ini içeren benzersiz bir **Service Ticket** elde etmek için **public-private key authentication credentials** kurmaya yönelik bir yöntem açıklanmaktadır. Bu işlem, Privilege Attribute Certificate (PAC) içindeki şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL verisini içerir ve bu veri decrypt edilebilir.<sup>[[1]](#references)</sup>

### Gereksinimler

Bu tekniği uygulamak için belirli koşulların karşılanması gerekir:<sup>[[1]](#references)</sup>

- En az bir Windows Server 2016 Domain Controller gereklidir.
- Domain Controller üzerinde bir server authentication digital certificate yüklü olmalıdır.
- Directory schema, `msDS-KeyCredentialLink` özniteliğini içermelidir; araştırmada açıklanan pratik platform gereksinimleri, Windows Server 2016 veya daha yeni bir DC ve KDC üzerinde PKINIT-capable bir certificate bulunmasıdır. Exploit edilebilirliğin yalnızca domain functional-level etiketiyle belirlendiğini varsaymak yerine domain'in schema/DC bileşimini doğrulayın.
- Hedef nesnenin msDS-KeyCredentialLink özniteliğini değiştirmek için delegated rights atanmış bir hesap gereklidir.

## Abuse

Computer objects için Key Trust abuse, bir Ticket Granting Ticket (TGT) ve NTLM hash elde etmenin ötesine geçen adımları kapsar. Seçenekler şunlardır:<sup>[[1]](#references)</sup>

1. Hedef host üzerinde privileged users olarak hareket etmek için bir **RC4 silver ticket** oluşturmak.
2. **Privileged users** impersonation'ı için TGT'yi **S4U2Self** ile kullanmak; bunun için service name'e bir service class eklemek üzere Service Ticket üzerinde değişiklik yapılması gerekir.

Key Trust abuse'un önemli bir avantajı, yalnızca saldırgan tarafından oluşturulan private key ile sınırlı olmasıdır. Böylece potansiyel olarak vulnerable hesaplara delegation yapılması önlenir ve kaldırılması zor olabilecek bir computer account oluşturulması gerekmez.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker, C# üzerinden `msDS-KeyCredentialLink` özniteliğini manipulate etmek için DSInternals kullanır. Whisker ve Python counterpart'ı **pyWhisker**, key credential eklemeyi, listelemeyi, kaldırmayı ve temizlemeyi destekler.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** işlevleri şunlardır:

- **Add**: Bir key pair oluşturur ve bir key credential ekler.
- **List**: Tüm key credential girdilerini görüntüler.
- **Remove**: Belirtilen bir key credential'ı siler.
- **Clear**: Tüm key credential'ları siler; bu işlem meşru WHfB kullanımını potansiyel olarak kesintiye uğratabilir.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker, Impacket ve PyDSInternals ile **UNIX-like systems** üzerindeki iş akışını; listeleme/ekleme/kaldırma ve JSON içe/dışa aktarma işlemlerini destekleyecek şekilde sunar.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, operatörün `GenericWrite`/`GenericAll` gibi haklara sahip olduğu domain nesnelerini enumerate eder, geniş kapsamlı olarak key credentials eklemeyi dener ve cleanup/recursive modlarını içerir. Geniş kapsamlı spraying işlemi kesintiye neden olur ve dikkat çeker; açık hedefler kullanın ve hassas kaldırma işlemleri için eklenen her DeviceID değerini saklayın.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Hesap Ele Geçirme için Key Trust Account Mapping Abuse](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink'i manipüle ederek AD hesaplarını ele geçirme aracı](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Shadow Credentials'ı bir domain genelinde spray etmek için araç](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials aracının Python sürümü](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
