# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#3f17" id="3f17"></a>

**[Bu teknik hakkındaki tüm bilgiler](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) için orijinal gönderiye göz atın.**<sup>[[1]](#references)</sup>

Özetle, bir kullanıcının veya bilgisayarın **`msDS-KeyCredentialLink`** özniteliğini kontrol etmek, saldırganın bir key credential eklemesine ve PKINIT ile bu nesne olarak kimlik doğrulaması yapmasına olanak tanıyabilir. KDC ve hesap gerekli akışları destekliyorsa, elde edilen ticket `S4U2Self`/user-to-user ile kullanılarak nesnenin NT hash'i kurtarılabilir.<sup>[[1]](#references)</sup>

Gönderide, hedefin NTLM hash'ini içeren benzersiz bir **Service Ticket** edinmek için **public-private key authentication credentials** ayarlama yöntemi açıklanıyor. Bu süreç, Privilege Attribute Certificate (PAC) içindeki şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL'ı içerir ve bu şifre çözülebilir.<sup>[[1]](#references)</sup>

### Gereksinimler

Bu tekniği uygulamak için bazı koşulların karşılanması gerekir:<sup>[[1]](#references)</sup>

- En az bir Windows Server 2016 Domain Controller gerekir.
- Domain Controller'da bir server authentication digital certificate yüklü olmalıdır.
- Directory schema `msDS-KeyCredentialLink` özniteliğini içermelidir; araştırmada belirtilen pratik platform gereksinimleri, Windows Server 2016 veya daha yeni bir DC ve KDC üzerinde PKINIT destekli bir sertifikadır. Yalnızca domain functional-level etiketinin istismar edilebilirliği belirlediğini varsaymak yerine, domain'in schema/DC bileşimini doğrulayın.
- Hedef nesnenin msDS-KeyCredentialLink özniteliğini değiştirmek için devredilmiş haklara sahip bir hesap gerekir.

## Kötüye Kullanım

Bilgisayar nesneleri için Key Trust'ın kötüye kullanılması, Ticket Granting Ticket (TGT) ve NTLM hash'ini elde etmenin ötesinde adımlar içerir. Seçenekler şunlardır:<sup>[[1]](#references)</sup>

1. Hedef host üzerinde ayrıcalıklı kullanıcılar gibi davranmak için bir **RC4 silver ticket** oluşturmak.
2. **Ayrıcalıklı kullanıcıların** kimliğine bürünmek için TGT'yi **S4U2Self** ile kullanmak; bunun için service name'e bir service class eklemek üzere Service Ticket'ta değişiklik yapmak gerekir.

Key Trust'ı kötüye kullanmanın önemli bir avantajı, bunun saldırganın oluşturduğu private key ile sınırlı olmasıdır. Böylece potansiyel olarak savunmasız hesaplara delegation yapılmaz ve kaldırılması zor olabilecek bir bilgisayar hesabı oluşturmak gerekmez.<sup>[[1]](#references)</sup>

## Araçlar

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker, `msDS-KeyCredentialLink` özniteliğini C# üzerinden değiştirmek için DSInternals kullanır. Whisker ve Python karşılığı **pyWhisker**, key credentials ekleme, listeleme, kaldırma ve temizleme işlemlerini destekler.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** işlevleri şunlardır:

- **Add**: Bir key pair oluşturur ve key credential ekler.
- **List**: Tüm key credential girdilerini görüntüler.
- **Remove**: Belirtilen bir key credential'ı siler.
- **Clear**: Tüm key credentials'ları siler; bu, meşru WHfB kullanımını aksatabilir.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker, Impacket ve PyDSInternals ile iş akışını **UNIX benzeri sistemlere** taşır; listeleme/ekleme/kaldırma ve JSON içe/dışa aktarma işlemlerini destekler.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, operatörün `GenericWrite`/`GenericAll` gibi haklara sahip olduğu domain nesnelerini enumerate eder, geniş kapsamda key credential eklemeyi dener ve cleanup/recursive modları içerir. Geniş çaplı spraying kesintiye yol açar ve dikkat çeker; açık hedefler kullanın ve hassas biçimde kaldırmak için eklenen her DeviceID'yi kaydedin.<sup>[[3]](#references)</sup>

Doğrudan LDAP filtrelendiğinde key-credential yazma işlemi ADWS üzerinden gerçekleştirilebilir. Bkz. [SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Hesap Ele Geçirme için Key Trust Hesap Eşlemesinin Kötüye Kullanılması](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink'i manipüle ederek AD hesaplarını ele geçirme aracı](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Shadow Credentials'ı bir domain genelinde spray etme aracı](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials aracının Python sürümü](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
