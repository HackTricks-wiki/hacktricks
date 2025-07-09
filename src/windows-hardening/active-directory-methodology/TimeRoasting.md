## TimeRoasting

timeRoasting'in ana nedeni, Microsoft'un NTP sunucularına uzantısında bıraktığı güncel olmayan kimlik doğrulama mekanizmasıdır, bu mekanizma MS-SNTP olarak bilinir. Bu mekanizmada, istemciler herhangi bir bilgisayar hesabının Göreli Tanımlayıcısını (RID) doğrudan kullanabilir ve etki alanı denetleyicisi, yanıt paketinin **Mesaj Kimlik Doğrulama Kodu (MAC)**'sını oluşturmak için bilgisayar hesabının NTLM hash'ini (MD4 tarafından üretilen) anahtar olarak kullanır.

Saldırganlar, bu mekanizmayı kullanarak kimlik doğrulama olmadan rastgele bilgisayar hesaplarının eşdeğer hash değerlerini elde edebilirler. Açıkça, brute-forcing için Hashcat gibi araçlar kullanabiliriz.

Belirli mekanizma, [MS-SNTP protokolü için resmi Windows belgeleri](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf) belgesinin 3.1.5.1 "Kimlik Doğrulama İsteği Davranışı" bölümünde görülebilir.

Belgede, 3.1.5.1 bölümü Kimlik Doğrulama İsteği Davranışını kapsamaktadır.
![](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM öğesi `false` olarak ayarlandığında, orijinal Markdown formatı korunur.

>Orijinal makaleden alıntı：
>>ExtendedAuthenticatorSupported ADM öğesi false ise, istemci bir İstemci NTP İsteği mesajı oluşturmalıdır. İstemci NTP İsteği mesajı uzunluğu 68 bayttır. İstemci, 2.2.1 bölümünde açıklandığı gibi İstemci NTP İsteği mesajının Kimlik Doğrulayıcı alanını ayarlar, RID değerinin en az anlamlı 31 bitini kimlik doğrulayıcının anahtar tanımlayıcı alt alanının en az anlamlı 31 bitine yazar ve ardından Anahtar Seçici değerini anahtar tanımlayıcı alt alanının en anlamlı bitine yazar.

Belge bölüm 4 Protokol Örnekleri nokta 3

>Orijinal makaleden alıntı：
>>3. İsteği aldıktan sonra, sunucu alınan mesaj boyutunun 68 bayt olduğunu doğrular. Eğer değilse, sunucu isteği ya düşürür (eğer mesaj boyutu 48 bayta eşit değilse) ya da bunu kimlik doğrulaması yapılmamış bir istek olarak değerlendirir (eğer mesaj boyutu 48 baytsa). Alınan mesaj boyutunun 68 bayt olduğunu varsayarsak, sunucu alınan mesajdan RID'yi çıkarır. Sunucu, NetrLogonComputeServerDigest yöntemini çağırmak için bunu kullanır (belirtilen [MS-NRPC] bölüm 3.5.4.8.2) kripto-kontrol toplamlarını hesaplamak ve alınan mesajdan anahtar tanımlayıcı alt alanının en anlamlı bitine göre kripto-kontrol toplamını seçmek için, 3.2.5 bölümünde belirtildiği gibi. Sunucu daha sonra istemciye bir yanıt gönderir, Anahtar Tanımlayıcı alanını 0 ve Kripto-Kontrol Toplamı alanını hesaplanan kripto-kontrol toplamı olarak ayarlar.

Yukarıdaki Microsoft resmi belgesindeki açıklamaya göre, kullanıcıların herhangi bir kimlik doğrulamasına ihtiyaçları yoktur; yalnızca bir isteği başlatmak için RID'yi doldurmaları yeterlidir ve ardından kriptografik kontrol toplamını elde edebilirler. Kriptografik kontrol toplamı, belgenin 3.2.5.1.1 bölümünde açıklanmaktadır.

>Orijinal makaleden alıntı：
>>Sunucu, İstemci NTP İsteği mesajının Kimlik Doğrulayıcı alanının Anahtar Tanımlayıcı alt alanının en az anlamlı 31 bitinden RID'yi alır. Sunucu, aşağıdaki giriş parametreleri ile kripto-kontrol toplamlarını hesaplamak için NetrLogonComputeServerDigest yöntemini kullanır:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Kriptografik kontrol toplamı MD5 kullanılarak hesaplanır ve belirli süreç belge içeriğinde referans alınabilir. Bu, bize bir roasting saldırısı gerçekleştirme fırsatı verir.

## nasıl saldırılır

Quote to https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scriptleri Tom Tervoort tarafından
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
