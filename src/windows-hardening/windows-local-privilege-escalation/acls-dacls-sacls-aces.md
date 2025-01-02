# ACL'ler - DACL'ler/SACL'ler/ACE'ler

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{{#include ../../banners/hacktricks-training.md}}

## **Erişim Kontrol Listesi (ACL)**

Erişim Kontrol Listesi (ACL), bir nesne ve onun özellikleri için korumaları belirleyen sıralı bir Erişim Kontrol Girişi (ACE) setinden oluşur. Temelde, bir ACL, belirli bir nesne üzerinde hangi güvenlik ilkelerinin (kullanıcılar veya gruplar) hangi eylemlere izin verildiğini veya reddedildiğini tanımlar.

İki tür ACL vardır:

- **İhtiyari Erişim Kontrol Listesi (DACL):** Hangi kullanıcıların ve grupların bir nesneye erişimi olup olmadığını belirtir.
- **Sistem Erişim Kontrol Listesi (SACL):** Bir nesneye erişim girişimlerinin denetimini yönetir.

Bir dosyaya erişim süreci, sistemin nesnenin güvenlik tanımını kullanıcının erişim belirteci ile karşılaştırarak erişimin verilmesi gerekip gerekmediğini ve bu erişimin kapsamını belirlemesini içerir.

### **Ana Bileşenler**

- **DACL:** Kullanıcılara ve gruplara bir nesne için erişim izinleri veren veya reddeden ACE'leri içerir. Temelde, erişim haklarını belirleyen ana ACL'dir.
- **SACL:** Nesnelere erişimin denetimi için kullanılır; burada ACE'ler, Güvenlik Olay Günlüğü'nde kaydedilecek erişim türlerini tanımlar. Bu, yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için çok değerli olabilir.

### **Sistem ve ACL'ler Arasındaki Etkileşim**

Her kullanıcı oturumu, o oturumla ilgili güvenlik bilgilerini içeren bir erişim belirteci ile ilişkilidir; bu bilgiler arasında kullanıcı, grup kimlikleri ve ayrıcalıklar bulunur. Bu belirteç ayrıca oturumu benzersiz bir şekilde tanımlayan bir oturum SID'si içerir.

Yerel Güvenlik Otoritesi (LSASS), erişim isteklerini nesnelere işleyerek, erişim talep eden güvenlik ilkesine uyan ACE'leri DACL'de inceleyerek gerçekleştirir. İlgili ACE'ler bulunmazsa erişim hemen verilir. Aksi takdirde, LSASS, erişim belirtecindeki güvenlik ilkesinin SID'si ile ACE'leri karşılaştırarak erişim uygunluğunu belirler.

### **Özetlenmiş Süreç**

- **ACL'ler:** DACL'ler aracılığıyla erişim izinlerini ve SACL'ler aracılığıyla denetim kurallarını tanımlar.
- **Erişim Belirteci:** Bir oturum için kullanıcı, grup ve ayrıcalık bilgilerini içerir.
- **Erişim Kararı:** DACL ACE'leri ile erişim belirteci karşılaştırılarak verilir; SACL'ler denetim için kullanılır.

### ACE'ler

**Üç ana Erişim Kontrol Girişi (ACE) türü** vardır:

- **Erişim Reddedildi ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça reddeder (bir DACL'de).
- **Erişim İzin Verildi ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça verir (bir DACL'de).
- **Sistem Denetim ACE:** Bir Sistem Erişim Kontrol Listesi (SACL) içinde yer alır ve kullanıcılar veya gruplar tarafından bir nesneye erişim girişimlerinde denetim günlükleri oluşturulmasından sorumludur. Erişimin izin verilip verilmediğini ve erişimin niteliğini belgeler.

Her ACE'nin **dört kritik bileşeni** vardır:

1. Kullanıcının veya grubun **Güvenlik Tanımlayıcısı (SID)** (veya grafiksel bir temsil içindeki ilke adı).
2. ACE türünü tanımlayan bir **bayrak** (erişim reddedildi, izin verildi veya sistem denetimi).
3. Çocuk nesnelerin ACE'yi ebeveynlerinden miras alıp almayacağını belirleyen **miras bayrakları**.
4. Bir [**erişim maskesi**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), nesnenin verilen haklarını belirten 32 bitlik bir değer.

Erişim belirlemesi, her ACE'yi sırasıyla inceleyerek gerçekleştirilir:

- Bir **Erişim-Reddedildi ACE** erişim belirtecinde tanımlanan bir güvenilir kişiye istenen hakları açıkça reddeder.
- **Erişim-İzin Verildi ACE'leri** erişim belirtecindeki bir güvenilir kişiye tüm istenen hakları açıkça verir.
- Tüm ACE'ler kontrol edildikten sonra, istenen herhangi bir hak **açıkça izin verilmemişse**, erişim **reddedilir**.

### ACE'lerin Sırası

**ACE'lerin** (bir şeyin kimler tarafından erişilip erişilemeyeceğini belirten kurallar) **DACL** içinde sıralanma şekli çok önemlidir. Çünkü sistem, bu kurallara dayanarak erişim verip reddettikten sonra geri kalanına bakmayı durdurur.

Bu ACE'leri düzenlemenin en iyi yolu **"kanonik sıra"** olarak adlandırılır. Bu yöntem, her şeyin düzgün ve adil bir şekilde çalışmasını sağlamaya yardımcı olur. İşte **Windows 2000** ve **Windows Server 2003** gibi sistemler için nasıl olduğu:

- Öncelikle, **bu nesneye özel** olarak oluşturulmuş tüm kuralları, başka bir yerden gelen kurallardan (örneğin, bir üst klasörden) önce yerleştirin.
- Bu özel kurallar içinde, **"hayır" (reddet)** diyenleri, **"evet" (izin ver)** diyenlerden önce yerleştirin.
- Başka bir yerden gelen kurallar için, **en yakın kaynaktan** gelenlerle başlayın (örneğin, ebeveyn) ve oradan geriye doğru gidin. Yine, **"hayır"** öncelikli olarak **"evet"** olmalıdır.

Bu düzenleme iki büyük şekilde yardımcı olur:

- Eğer belirli bir **"hayır"** varsa, bu saygı gösterilir; diğer **"evet"** kuralları ne olursa olsun.
- Bir nesnenin sahibi, herhangi bir üst klasörden veya daha geriden gelen kurallardan önce kimin gireceği konusunda **son sözü** söyleyebilir.

Bu şekilde, bir dosya veya klasörün sahibi, kimin erişim alacağı konusunda çok hassas olabilir, doğru kişilerin girebilmesini ve yanlış olanların girememesini sağlar.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Bu nedenle, bu **"kanonik sıra"**, erişim kurallarının net ve iyi çalışmasını sağlamak, özel kuralları öncelikli hale getirmek ve her şeyi akıllıca düzenlemekle ilgilidir.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI Örneği

[**Buradan örnek**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Bu, ACL, DACL ve ACE'leri gösteren bir klasörün klasik güvenlik sekmesidir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Gelişmiş butonuna** tıkladığımızda miras gibi daha fazla seçenek alırız:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Ve bir Güvenlik İlkesi eklediğinizde veya düzenlediğinizde:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Son olarak, Denetim sekmesinde SACL'yi görüyoruz:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Erişim Kontrolünü Basit Bir Şekilde Açıklamak

Kaynaklara, örneğin bir klasöre erişimi yönetirken, Erişim Kontrol Listeleri (ACL'ler) ve Erişim Kontrol Girişleri (ACE'ler) olarak bilinen listeleri ve kuralları kullanırız. Bu kurallar, belirli verilere kimin erişip erişemeyeceğini tanımlar.

#### Belirli Bir Gruba Erişimi Reddetmek

Diyelim ki, Maliyet adında bir klasörünüz var ve herkesin erişmesini istiyorsunuz, ancak pazarlama ekibinin erişimini istemiyorsunuz. Kuralları doğru bir şekilde ayarlayarak, pazarlama ekibinin erişiminin açıkça reddedildiğinden emin olabiliriz; bu, pazarlama ekibine erişimi reddeden kuralı, diğer herkesin erişimine izin veren kuraldan önce yerleştirerek yapılır.

#### Reddedilen Bir Grubun Belirli Bir Üyesine Erişime İzin Vermek

Diyelim ki, pazarlama direktörü Bob'un Maliyet klasörüne erişime ihtiyacı var, oysa pazarlama ekibinin genel olarak erişimi olmamalı. Bob için erişim izni veren belirli bir kural (ACE) ekleyebiliriz ve bunu pazarlama ekibine erişimi reddeden kuraldan önce yerleştirebiliriz. Bu şekilde, Bob, ekibinin genel kısıtlamasına rağmen erişim alır.

#### Erişim Kontrol Girişlerini Anlamak

ACE'ler, bir ACL'deki bireysel kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişimin izin verildiğini veya reddedildiğini belirtir ve bu kuralların alt öğelere (miras) nasıl uygulanacağını belirler. İki ana ACE türü vardır:

- **Genel ACE'ler:** Bunlar geniş bir şekilde uygulanır, tüm nesne türlerini etkiler veya yalnızca konteynerler (klasörler gibi) ile konteyner olmayanlar (dosyalar gibi) arasında ayrım yapar. Örneğin, kullanıcıların bir klasörün içeriğini görmesine izin veren ancak içindeki dosyalara erişmesine izin vermeyen bir kural.
- **Nesne-Özel ACE'ler:** Bunlar daha hassas kontrol sağlar, belirli nesne türleri veya bir nesne içindeki bireysel özellikler için kuralların ayarlanmasına izin verir. Örneğin, bir kullanıcılar dizininde, bir kullanıcının telefon numarasını güncellemesine izin veren ancak giriş saatlerini güncellemesine izin vermeyen bir kural olabilir.

Her ACE, kuralın kime uygulandığı (bir Güvenlik Tanımlayıcısı veya SID kullanarak), kuralın neyi izin verdiği veya reddettiği (bir erişim maskesi kullanarak) ve diğer nesneler tarafından nasıl miras alındığı gibi önemli bilgileri içerir.

#### ACE Türleri Arasındaki Temel Farklar

- **Genel ACE'ler**, nesnenin tüm yönlerine veya bir konteyner içindeki tüm nesnelere aynı kuralın uygulandığı basit erişim kontrol senaryoları için uygundur.
- **Nesne-Özel ACE'ler**, özellikle Active Directory gibi ortamlarda, bir nesnenin belirli özelliklerine erişimi farklı bir şekilde kontrol etmeniz gerektiğinde daha karmaşık senaryolar için kullanılır.

Özetle, ACL'ler ve ACE'ler, yalnızca doğru bireylerin veya grupların hassas bilgilere veya kaynaklara erişimini sağlamak için kesin erişim kontrolleri tanımlamaya yardımcı olur ve erişim haklarını bireysel özellikler veya nesne türleri seviyesine kadar özelleştirme yeteneği sunar.

### Erişim Kontrol Girişi Düzeni

| ACE Alanı   | Açıklama                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tür         | ACE türünü belirten bayrak. Windows 2000 ve Windows Server 2003, tüm güvenli nesnelere eklenebilen üç genel ACE türü ve Active Directory nesneleri için meydana gelebilecek üç nesne-özel ACE türü destekler.                                                                                                                                                                                                                                                                                                   |
| Bayraklar   | Miras ve denetimi kontrol eden bit bayrakları seti.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Boyut       | ACE için tahsis edilen bellek bayt sayısı.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Erişim maskesi | Nesne için erişim haklarına karşılık gelen bitlerin bulunduğu 32 bitlik değer. Bitler ya açık ya da kapalı olarak ayarlanabilir, ancak ayarın anlamı ACE türüne bağlıdır. Örneğin, izin okuma haklarına karşılık gelen bit açıldığında ve ACE türü Reddet ise, ACE nesnenin izinlerini okuma hakkını reddeder. Aynı bit açık ayarlandığında ancak ACE türü İzin Ver ise, ACE nesnenin izinlerini okuma hakkını verir. Erişim maskesinin daha fazla ayrıntısı bir sonraki tabloda yer almaktadır. |
| SID         | Bu ACE tarafından kontrol edilen veya izlenen bir kullanıcı veya grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Erişim Maskesi Düzeni

| Bit (Aralık) | Anlamı                            | Açıklama/Örnek                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Nesne Özel Erişim Hakları      | Verileri oku, Çalıştır, Verileri ekle           |
| 16 - 22     | Standart Erişim Hakları             | Sil, ACL yaz, Sahibi yaz            |
| 23          | Güvenlik ACL'sine erişebilir      |                                           |
| 24 - 27     | Ayrılmış                           |                                           |
| 28          | Genel Tüm (Oku, Yaz, Çalıştır) | Her şey aşağıda                          |
| 29          | Genel Çalıştır                    | Bir programı çalıştırmak için gerekli tüm şeyler |
| 30          | Genel Yaz                        | Bir dosyaya yazmak için gerekli tüm şeyler   |
| 31          | Genel Oku                       | Bir dosyayı okumak için gerekli tüm şeyler       |

## Referanslar

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
