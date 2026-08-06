# ACL'ler - DACL'ler/SACL'ler/ACE'ler

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Bir Access Control List (ACL), bir nesne ve özellikleri için uygulanacak korumaları belirleyen, sıralı bir Access Control Entry (ACE) kümesinden oluşur. Temel olarak ACL, belirli bir nesne üzerinde hangi security principal'ların (kullanıcılar veya gruplar) hangi eylemlerine izin verildiğini veya izin verilmediğini tanımlar.

İki tür ACL vardır:

- **Discretionary Access Control List (DACL):** Hangi kullanıcıların ve grupların bir nesneye erişimi olduğunu veya olmadığını belirtir.
- **System Access Control List (SACL):** Bir nesneye yönelik erişim girişimlerinin auditing işlemlerini yönetir.

Bir dosyaya erişim sürecinde sistem, erişimin verilip verilmeyeceğini ve erişimin kapsamını belirlemek için nesnenin security descriptor'ını kullanıcının access token'ı ile karşılaştırır. Bu işlem ACE'lere dayanır.<sup>[[1]](#references)</sup>

### **Temel Bileşenler**

- **DACL:** Bir nesne için kullanıcılara ve gruplara erişim izinleri veren veya erişimi reddeden ACE'leri içerir. Esasen erişim haklarını belirleyen ana ACL'dir.
- **SACL:** Nesnelere erişimin auditing işlemi için kullanılır. ACE'ler, Security Event Log'a kaydedilecek erişim türlerini tanımlar. Bu özellik, yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için oldukça değerlidir.<sup>[[1]](#references)</sup>

### **Sistemin ACL'lerle Etkileşimi**

Her kullanıcı oturumu, kullanıcı ve grup kimlikleri ile yetkiler dahil olmak üzere o oturumla ilgili security bilgilerini içeren bir access token ile ilişkilidir. Bu token ayrıca oturumu benzersiz şekilde tanımlayan bir logon SID içerir.

Local Security Authority (LSASS), erişim isteyen security principal ile eşleşen ACE'leri bulmak için DACL'yi inceleyerek nesnelere yönelik erişim isteklerini işler. İlgili hiçbir ACE bulunmazsa erişim hemen verilir. Aksi takdirde LSASS, erişim uygunluğunu belirlemek için ACE'leri access token içindeki security principal'ın SID'si ile karşılaştırır.<sup>[[1]](#references)</sup>

### **Özetlenmiş Süreç**

- **ACL'ler:** DACL'ler aracılığıyla erişim izinlerini, SACL'ler aracılığıyla auditing kurallarını tanımlar.
- **Access Token:** Bir oturum için kullanıcı, grup ve yetki bilgilerini içerir.
- **Erişim Kararı:** DACL ACE'leri access token ile karşılaştırılarak verilir; SACL'ler auditing için kullanılır.<sup>[[1]](#references)</sup>

### ACE'ler

**Üç ana Access Control Entry (ACE) türü** vardır:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Bu ACE, belirtilen kullanıcılar veya gruplar için bir nesneye erişimi açıkça reddeder (bir DACL içinde).
- **Access Allowed ACE**: Bu ACE, belirtilen kullanıcılar veya gruplar için bir nesneye erişim izni verir (bir DACL içinde).
- **System Audit ACE**: Bir System Access Control List (SACL) içinde yer alan bu ACE, kullanıcıların veya grupların bir nesneye erişim girişimlerinde auditing logları oluşturur. Erişimin izin verilip verilmediğini ve erişimin niteliğini kaydeder.

Her ACE'nin **dört kritik bileşeni** vardır:<sup>[[1]](#references)</sup>

1. Kullanıcının veya grubun **Security Identifier (SID)** değeri (veya graphical representation içindeki principal adı).
2. ACE türünü (access denied, allowed veya system audit) belirleyen bir **flag**.
3. Alt nesnelerin ACE'yi üst nesnelerinden devralıp devralamayacağını belirleyen **inheritance flag'leri**.
4. Nesne için verilen hakları belirten 32-bit değer olan bir [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN).

Erişim belirleme işlemi, her ACE'nin aşağıdaki durumlardan biri gerçekleşene kadar sırayla incelenmesiyle yapılır:<sup>[[1]](#references)</sup>

- Bir **Access-Denied ACE**, access token içinde tanımlanan bir trustee için istenen hakları açıkça reddeder.
- **Access-Allowed ACE(ler)i**, access token içindeki bir trustee için istenen tüm hakları açıkça verir.
- Tüm ACE'ler kontrol edildikten sonra, istenen herhangi bir hak açıkça verilmemişse erişim örtük olarak **reddedilir**.

### ACE'lerin Sırası

Bir listenin, yani **DACL**'nin içinde **ACE'lerin** (bir şeye kimin erişebileceğini veya erişemeyeceğini belirten kuralların) nasıl sıralandığı çok önemlidir. Bunun nedeni, sistem bu kurallara göre erişim verdiğinde veya reddettiğinde geri kalan kuralları incelemeyi bırakmasıdır.<sup>[[1]](#references)</sup>

Bu ACE'leri düzenlemenin en iyi yolu **"canonical order"** olarak adlandırılır. Bu yöntem her şeyin sorunsuz ve tutarlı çalışmasına yardımcı olur. **Windows 2000** ve **Windows Server 2003** gibi sistemlerde sıralama şu şekildedir:

- Önce, başka bir yerden (örneğin bir üst klasörden) gelen kurallardan önce, **özellikle bu öğe için** oluşturulan tüm kuralları yerleştirin.
- Bu özel kurallar içinde **"hayır" (deny)** diyenleri, **"evet" (allow)** diyenlerden önce yerleştirin.
- Başka bir yerden gelen kurallarda, **en yakın kaynaktan** (örneğin üst nesneden) gelenlerle başlayın ve daha uzaktaki kaynaklara doğru ilerleyin. Yine **"hayır"** kurallarını **"evet"** kurallarından önce yerleştirin.

Bu düzen iki önemli avantaj sağlar:

- Özel bir **"hayır"** kuralı varsa, başka **"evet"** kuralları bulunsa bile bu kuralın uygulanmasını sağlar.
- Bir öğenin sahibine, üst klasörlerden veya daha uzak kaynaklardan gelen kurallar devreye girmeden önce erişim izni verilecek kişiler konusunda **son söz hakkı** tanır.

Bu şekilde, bir dosya veya klasörün sahibi kimlerin erişebileceğini hassas biçimde belirleyebilir; doğru kişilerin erişmesini, yanlış kişilerin ise erişememesini sağlayabilir.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dolayısıyla bu **"canonical order"**, erişim kurallarının açık ve düzgün çalışmasını sağlamakla ilgilidir. Bunun için özel kurallar önce yerleştirilir ve her şey akıllı bir şekilde düzenlenir.

### GUI Örneği

[**Buradaki örnek**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Bu, ACL, DACL ve ACE'leri gösteren bir klasörün klasik security sekmesidir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Advanced button**'a tıklarsak inheritance gibi daha fazla seçenek görürüz:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Ayrıca bir Security Principal ekler veya düzenlerseniz:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Son olarak Auditing sekmesinde SACL'yi bulabiliriz:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Access Control'ü Basitleştirilmiş Şekilde Açıklama

Bir klasör gibi kaynaklara erişimi yönetirken Access Control List (ACL) ve Access Control Entry (ACE) olarak bilinen liste ve kuralları kullanırız. Bunlar belirli verilere kimlerin erişebileceğini veya erişemeyeceğini tanımlar.<sup>[[1]](#references)</sup>

#### Belirli Bir Grubun Erişimini Reddetme

Cost adlı bir klasörünüz olduğunu ve bir marketing team dışındaki herkesin bu klasöre erişmesini istediğinizi düşünün. Kuralları doğru şekilde ayarlayarak marketing team'in erişimini açıkça reddedebilir ve ardından diğer herkese izin verebiliriz. Bunun için marketing team'in erişimini reddeden kural, herkese erişim izni veren kuraldan önce yerleştirilir.

#### Reddedilen Bir Grubun Belirli Bir Üyesine Erişim Verme

Marketing director olan Bob'un, marketing team'in genel olarak erişmemesi gereken Cost klasörüne erişmesi gerektiğini varsayalım. Bob için erişim izni veren özel bir kural (ACE) ekleyebilir ve bu kuralı marketing team'in erişimini reddeden kuraldan önce yerleştirebiliriz. Böylece ekibine uygulanan genel kısıtlamaya rağmen Bob erişim elde eder.

#### Access Control Entry'leri Anlama

ACE'ler, bir ACL içindeki münferit kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişime izin verildiğini veya erişimin reddedildiğini belirtir ve bu kuralların alt öğelere nasıl uygulanacağını (inheritance) belirler. İki ana ACE türü vardır:

- **Generic ACE'ler**: Bunlar geniş kapsamlı şekilde uygulanır; tüm nesne türlerini etkiler veya yalnızca container'lar (klasörler gibi) ile container olmayan nesneler (dosyalar gibi) arasında ayrım yapar. Örneğin kullanıcıların bir klasörün içeriğini görmesine izin veren, ancak klasör içindeki dosyalara erişmesine izin vermeyen bir kural.
- **Object-Specific ACE'ler**: Bunlar daha hassas control sağlar; belirli nesne türleri veya hatta bir nesne içindeki münferit özellikler için kurallar belirlenmesine olanak tanır. Örneğin bir kullanıcı dizininde, bir kullanıcının telefon numarasını güncellemesine izin veren ancak login saatlerini değiştirmesine izin vermeyen bir kural.

Her ACE; kuralın kim için geçerli olduğu (Security Identifier veya SID kullanılarak), kuralın neye izin verdiği veya neyi reddettiği (access mask kullanılarak) ve diğer nesneler tarafından nasıl devralındığı gibi önemli bilgileri içerir.

#### ACE Türleri Arasındaki Temel Farklar

- **Generic ACE'ler**, aynı kuralın bir nesnenin tüm yönlerine veya bir container içindeki tüm nesnelere uygulandığı basit access control senaryoları için uygundur.
- **Object-Specific ACE'ler**, özellikle Active Directory gibi ortamlarda, bir nesnenin belirli özelliklerine erişimin farklı şekilde kontrol edilmesi gereken daha karmaşık senaryolarda kullanılır.

Özetle ACL'ler ve ACE'ler, hassas bilgi veya kaynaklara yalnızca doğru kişilerin ya da grupların erişmesini sağlayan kesin access control'ler tanımlamaya yardımcı olur. Erişim hakları münferit özellikler veya nesne türleri düzeyine kadar özelleştirilebilir.

### Access Control Entry Düzeni

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE türünü belirten flag. Windows 2000 ve Windows Server 2003 altı ACE türünü destekler: securable nesnelere eklenen üç generic ACE türü ve Active Directory nesnelerinde bulunabilen üç object-specific ACE türü.                                                                                                                                                                                                                                                            |
| Flags       | Inheritance ve auditing işlemlerini kontrol eden bit flag'leri kümesi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE için ayrılan memory baytlarının sayısı.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Bit'leri nesnenin access rights değerlerine karşılık gelen 32-bit değer. Bit'ler açık veya kapalı olarak ayarlanabilir, ancak ayarın anlamı ACE türüne bağlıdır. Örneğin permissions okuma hakkına karşılık gelen bit açık ve ACE türü Deny ise ACE, nesnenin permissions değerlerini okuma hakkını reddeder. Aynı bit açıkken ACE türü Allow ise ACE, nesnenin permissions değerlerini okuma hakkını verir. Access mask hakkında daha fazla bilgi sonraki tabloda yer almaktadır. |
| SID         | Bu ACE ile erişimi kontrol edilen veya izlenen kullanıcıyı ya da grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Düzeni

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Veri okuma, Execute, veri ekleme           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Security ACL'ye erişebilir          |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Aşağıdakilerin tamamı                          |
| 29          | Generic Execute                    | Bir programı çalıştırmak için gereken her şey |
| 30          | Generic Write                      | Bir dosyaya yazmak için gereken her şey   |
| 31          | Generic Read                       | Bir dosyayı okumak için gereken her şey       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
