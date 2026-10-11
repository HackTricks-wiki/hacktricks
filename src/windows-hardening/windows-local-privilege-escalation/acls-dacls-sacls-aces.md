# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL), bir nesne ve özellikleri için korumaları belirleyen, sıralı bir Access Control Entries (ACE) kümesinden oluşur. Esasen ACL, belirli bir nesne üzerinde hangi güvenlik sorumlularının (kullanıcılar veya gruplar) hangi eylemlere izinli ya da yasaklı olduğunu tanımlar.

İki tür ACL vardır:

- **Discretionary Access Control List (DACL):** Hangi kullanıcı ve grupların bir nesneye erişimi olduğunu veya olmadığını belirtir.
- **System Access Control List (SACL):** Bir nesneye erişim girişimlerinin denetlenmesini yönetir.

Bir dosyaya erişim sürecinde sistem, erişimin verilip verilmeyeceğini ve erişimin kapsamını ACE'lere göre belirlemek için nesnenin güvenlik tanımlayıcısını kullanıcının access token'ı ile karşılaştırır.<sup>[[1]](#references)</sup>

Bir üst dizin Full Control izni verirken altındaki bir dosya okuma iznini reddediyorsa, **alt dosyanın** etkin DACL'sini, sahibini ve devralma ayarlarını ayrı ayrı inceleyin. Dosyanın DACL'sini değiştirmek için dosya üzerinde `WRITE_DAC` veya geçerli sahiplik hakkı gerekir; [Microsoft `WRITE_DAC` hakkını tanımlar](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) ve [sahibin örtük erişim haklarını belgeler](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Yalnızca üst dizin izinlerinin olması, alt dosyanın okunabileceği veya DACL'sinin değiştirilebileceği anlamına gelmez.

### **Key Components**

- **DACL:** Bir nesne için kullanıcı ve gruplara erişim izni veren veya erişimi reddeden ACE'leri içerir. Erişim haklarını belirleyen temel ACL'dir.
- **SACL:** Nesnelere erişimin denetlenmesi için kullanılır; ACE'ler Security Event Log'a kaydedilecek erişim türlerini tanımlar. Yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için çok yararlı olabilir.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Her kullanıcı oturumu; kullanıcı ve grup kimlikleri ile ayrıcalıklar dahil, o oturumla ilgili güvenlik bilgilerini içeren bir access token ile ilişkilendirilir. Bu token ayrıca oturumu benzersiz şekilde tanımlayan bir logon SID içerir.

Local Security Authority (LSASS), erişmeye çalışan güvenlik sorumlusuyla eşleşen ACE'leri bulmak için DACL'yi inceleyerek nesnelere yönelik erişim isteklerini işler. İlgili ACE bulunmazsa erişim derhal verilir. Aksi takdirde LSASS, erişim izni olup olmadığını belirlemek için ACE'leri access token'daki güvenlik sorumlusunun SID'siyle karşılaştırır.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** DACL'ler aracılığıyla erişim izinlerini, SACL'ler aracılığıyla denetim kurallarını tanımlar.
- **Access Token:** Bir oturumun kullanıcı, grup ve ayrıcalık bilgilerini içerir.
- **Access Decision:** DACL ACE'leri access token ile karşılaştırılarak verilir; SACL'ler denetim için kullanılır.<sup>[[1]](#references)</sup>

### ACEs

Üç **ana Access Control Entry (ACE) türü** vardır:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Bu ACE, bir DACL içinde, belirtilen kullanıcı veya grupların bir nesneye erişimini açıkça reddeder.
- **Access Allowed ACE**: Bu ACE, bir DACL içinde, belirtilen kullanıcı veya gruplara bir nesneye erişim iznini açıkça verir.
- **System Audit ACE**: System Access Control List (SACL) içinde yer alan bu ACE, kullanıcıların veya grupların bir nesneye erişim girişimleri sırasında denetim günlükleri oluşturur. Erişime izin verilip verilmediğini ve erişimin türünü kaydeder.

Her ACE'nin **dört önemli bileşeni** vardır:<sup>[[1]](#references)</sup>

1. Kullanıcının veya grubun **Security Identifier (SID)**'si (ya da grafik gösterimindeki sorumlu adı).
2. ACE türünü (erişim reddedildi, izin verildi veya sistem denetimi) belirten bir **flag**.
3. Alt nesnelerin ACE'yi üst nesneden devralıp devralamayacağını belirleyen **inheritance flags**.
4. Nesne için verilen hakları belirten, 32 bitlik bir değer olan bir [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN).

Erişim belirlenirken her ACE sırayla incelenir. İnceleme şu durumlardan biri gerçekleşene kadar sürer:<sup>[[1]](#references)</sup>

- Bir **Access-Denied ACE**, access token'da tanımlı bir trustee için istenen hakları açıkça reddeder.
- **Access-Allowed ACE(ler)**, access token'daki bir trustee'ye istenen tüm hakları açıkça verir.
- Tüm ACE'ler incelendiğinde, istenen haklardan herhangi biri **açıkça verilmemişse** erişim örtük olarak **reddedilir**.

### Order of ACEs

**ACEs**'lerin (bir şeye kimin erişip kimin erişemeyeceğini belirten kurallar) **DACL** adı verilen bir listede sıralanma biçimi çok önemlidir. Bunun nedeni, sistem bu kurallara göre erişim izni verdikten veya erişimi reddettikten sonra geri kalan kuralları incelemeyi bırakmasıdır.<sup>[[1]](#references)</sup>

Bu ACE'leri düzenlemenin en uygun yolu **"canonical order"** olarak adlandırılır. Bu yöntem, her şeyin sorunsuz ve tutarlı çalışmasına yardımcı olur. **Windows 2000** ve **Windows Server 2003** gibi sistemlerde sıralama şöyledir:

- Önce **bu nesne için özel olarak** tanımlanmış kuralları, üst klasörden gelenler gibi başka bir yerden devralınan kurallardan önce yerleştirin.
- Bu özel kurallar arasında **"hayır" (deny)** diyenleri **"evet" (allow)** diyenlerden önce yerleştirin.
- Başka bir yerden devralınan kurallarda önce **en yakın kaynaktan**, örneğin üst klasörden gelenleri yerleştirin; ardından daha uzaktaki kaynaklardan gelenlerle devam edin. Burada da **"hayır"** diyenleri **"evet"** diyenlerden önce yerleştirin.

Bu düzen iki önemli fayda sağlar:

- Belirli bir **"hayır"** kuralının, diğer **"evet"** kuralları ne olursa olsun geçerli olmasını sağlar.
- Üst klasörlerden veya daha uzaktaki kaynaklardan gelen kurallar devreye girmeden önce, nesnenin sahibine kimin erişebileceği konusunda **son sözü** söyleme imkânı verir.

Bu şekilde, bir dosyanın veya klasörün sahibi kimin erişebileceğini hassas biçimde belirleyebilir; doğru kişilerin erişmesini ve yanlış kişilerin erişememesini sağlar.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dolayısıyla bu **"canonical order"**, erişim kurallarının açık ve etkili olmasını sağlar; özel kuralları öne alır ve her şeyi akıllıca sıralar.

### GUI Example

[**Buradaki örnek**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Bu, ACL, DACL ve ACE'leri gösteren bir klasörün klasik security sekmesidir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Advanced button**'a tıklarsak, inheritance gibi daha fazla seçenek görürüz:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Bir Security Principal ekler veya düzenlersek:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Son olarak, Auditing sekmesinde SACL bulunur:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Klasör gibi kaynaklara erişimi yönetirken, Access Control Lists (ACLs) ve Access Control Entries (ACEs) olarak bilinen listeler ve kurallar kullanırız. Bunlar belirli verilere kimin erişebileceğini veya erişemeyeceğini tanımlar.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Cost adında bir klasörünüz olduğunu ve pazarlama ekibi dışındaki herkesin bu klasöre erişmesini istediğinizi varsayalım. Kuralları doğru şekilde ayarlayarak, herkese izin vermeden önce pazarlama ekibinin erişiminin açıkça reddedilmesini sağlayabiliriz. Bunun için pazarlama ekibinin erişimini reddeden kuralı, herkese erişim izni veren kuraldan önce yerleştiririz.

#### Allowing Access to a Specific Member of a Denied Group

Pazarlama direktörü Bob'un, pazarlama ekibinin genel olarak erişememesi gereken Cost klasörüne erişmesi gerektiğini varsayalım. Bob'a erişim izni veren özel bir kural (ACE) ekleyip bunu pazarlama ekibinin erişimini reddeden kuraldan önce yerleştirebiliriz. Böylece ekibi için geçerli olan genel kısıtlamaya rağmen Bob erişebilir.

#### Understanding Access Control Entries

ACE'ler, ACL içindeki bağımsız kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişime izin verildiğini veya erişimin reddedildiğini belirtir ve bu kuralların alt öğelere nasıl uygulanacağını (inheritance) belirler. İki ana ACE türü vardır:

- **Generic ACEs**: Bunlar geniş kapsamlı olarak uygulanır; tüm nesne türlerini etkiler veya yalnızca kapsayıcılar (klasörler gibi) ile kapsayıcı olmayan nesneler (dosyalar gibi) arasında ayrım yapar. Örneğin, kullanıcıların bir klasörün içeriğini görmesine izin veren, ancak içindeki dosyalara erişmesine izin vermeyen bir kural.
- **Object-Specific ACEs**: Bunlar daha hassas denetim sağlar; belirli nesne türleri, hatta bir nesnenin tek tek özellikleri için kurallar belirlemeye imkân verir. Örneğin, bir kullanıcı dizininde, kullanıcının telefon numarasını güncellemesine izin veren ancak oturum açma saatlerini değiştirmesine izin vermeyen bir kural bulunabilir.

Her ACE; kuralın kime uygulanacağı (Security Identifier veya SID kullanılarak), kuralın neye izin verip neyi reddettiği (access mask kullanılarak) ve diğer nesneler tarafından nasıl devralınacağı gibi önemli bilgileri içerir.

#### Key Differences Between ACE Types

- **Generic ACEs**, aynı kuralın bir nesnenin tüm yönlerine veya bir kapsayıcıdaki tüm nesnelere uygulandığı basit erişim denetimi senaryoları için uygundur.
- **Object-Specific ACEs**, özellikle Active Directory gibi ortamlarda, bir nesnenin belirli özelliklerine erişimi farklı şekilde denetlemeniz gereken daha karmaşık senaryolarda kullanılır.

Özetle, ACL'ler ve ACE'ler hassas erişim denetimleri tanımlamaya yardımcı olur. Böylece hassas bilgilere veya kaynaklara yalnızca doğru kişi ve grupların erişmesi sağlanır; erişim hakları tek tek özellik veya nesne türü düzeyinde özelleştirilebilir.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE türünü belirten flag. Windows 2000 ve Windows Server 2003 altı ACE türünü destekler: Tüm güvenli nesnelere eklenen üç genel ACE türü ve Active Directory nesnelerinde görülebilen üç nesneye özgü ACE türü.                                                                                                                                                                                                                                                            |
| Flags       | Inheritance ve denetimi yöneten bit flag'leri kümesi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE için ayrılan bellek miktarını bayt cinsinden belirtir.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Bitleri nesnenin erişim haklarına karşılık gelen 32 bitlik değer. Bitler açık veya kapalı olarak ayarlanabilir; ancak ayarın anlamı ACE türüne bağlıdır. Örneğin, izinleri okuma hakkına karşılık gelen bit açıksa ve ACE türü Deny ise ACE, nesnenin izinlerini okuma hakkını reddeder. Aynı bit açıkken ACE türü Allow ise ACE, nesnenin izinlerini okuma hakkını verir. Access mask hakkında daha fazla ayrıntı sonraki tabloda yer alır. |
| SID         | Erişimi bu ACE tarafından denetlenen veya izlenen kullanıcıyı ya da grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Nesneye Özgü Erişim Hakları        | Veri okuma, yürütme, veri ekleme          |
| 16 - 22     | Standart Erişim Hakları            | Silme, ACL yazma, sahip yazma              |
| 23          | Güvenlik ACL'sine erişebilir       |                                           |
| 24 - 27     | Ayrılmış                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Aşağıdakilerin tümü                        |
| 29          | Generic Execute                    | Bir programı yürütmek için gereken her şey |
| 30          | Generic Write                      | Bir dosyaya yazmak için gereken her şey    |
| 31          | Generic Read                       | Bir dosyayı okumak için gereken her şey    |

## References

- [1] [Sistemin ACL'leri Kullanma Biçimi - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL ve ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
