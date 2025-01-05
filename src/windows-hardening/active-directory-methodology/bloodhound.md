# BloodHound & Diğer AD Enum Araçları

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) Sysinternal Suite'ten gelmektedir:

> Gelişmiş bir Active Directory (AD) görüntüleyici ve düzenleyicisidir. AD Explorer'ı kullanarak bir AD veritabanında kolayca gezinebilir, favori konumlar tanımlayabilir, nesne özelliklerini ve niteliklerini diyalog kutuları açmadan görüntüleyebilir, izinleri düzenleyebilir, bir nesnenin şemasını görüntüleyebilir ve kaydedip yeniden çalıştırabileceğiniz karmaşık aramalar gerçekleştirebilirsiniz.

### Anlık Görüntüler

AD Explorer, AD'nin anlık görüntülerini oluşturabilir, böylece çevrimdışı kontrol edebilirsiniz.\
Çevrimdışı zafiyetleri keşfetmek veya AD DB'nin farklı durumlarını zaman içinde karşılaştırmak için kullanılabilir.

Bağlanmak için kullanıcı adı, şifre ve yön gerekecektir (herhangi bir AD kullanıcısı gereklidir).

AD'nin anlık görüntüsünü almak için `File` --> `Create Snapshot` yolunu izleyin ve anlık görüntü için bir isim girin.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon), bir AD ortamından çeşitli artefaktları çıkaran ve birleştiren bir araçtır. Bilgiler, analiz kolaylığı sağlamak ve hedef AD ortamının mevcut durumu hakkında bütünsel bir resim sunmak için metriklerle birlikte özet görünümler içeren **özel formatlanmış** Microsoft Excel **raporu** şeklinde sunulabilir.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound, [Linkurious](http://linkurio.us/) üzerine inşa edilmiş, [Electron](http://electron.atom.io/) ile derlenmiş, C# veri toplayıcı tarafından beslenen bir [Neo4j](https://neo4j.com/) veritabanına sahip tek sayfa Javascript web uygulamasıdır.

BloodHound, bir Active Directory veya Azure ortamındaki gizli ve genellikle istenmeyen ilişkileri ortaya çıkarmak için grafik teorisini kullanır. Saldırganlar, BloodHound'u kullanarak, aksi takdirde hızlı bir şekilde tanımlanması imkansız olan son derece karmaşık saldırı yollarını kolayca belirleyebilirler. Savunucular, BloodHound'u kullanarak aynı saldırı yollarını tanımlayıp ortadan kaldırabilirler. Hem mavi hem de kırmızı takımlar, BloodHound'u kullanarak bir Active Directory veya Azure ortamındaki ayrıcalık ilişkilerini daha derinlemesine anlamak için kolayca faydalanabilirler.

Bu nedenle, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) otomatik olarak bir alanı listeleyebilen, tüm bilgileri kaydedebilen, olası ayrıcalık yükseltme yollarını bulabilen ve tüm bilgileri grafikler kullanarak gösterebilen harika bir araçtır.

BloodHound, 2 ana bölümden oluşur: **ingestors** ve **görselleştirme uygulaması**.

**Ingestors**, **alanı listelemek ve tüm bilgileri** görselleştirme uygulamasının anlayacağı bir formatta çıkarmak için kullanılır.

**Görselleştirme uygulaması, neo4j kullanarak** tüm bilgilerin nasıl ilişkili olduğunu gösterir ve alandaki ayrıcalıkları yükseltmenin farklı yollarını sergiler.

### Kurulum

BloodHound CE'nin oluşturulmasından sonra, tüm proje Docker ile kullanım kolaylığı için güncellendi. Başlamak için en kolay yol, önceden yapılandırılmış Docker Compose yapılandırmasını kullanmaktır.

1. Docker Compose'u kurun. Bu, [Docker Desktop](https://www.docker.com/products/docker-desktop/) kurulumu ile birlikte gelmelidir.
2. Çalıştırın:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Compose'un terminal çıktısında rastgele oluşturulmuş şifreyi bulun.  
4. Bir tarayıcıda http://localhost:8080/ui/login adresine gidin. admin kullanıcı adı ve günlüklerden rastgele oluşturulmuş şifre ile giriş yapın.  

Bundan sonra rastgele oluşturulmuş şifreyi değiştirmeniz gerekecek ve ingestor'ları doğrudan indirebileceğiniz yeni arayüz hazır olacak.  

### SharpHound  

Birçok seçeneği var, ancak eğer alan adına katılmış bir PC'den SharpHound'u çalıştırmak ve mevcut kullanıcıyı kullanarak tüm bilgileri çıkarmak istiyorsanız, şunları yapabilirsiniz:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** ve döngü oturumu hakkında daha fazla bilgiye [buradan](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) ulaşabilirsiniz.

Farklı kimlik bilgileri kullanarak SharpHound'u çalıştırmak isterseniz, bir CMD netonly oturumu oluşturabilir ve oradan SharpHound'u çalıştırabilirsiniz:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound hakkında daha fazla bilgi edinin ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r), **Group Policy** ile ilişkili Active Directory'deki **vulnerabilities** bulmak için bir araçtır. \
**group3r'ı** alan içindeki bir hosttan **herhangi bir alan kullanıcısı** ile çalıştırmalısınız.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **AD ortamının güvenlik durumunu değerlendirir** ve grafiklerle güzel bir **rapor** sunar.

Çalıştırmak için, `PingCastle.exe` ikili dosyasını çalıştırabilir ve seçeneklerin bulunduğu bir **etkileşimli oturum** başlatır. Kullanılacak varsayılan seçenek **`healthcheck`** olup, **alan** hakkında bir temel **genel bakış** oluşturacak ve **yanlış yapılandırmaları** ve **zayıflıkları** bulacaktır.

{{#include ../../banners/hacktricks-training.md}}
