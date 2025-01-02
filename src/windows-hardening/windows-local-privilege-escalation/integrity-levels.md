# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista ve sonraki sürümlerde, tüm korunan öğeler bir **bütünlük seviyesi** etiketi ile gelir. Bu yapılandırma, belirli klasörler ve Internet Explorer 7'nin düşük bütünlük seviyesinde yazabileceği dosyalar hariç, dosyalara ve kayıt defteri anahtarlarına genellikle "orta" bir bütünlük seviyesi atar. Varsayılan davranış, standart kullanıcılar tarafından başlatılan süreçlerin orta bütünlük seviyesine sahip olmasıdır, oysa hizmetler genellikle sistem bütünlük seviyesinde çalışır. Yüksek bir bütünlük etiketi, kök dizini korur.

Ana kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip süreçler tarafından değiştirilemeyeceğidir. Bütünlük seviyeleri şunlardır:

- **Güvenilmez**: Bu seviye, anonim oturum açma ile çalışan süreçler içindir. %%%Örnek: Chrome%%%
- **Düşük**: Temelde internet etkileşimleri için, özellikle Internet Explorer'ın Korunan Modu'nda, ilişkili dosyaları ve süreçleri etkileyen ve **Geçici İnternet Klasörü** gibi belirli klasörler için. Düşük bütünlük seviyesine sahip süreçler, kayıt defteri yazma erişimi olmaması ve sınırlı kullanıcı profili yazma erişimi dahil olmak üzere önemli kısıtlamalarla karşılaşır.
- **Orta**: Çoğu etkinlik için varsayılan seviye, standart kullanıcılara ve belirli bütünlük seviyeleri olmayan nesnelere atanır. Yöneticiler grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
- **Yüksek**: Yöneticiler için ayrılmıştır, onlara daha düşük bütünlük seviyelerine sahip nesneleri değiştirme yetkisi verir, bunlar yüksek seviyedeki nesneleri de içerir.
- **Sistem**: Windows çekirdeği ve temel hizmetler için en yüksek operasyonel seviyedir, yöneticiler için bile erişilemez, kritik sistem işlevlerinin korunmasını sağlar.
- **Yükleyici**: Diğer tüm seviyelerin üzerinde yer alan benzersiz bir seviyedir, bu seviyedeki nesnelerin herhangi bir diğer nesneyi kaldırmasına olanak tanır.

Bir sürecin bütünlük seviyesini **Sysinternals**'dan **Process Explorer** kullanarak, sürecin **özelliklerine** erişip "**Güvenlik**" sekmesine bakarak öğrenebilirsiniz:

![](<../../images/image (824).png>)

Ayrıca `whoami /groups` komutunu kullanarak **mevcut bütünlük seviyenizi** de öğrenebilirsiniz.

![](<../../images/image (325).png>)

### Integrity Levels in File-system

Dosya sistemindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimi** gerektirebilir ve eğer bir süreç bu bütünlük seviyesine sahip değilse, onunla etkileşimde bulunamayacaktır.\
Örneğin, **standart bir kullanıcı konsolundan bir dosya oluşturalım ve izinleri kontrol edelim**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Şimdi dosyaya **Yüksek** bir minimum bütünlük seviyesi atayalım. Bu **bir yönetici olarak çalışan bir konsoldan** **yapılmalıdır**, çünkü **normal bir konsol** Orta Bütünlük seviyesinde çalışacak ve bir nesneye Yüksek Bütünlük seviyesi atamasına **izin verilmeyecektir**:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Burada işler ilginçleşiyor. Kullanıcı `DESKTOP-IDJHTKP\user` dosya üzerinde **TAM yetkilere** sahip (aslında bu dosyayı oluşturan kullanıcıdır), ancak uygulanan minimum bütünlük seviyesi nedeniyle, artık dosyayı değiştiremeyecek, yalnızca Yüksek Bütünlük Seviyesi içinde çalışıyorsa (okuyabileceğini unutmayın):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **Bu nedenle, bir dosyanın minimum bir bütünlük seviyesi olduğunda, onu değiştirmek için en az o bütünlük seviyesinde çalışıyor olmanız gerekir.**

### Binaries'deki Bütünlük Seviyeleri

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` olarak oluşturdum ve ona **bir yönetici konsolundan düşük bir bütünlük seviyesi ayarladım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe` çalıştırdığımda, **orta bir seviyede değil, düşük bir bütünlük seviyesinde çalışacak**:

![](<../../images/image (313).png>)

Meraklılar için, bir ikili dosyaya yüksek bütünlük seviyesi atarsanız (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), otomatik olarak yüksek bütünlük seviyesinde çalışmayacaktır (orta bütünlük seviyesinden çağırırsanız --varsayılan olarak-- orta bütünlük seviyesinde çalışacaktır).

### Süreçlerde Bütünlük Seviyeleri

Tüm dosya ve klasörlerin minimum bir bütünlük seviyesi yoktur, **ancak tüm süreçler bir bütünlük seviyesinde çalışmaktadır**. Ve dosya sistemiyle olan benzer bir şekilde, **bir süreç başka bir süreç içinde yazmak istiyorsa en az aynı bütünlük seviyesine sahip olmalıdır**. Bu, düşük bütünlük seviyesine sahip bir sürecin, orta bütünlük seviyesine sahip bir sürece tam erişimle bir tanıtıcı açamayacağı anlamına gelir.

Bu ve önceki bölümde belirtilen kısıtlamalar nedeniyle, güvenlik açısından, her zaman **bir süreci mümkün olan en düşük bütünlük seviyesinde çalıştırmak önerilir**.

{{#include ../../banners/hacktricks-training.md}}
