# Bütünlük Seviyeleri

{{#include ../../banners/hacktricks-training.md}}

## Bütünlük Seviyeleri

Windows Vista ve sonraki sürümlerde, korunan tüm öğeler bir **bütünlük seviyesi** etiketiyle birlikte gelir. Bu yapı, Internet Explorer 7'nin düşük bütünlük seviyesinde yazabildiği belirli klasörler ve dosyalar dışında, dosyalara ve registry anahtarlarına çoğunlukla "medium" bütünlük seviyesi atar. Varsayılan davranış, standard user'lar tarafından başlatılan process'lerin medium bütünlük seviyesine sahip olmasıdır; services ise genellikle system bütünlük seviyesinde çalışır. High-bütünlük etiketi root directory'yi korur.

Önemli bir kural, object'lerin object'in seviyesinden daha düşük bir bütünlük seviyesine sahip process'ler tarafından değiştirilememesidir. Bütünlük seviyeleri şunlardır:

- **Untrusted**: Bu seviye anonymous login kullanan process'ler içindir. Örnek: Chrome
- **Low**: Özellikle Internet Explorer'ın Protected Mode'undaki internet etkileşimleri için kullanılır; ilişkili dosyaları ve process'leri, ayrıca **Temporary Internet Folder** gibi belirli klasörleri etkiler. Low bütünlük process'leri, registry'ye yazma erişiminin olmaması ve user profile'a sınırlı yazma erişimi dahil olmak üzere önemli kısıtlamalara sahiptir.
- **Medium**: Çoğu etkinlik için varsayılan seviyedir ve standard user'lara ve belirli bütünlük seviyeleri olmayan object'lere atanır. Administrators grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
- **High**: Administrators için ayrılmıştır ve onların daha düşük bütünlük seviyelerindeki object'leri, hatta high seviyesindekileri bile değiştirmesine olanak tanır.
- **System**: Windows kernel'i ve core services için en yüksek çalışma seviyesidir. Administrators için bile erişilemezdir ve kritik system işlevlerinin korunmasını sağlar.
- **Installer**: Diğer tüm seviyelerin üzerinde yer alan özel bir seviyedir; bu seviyedeki object'lerin diğer tüm object'leri uninstall etmesini sağlar.

**Process Explorer** ile **Sysinternals** üzerinden bir process'in bütünlük seviyesini öğrenebilirsiniz. Bunun için process'in **properties** bölümüne girip "**Security**" sekmesini görüntüleyin:

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: Bir process'in bütünlük seviyesini **Sysinternals** içindeki Process Explorer'ı kullanarak, process'in properties bölümüne girip "Security" sekmesini görüntüleyerek öğrenebilirsiniz.](<../../images/image (824).png>)

`whoami /groups` kullanarak **mevcut bütünlük seviyenizi** de öğrenebilirsiniz.

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: whoami /groups kullanarak mevcut bütünlük seviyenizi de öğrenebilirsiniz.](<../../images/image (325).png>)

### File-system'de Bütünlük Seviyeleri

File-system içindeki bir object için **minimum bütünlük seviyesi gereksinimi** olabilir ve bir process bu bütünlük seviyesine sahip değilse object ile etkileşim kuramaz.\
Örneğin, **normal bir user console'dan normal bir file oluşturalım ve permissions'ı kontrol edelim**:
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
Şimdi dosyaya minimum **High** integrity level atayalım. Bu işlem, **administrator** olarak çalışan bir **console** üzerinden **yapılmalıdır**; çünkü **regular console**, Medium Integrity level'da çalışır ve bir objeye High Integrity level atamasına **izin verilmez**:
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
İşlerin ilginçleştiği nokta burasıdır. `DESKTOP-IDJHTKP\user` kullanıcısının dosya üzerinde **FULL privileges** sahibi olduğunu (dosyayı oluşturan kullanıcı gerçekten de buydu) görebilirsiniz; ancak uygulanan minimum bütünlük seviyesi nedeniyle, High Integrity Level içinde çalışmadığı sürece dosyayı artık değiştiremeyecektir (dosyayı okuyabileceğini unutmayın):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Bu nedenle, bir dosyanın minimum bütünlük seviyesi olduğunda, dosyayı değiştirebilmek için en azından o bütünlük seviyesinde çalışıyor olmanız gerekir.**

### İkili Dosyalardaki Bütünlük Seviyeleri

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` konumunda oluşturdum ve **bir administrator konsolundan düşük bütünlük seviyesi olarak ayarladım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe` çalıştırdığımda **medium yerine low integrity level altında çalışacak**:

![File-system'de Integrity Levels - Binaries'de Integrity Levels: Şimdi, cmd-low.exe çalıştırdığımda medium yerine low integrity level altında çalışacak](<../../images/image (313).png>)

Merak edenler için, bir binary'ye high integrity level atarsanız (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), otomatik olarak high integrity level ile çalışmaz (medium integrity level'dan --varsayılan olarak-- çağırırsanız medium integrity level altında çalışır).

### Process'lerde Integrity Levels

Tüm dosya ve klasörlerin minimum bir integrity level'ı yoktur, **ancak tüm process'ler bir integrity level altında çalışır**. Dosya sisteminde olduğu gibi, **bir process başka bir process'in içine yazmak istiyorsa en azından aynı integrity level'a sahip olmalıdır**. Bu, low integrity level'a sahip bir process'in medium integrity level'a sahip bir process'e full access ile bir handle açamayacağı anlamına gelir.

Bu ve önceki bölümde açıklanan kısıtlamalar nedeniyle, güvenlik açısından bir process'i her zaman **mümkün olan en düşük integrity level'da çalıştırmanız önerilir**.

{{#include ../../banners/hacktricks-training.md}}
