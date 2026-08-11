# Bütünlük Seviyeleri

{{#include ../../banners/hacktricks-training.md}}

## Bütünlük Seviyeleri

Windows Vista ve sonraki sürümlerde, güvenliğinin sağlanabildiği nesneler bir **bütünlük seviyesi** etiketi taşıyabilir. Çoğu nesne orta bütünlük olarak değerlendirilirken, düşük bütünlüklü uygulamalar için tasarlanmış belirli konumlar düşük olarak etiketlenebilir. Standart kullanıcılar tarafından başlatılan işlemler normalde orta bütünlükte, yükseltilmiş uygulamalar yüksek bütünlükte ve birçok servis sistem bütünlüğünde çalışır.<sup>[[1]](#references)</sup>

Temel bir kural, nesnelerin seviyesinden daha düşük bir bütünlük seviyesine sahip işlemler tarafından değiştirilememesidir. Windows, nesnenin isteğe bağlı erişim denetim listesini (DACL) değerlendirmeden önce bu Mandatory Integrity Control (MIC) denetimini uygular. Yaygın olarak karşılaşılan seviyeler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: `SECURITY_MANDATORY_UNTRUSTED_RID` ile temsil edilen en düşük seviye.
- **Low**: Özellikle Internet Explorer'ın Protected Mode özelliğinde olmak üzere, internet etkileşimleri için kullanılır; ilişkili dosya ve işlemleri ve **Temporary Internet Folder** gibi belirli klasörleri etkiler. Low integrity işlemleri, kayıt defterine yazma erişimi olmaması ve kullanıcı profiline yazma erişiminin sınırlı olması dahil olmak üzere önemli kısıtlamalara tabidir.
- **Medium**: Çoğu etkinlik için varsayılan seviyedir; standart kullanıcılara ve belirli bir bütünlük seviyesi olmayan nesnelere atanır. Administrators grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
- **High**: Yöneticiler için ayrılmıştır ve daha düşük bütünlük seviyelerindeki nesneleri, hatta High seviyesindeki nesneleri bile değiştirmelerine izin verir.
- **System**: Windows kernel'i ve temel servisler için en yüksek operasyonel seviyedir. Yöneticilerin bile erişemeyeceği bu seviye, kritik sistem işlevlerinin korunmasını sağlar.

Windows ayrıca System seviyesinin üzerinde bir protected-process bütünlük değeri tanımlar. Ancak **TrustedInstaller**, ayrı bir MIC seviyesi değil, bir Windows servis kimliğidir; korunan işletim sistemi kaynaklarını değiştirme yeteneği, bu kimliğe verilen izinlerden kaynaklanır.

Bir işlemin bütünlük seviyesini **Sysinternals** içerisindeki **Process Explorer** aracını kullanarak, işlemin özelliklerini açıp **Security** sekmesini görüntüleyerek öğrenebilirsiniz:<sup>[[3]](#references)</sup>

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: Bir işlemin bütünlük seviyesini Sysinternals içerisindeki Process Explorer aracını kullanarak, işlemin özelliklerine erişip "...](<../../images/image (824).png>)

`whoami /groups` komutunu kullanarak **mevcut bütünlük seviyenizi** de öğrenebilirsiniz:

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: whoami /groups komutunu kullanarak mevcut bütünlük seviyenizi de öğrenebilirsiniz](<../../images/image (325).png>)

### Dosya Sisteminde Bütünlük Seviyeleri

Dosya sistemindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimine** sahip olabilir. Bu seviyenin altında olan bir işlem, DACL erişim verse bile nesnenin zorunlu politikasına tabi olur. Örneğin, standart kullanıcı konsolundan normal bir dosya oluşturup izinlerini inceleyin:<sup>[[1]](#references)[[4]](#references)</sup>
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
Şimdi dosyaya minimum **High** integrity level atayın. Bu işlem **administrator** olarak çalışan bir **console** üzerinden yapılmalıdır; çünkü normal bir console Medium integrity seviyesinde çalışır ve bir nesneye High integrity atamasına **izin verilmez**:
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
`DESKTOP-IDJHTKP\user` kullanıcısı, dosyayı bu kullanıcı oluşturduğu için dosya üzerinde **TAM yetkilere** sahiptir. Ancak zorunlu etiket, process High integrity seviyesinde çalışmadığı sürece kullanıcının dosyayı değiştirmesini engeller. Görüntülenen zorunlu policy `(NW)`, yani no-write-up olduğu için kullanıcı dosyayı yine de okuyabilir:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Bu nedenle, bir dosyanın minimum bütünlük seviyesi olduğunda, dosyayı değiştirebilmek için en azından bu bütünlük seviyesinde çalışıyor olmanız gerekir.**

### Binary'lerde Bütünlük Seviyeleri

Aşağıdaki örnekte, `C:\Windows\System32\cmd-low.exe` konumunda `cmd.exe` dosyasının bir kopyası kullanılır ve **bir yönetici konsolundan Düşük bütünlük seviyesi atanır**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi `cmd-low.exe` çalıştırdığımda, orta düzey yerine **düşük bütünlük düzeyinde çalışacak**:

![Dosya sisteminde bütünlük düzeyleri - İkili dosyalarda bütünlük düzeyleri: Şimdi cmd-low.exe çalıştırdığımda, orta düzey yerine düşük bütünlük düzeyinde çalışacak](<../../images/image (313).png>)

Bir ikili dosyaya yüksek bütünlük etiketi atamak (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), dosyanın otomatik olarak yüksek bütünlük düzeyinde çalışmasını sağlamaz. Orta bütünlük düzeyindeki bir process tarafından çağrılırsa, orta bütünlük düzeyinde çalışır; çünkü yeni bir process, çalıştırılabilir dosyanın ve çağıran process'in bütünlük düzeylerinden düşük olanını alır.<sup>[[1]](#references)</sup>

### Process'lerde Bütünlük Düzeyleri

Tüm dosya ve klasörlerin açıkça belirtilmiş bir minimum bütünlük etiketi yoktur, **ancak her process bir bütünlük düzeyinde çalışır**. Dosya sistemi nesnelerinde olduğu gibi, **başka bir process'e yazma erişimi elde etmek isteyen bir process'in en az aynı bütünlük düzeyine sahip olması gerekir**. Bu nedenle düşük bütünlük düzeyindeki bir process, orta bütünlük düzeyindeki bir process'i tam erişimle açamaz.<sup>[[1]](#references)</sup>

Bu kısıtlamalar nedeniyle en güvenli yaklaşım, **her process'i amaçlanan işlevini yerine getirmesine hâlâ izin veren en düşük bütünlük düzeyinde çalıştırmaktır**.

## References

- [1] [Microsoft Learn – Zorunlu Bütünlük Denetimi](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL numaralandırması](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
