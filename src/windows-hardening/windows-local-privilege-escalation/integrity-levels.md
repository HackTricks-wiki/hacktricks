# Bütünlük Düzeyleri

{{#include ../../banners/hacktricks-training.md}}

## Bütünlük Düzeyleri

Windows Vista ve sonraki sürümlerde, güvenliği sağlanabilir nesneler bir **bütünlük düzeyi** etiketi taşıyabilir. Nesnelerin çoğu orta bütünlük olarak değerlendirilirken, düşük bütünlüklü uygulamalar için tasarlanmış belirli konumlar düşük olarak etiketlenebilir. Standart kullanıcılar tarafından başlatılan işlemler normalde orta bütünlükte, yükseltilmiş uygulamalar yüksek bütünlükte ve birçok hizmet sistem bütünlüğünde çalışır.<sup>[[1]](#references)</sup>

Temel bir kural, nesnelerin düzeyinden daha düşük bir bütünlük düzeyine sahip işlemler tarafından değiştirilememesidir. Windows, nesnenin isteğe bağlı erişim denetim listesini (DACL) değerlendirmeden önce bu Zorunlu Bütünlük Denetimi (MIC) kontrolünü uygular. Yaygın olarak karşılaşılan düzeyler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: `SECURITY_MANDATORY_UNTRUSTED_RID` ile temsil edilen en düşük düzeydir. Gerçek dünyadan bir örnek olarak Chromium'un Windows sandbox özelliği, başlangıçta sandbox içindeki hedeflere Low bütünlük atar ve ardından başlatma sonrasında renderer hedeflerinin bütünlüğünü Untrusted düzeyine düşürür.<sup>[[5]](#references)</sup>
- **Low**: Özellikle Internet Explorer'ın Protected Mode özelliğinde internet etkileşimleri için kullanılır; ilişkili dosyaları ve işlemleri, ayrıca **Temporary Internet Folder** gibi belirli klasörleri etkiler. Low bütünlük işlemleri, kayıt defterine yazma erişiminin olmaması ve kullanıcı profiline yazma erişiminin sınırlı olması dahil olmak üzere önemli kısıtlamalara tabidir.
- **Medium**: Çoğu etkinlik için varsayılan düzeydir; standart kullanıcılara ve belirli bütünlük düzeyleri olmayan nesnelere atanır. Administrators grubunun üyeleri bile varsayılan olarak bu düzeyde çalışır.
- **High**: Yöneticiler için ayrılmıştır ve düşük bütünlük düzeylerindeki, hatta High düzeyindeki nesneleri değiştirmelerine izin verir.
- **System**: Windows kernel'i ve temel hizmetler için en yüksek operasyonel düzeydir; yöneticilerin bile erişemeyeceği bu düzey, hayati sistem işlevlerinin korunmasını sağlar.

Windows, System düzeyinin üzerinde bir protected-process bütünlük değeri de tanımlar. Ancak **TrustedInstaller**, ayrı bir MIC düzeyi değil, Windows hizmet kimliğidir; korunan işletim sistemi kaynaklarını değiştirebilmesi, bu kimliğe verilen izinlerden kaynaklanır.

Bir işlemin bütünlük düzeyini, **Sysinternals** tarafından sağlanan **Process Explorer** aracında işlemin özelliklerini açıp **Security** sekmesini görüntüleyerek öğrenebilirsiniz:<sup>[[3]](#references)</sup>

![Bütünlük Düzeyleri - Bütünlük Düzeyleri: Sysinternals tarafından sağlanan Process Explorer kullanılarak, işlemin özelliklerine erişip "..." görüntülenerek bir işlemin bütünlük düzeyini öğrenebilirsiniz](<../../images/image (824).png>)

Ayrıca `whoami /groups` komutunu kullanarak **mevcut bütünlük düzeyinizi** öğrenebilirsiniz:

![Bütünlük Düzeyleri - Bütünlük Düzeyleri: whoami /groups kullanarak mevcut bütünlük düzeyinizi de öğrenebilirsiniz](<../../images/image (325).png>)

### Dosya Sisteminde Bütünlük Düzeyleri

Dosya sistemindeki bir nesne, bir **minimum bütünlük düzeyi gereksinimine** sahip olabilir. Bu düzeyin altındaki bir işlem, DACL normalde erişim izni verse bile nesnenin zorunlu politikasına tabi olur. Örneğin, standart kullanıcı konsolundan normal bir dosya oluşturup izinlerini inceleyin:<sup>[[1]](#references)[[4]](#references)</sup>
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
Şimdi dosyaya minimum integrity level **High** atayın. Bu işlem **administrator** olarak çalışan bir **console** üzerinden **yapılmalıdır**, çünkü normal bir **console** Medium integrity seviyesinde çalışır ve bir nesneye High integrity atamasına **izin verilmez**:
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
Kullanıcı `DESKTOP-IDJHTKP\user`, dosyayı bu kullanıcı oluşturduğu için dosya üzerinde **FULL privileges** sahibidir. Ancak zorunlu etiket, işlem High integrity düzeyinde çalışmadığı sürece kullanıcının dosyayı değiştirmesini engeller. Görüntülenen zorunlu politika `(NW)`, yani no-write-up olduğu için kullanıcı dosyayı yine de okuyabilir:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Bu nedenle, bir dosyanın minimum integrity level değeri varsa, dosyayı değiştirebilmek için en azından bu integrity level değerinde çalışıyor olmanız gerekir.**

### Binary'lerde Integrity Level'lar

Aşağıdaki örnekte `C:\Windows\System32\cmd-low.exe` konumundaki `cmd.exe` kopyası kullanılır ve **administrator console üzerinden Low integrity level atanır**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe` çalıştırdığımda orta bütünlük seviyesi yerine **düşük bütünlük seviyesinde çalışacak**:

![Dosya sistemindeki bütünlük seviyeleri - Binary'lerde bütünlük seviyeleri: Şimdi, cmd-low.exe'yi çalıştırdığımda orta bütünlük seviyesi yerine düşük bütünlük seviyesinde çalışacak](<../../images/image (313).png>)

Bir binary'ye High bütünlük etiketi (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) atamak, binary'nin otomatik olarak High bütünlük seviyesinde çalışmasını sağlamaz. Medium bütünlük seviyesindeki bir process tarafından çağrılırsa Medium bütünlük seviyesinde çalışır; çünkü yeni bir process, executable dosyasının ve çağıran process'in bütünlük seviyelerinden düşük olanını alır.<sup>[[1]](#references)</sup>

### Process'lerde Bütünlük Seviyeleri

Tüm dosya ve klasörlerin açıkça belirtilmiş bir minimum bütünlük etiketi yoktur, **ancak her process bir bütünlük seviyesinde çalışır**. Dosya sistemi nesnelerinde olduğu gibi, **başka bir process'e yazma erişimi elde etmek isteyen bir process en az aynı bütünlük seviyesine sahip olmalıdır**. Bu nedenle, Low bütünlük seviyesindeki bir process, tam erişimle Medium bütünlük seviyesindeki bir process'i açamaz.<sup>[[1]](#references)</sup>

Bu kısıtlamalar nedeniyle en güvenli yaklaşım, **her process'i amaçlanan işini gerçekleştirmesine hâlâ olanak tanıyan en düşük bütünlük seviyesinde çalıştırmaktır**.

## References

- [1] [Microsoft Learn – Zorunlu Bütünlük Denetimi](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL numaralandırması](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Varsayılan Windows sandbox bütünlük ilkesi](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
