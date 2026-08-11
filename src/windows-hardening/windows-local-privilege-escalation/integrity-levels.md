# Bütünlük Seviyeleri

{{#include ../../banners/hacktricks-training.md}}

## Bütünlük Seviyeleri

Windows Vista ve sonraki sürümlerde, güvenliği sağlanabilir nesneler bir **bütünlük seviyesi** etiketi taşıyabilir. Çoğu nesne orta bütünlük olarak değerlendirilirken, düşük bütünlüklü uygulamalar için tasarlanmış belirli konumlar düşük olarak etiketlenebilir. Standart kullanıcılar tarafından başlatılan işlemler normalde orta bütünlükte, yükseltilmiş uygulamalar yüksek bütünlükte ve birçok hizmet sistem bütünlüğünde çalışır.<sup>[[1]](#references)</sup>

Temel bir kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip işlemler tarafından değiştirilememesidir. Windows, nesnenin isteğe bağlı erişim denetim listesini (DACL) değerlendirmeden önce bu Mandatory Integrity Control (MIC) denetimini uygular. Yaygın olarak karşılaşılan seviyeler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`) ile gösterilen en düşük seviyedir. Bu bütünlük etiketini **Anonymous Logon** kimliği (`S-1-5-7`) ile karıştırmayın; kimlik doğrulama kimlikleri ve MIC etiketleri ayrı SID ad alanlarıdır. Gerçek dünyadan bir örnek olarak Chromium'un Windows sandbox'ı, sandbox içindeki hedeflere başlangıçta Low bütünlük atar ve ardından başlangıçtan sonra renderer hedeflerini Untrusted bütünlüğüne düşürür.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Esas olarak internet etkileşimleri için, özellikle Internet Explorer'ın Protected Mode özelliğinde kullanılır; ilişkili dosyaları ve işlemleri ve **Temporary Internet Folder** gibi belirli klasörleri etkiler. Low bütünlük işlemleri, kayıt defterine yazma erişiminin olmaması ve kullanıcı profiline sınırlı yazma erişimi dahil olmak üzere önemli kısıtlamalarla karşılaşır.
- **Medium**: Çoğu etkinlik için varsayılan seviyedir; standart kullanıcılara ve belirli bütünlük seviyeleri olmayan nesnelere atanır. Administrators grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
- **High**: Yöneticiler için ayrılmıştır ve daha düşük bütünlük seviyelerindeki nesneleri, hatta yüksek seviyedeki nesneleri değiştirmelerine olanak tanır.
- **System**: Windows kernel'i ve temel hizmetleri için en yüksek operasyonel seviyedir; yöneticilerin bile erişemeyeceği bu seviye, kritik sistem işlevlerinin korunmasını sağlar.

Windows ayrıca System seviyesinin üzerinde bir protected-process bütünlük değeri tanımlar. Ancak **TrustedInstaller**, ayrı bir MIC seviyesi değil, bir Windows hizmet kimliğidir; korunan işletim sistemi kaynaklarını değiştirebilme yeteneği, bu kimliğe verilen izinlerden kaynaklanır.

Sistem sürücüsünün kökü gibi bir konumun her zaman sabit bir High bütünlük etiketine sahip olduğunu varsaymayın. `icacls` ile etkin DACL'yi ve açık bir mandatory label olup olmadığını inceleyin; etiketi olmayan bir nesne MIC açısından Medium olarak değerlendirilirken DACL'si ve sahipliği erişimi bağımsız olarak yine kısıtlayabilir.<sup>[[1]](#references)[[4]](#references)</sup>

Bir işlemin bütünlük seviyesini **Sysinternals** içindeki **Process Explorer** aracını kullanarak, işlemin özelliklerini açıp **Security** sekmesini görüntüleyerek öğrenebilirsiniz:<sup>[[3]](#references)</sup>

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: Bir işlemin bütünlük seviyesini, Sysinternals içindeki Process Explorer'ı kullanarak işlemin özelliklerine erişip "...](<../../images/image (824).png>)

`whoami /groups` komutunu kullanarak **mevcut bütünlük seviyenizi** de öğrenebilirsiniz:

![Bütünlük Seviyeleri - Bütünlük Seviyeleri: whoami /groups kullanarak mevcut bütünlük seviyenizi de öğrenebilirsiniz](<../../images/image (325).png>)

### Dosya Sisteminde Bütünlük Seviyeleri

Dosya sistemindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimine** sahip olabilir. Bu seviyenin altındaki bir işlem, DACL'si normalde erişim izni verse bile nesnenin mandatory policy'sine tabi olur. Örneğin, standart kullanıcı konsolundan normal bir dosya oluşturun ve izinlerini inceleyin:<sup>[[1]](#references)[[4]](#references)</sup>
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
`DESKTOP-IDJHTKP\user` kullanıcısının dosya üzerinde **FULL privileges** yetkisi vardır çünkü dosyayı bu kullanıcı oluşturmuştur. Ancak zorunlu etiket, işlem High integrity seviyesinde çalışmadığı sürece kullanıcının dosyayı değiştirmesini engeller. Görüntülenen zorunlu politika `(NW)`, yani no-write-up olduğu için kullanıcı dosyayı yine de okuyabilir:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Bu nedenle, bir dosyanın minimum bir bütünlük seviyesi olduğunda, dosyayı değiştirmek için en azından o bütünlük seviyesinde çalışıyor olmanız gerekir.**

### Binary'lerde Bütünlük Seviyeleri

Aşağıdaki örnekte `C:\Windows\System32\cmd-low.exe` konumundaki `cmd.exe` kopyası kullanılır ve bu kopyaya **bir administrator konsolundan Low bütünlük seviyesi atanır**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi `cmd-low.exe` çalıştırdığımda, medium yerine **low-integrity level altında çalışacak**:

![Dosya sistemindeki Integrity Levels - Binaries içindeki Integrity Levels: Şimdi cmd-low.exe çalıştırdığımda, medium yerine low-integrity level altında çalışacak](<../../images/image (313).png>)

Bir binary'ye High integrity label atamak (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), onun otomatik olarak High integrity ile çalışmasını sağlamaz. Bir Medium-integrity process tarafından çağrılırsa, Medium integrity ile çalışır; çünkü yeni bir process, executable file'ın ve çağıran process'in integrity level'larından düşük olanı alır.<sup>[[1]](#references)</sup>

### Process'lerde Integrity Levels

Tüm file ve folder'ların açık bir minimum integrity label'ı yoktur, **ancak her process bir integrity level ile çalışır**. File-system object'lerinde olduğu gibi, **başka bir process'e write access isteyen bir process en az aynı integrity level'a sahip olmalıdır**. Bu nedenle Low-integrity process, bir Medium-integrity process'i full access ile açamaz.<sup>[[1]](#references)</sup>

Bu kısıtlamalar nedeniyle en güvenli yaklaşım, **her process'i amaçlanan işlevini gerçekleştirmesine hâlâ izin veren en düşük integrity level'da çalıştırmaktır**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
