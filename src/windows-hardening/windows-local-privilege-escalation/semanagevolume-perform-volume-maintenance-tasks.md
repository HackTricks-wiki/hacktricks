# SeManageVolumePrivilege: Birim bakımının kötüye kullanılması ve ham erişimin doğrulanması

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows kullanıcı hakkı: Birim bakım görevlerini gerçekleştirme (sabit değer: SeManageVolumePrivilege).

Bu hak, birleştirme ve birim oluşturma ya da kaldırma gibi birim bakım işlemlerine izin verir. Microsoft, bu hakkı elinde bulunduran birinin dosyaları başka verileri içeren depolama alanına genişletebileceği ve ardından elde edilen baytları okuyabileceği veya değiştirebileceği konusunda uyarır.<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` hakkına sahip olmayı garantili ham disk erişimiyle bir tutmayın. Microsoft, doğrudan erişim için `CreateFile` aracılığıyla fiziksel bir diskin veya birimin açılmasının yönetici ayrıcalıkları gerektirdiğini ve normal nesne/cihaz erişim denetimlerinin geçerliliğini koruduğunu belirtir. Herhangi bir dosyanın okunabileceğini iddia etmeden önce, ilgili derleme veya üründe belirtecin, cihaz ACL’sinin, istenen erişimin, paylaşım bayraklarının ve birim durumunun ham tanıtıcıya izin verip vermediğini test edin.<sup>[[3]](#references)</sup>

Varsayılan: Sunucularda ve etki alanı denetleyicilerinde Administrators.<sup>[[1]](#references)</sup>

## Kötüye kullanım senaryoları

- Hesap gerçekten okunabilir bir ham birim tanıtıcısı alabiliyorsa, NTFS uyumlu bir parser dosya başına ACL’leri atlayabilir ve ayrılmış kümelerdeki korumalı veya kilitli dosyaları kurtarabilir.
- Olası hedefler arasında `C:\Windows\System32` altındaki kilitli veya ACL korumalı içerikler, kayıt defteri kovanları, DPAPI ana anahtarları, SAM ve —bir anlık görüntü veya çevrimdışı birim üzerinden ayrıca erişilebildiği durumlarda— `ntds.dit` bulunur.
- Sertifika hizmetleri ana bilgisayarlarında, yazılım anahtarlarının kullanılabileceği konumlar arasında `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` ve `%ProgramData%\Microsoft\Crypto\Keys` bulunur; bir dosyanın kurtarılması ancak anahtar materyali dışa aktarılabiliyorsa ve şifresi çözülebiliyorsa işe yarar.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Bir AD CS ana bilgisayarında, başarıyla kurtarılan **dışa aktarılabilir/yazılım destekli** bir CA özel anahtarı Golden Certificate kötüye kullanımını mümkün kılabilir. Donanım destekli veya dışa aktarılamayan anahtar tasarımları bu yolu değiştirir.<sup>[[2]](#references)</sup>
- Bazı birim bakım araçları, işlem için izin verildiğinde dosya sistemi ACL girdilerini değiştirmek üzere `FSCTL_SD_GLOBAL_CHANGE` kullanır. Bu, ham blokları pasif biçimde okumak yerine erişim denetimlerini değiştirir, birimin büyük bir bölümünü etkileyebilir ve gerçek belirteç ile cihaz davranışına göre doğrulanmalıdır. [Araç kaynak kodu](https://github.com/CsEnox/SeManageVolumeExploit) bu özel mekanizmayı gösterir; yalnızca bu ayrıcalığa sahip olmak işlemin başarılı olacağını kanıtlamaz.
- ACL değişiklikleri yoluyla dosya erişimi elde etmek, EFS ile şifrelenmiş bir dosyanın şifresini çözmez. Açık metin için hâlâ eşleşen bir kullanıcı veya kurtarma özel anahtarı gerekir. Benzer şekilde, yazılım destekli bir CA anahtarını [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) ile dışa aktarmak; anahtarın yerel olarak kullanılabilir, dışa aktarılabilir ve erişilebilir olmasına bağlıdır.

Not: Yardımcı araçlardan yararlanmıyorsanız NTFS yapılarını işlemek için yine de bir parser gerekir. Piyasada bulunan birçok araç ham erişimin ayrıntılarını soyutlar.

## Pratik teknikler

- Ham birim tanıtıcısı açıp kümeleri okuyun:

<details>
<summary>Genişletmek için tıklayın</summary>

```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
  static void Main(string[] a){
    using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
      fs.Position = 0x100000; // seek
      var buf = new byte[4096];
      fs.Read(buf,0,buf.Length);
      File.WriteAllBytes("C:\\temp\\blk.bin", buf);
    }
  }
}
```

</details>

- Raw volume'dan belirli dosyaları kurtarmak için NTFS destekli bir araç kullanın:
  - RawCopy/RawCopy64 (kullanımdaki dosyaların sektör düzeyinde kopyası)
  - FTK Imager veya The Sleuth Kit (salt okunur imaj alma, ardından dosyaları carve etme)
  - vssadmin/diskshadow + shadow copy, ardından hedef dosyayı snapshot'tan kopyalama (VSS oluşturabiliyorsanız; genellikle admin yetkisi gerektirir, ancak çoğunlukla SeManageVolumePrivilege'e sahip operatörler tarafından kullanılabilir)

Hedeflenebilecek yaygın hassas yollar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (yerel sırlar)
- C:\Windows\NTDS\ntds.dit (etki alanı denetleyicileri – shadow copy aracılığıyla)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA sertifikaları/CRL'ler; özel anahtarlar yukarıdaki machine key store'da bulunur)

## AD CS bağlantısı: Golden Certificate oluşturma

Enterprise CA'nın özel anahtarını machine key store'dan okuyabiliyorsanız, rastgele principal'lar için client-auth sertifikaları oluşturabilir ve PKINIT/Schannel aracılığıyla kimlik doğrulaması yapabilirsiniz. Bu genellikle Golden Certificate olarak adlandırılır.<sup>[[2]](#references)</sup> Bkz.:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Bölüm: “Çalınmış CA Sertifikalarıyla Sertifika Oluşturma (Golden Certificate) – DPERSIST1”).

## Tespit ve güçlendirme

- SeManageVolumePrivilege (Perform volume maintenance tasks) atamasını yalnızca güvenilir admin'lerle sınırlandırın.
- Sensitive Privilege Use'ı ve \\.\C:, \\.\PhysicalDrive0 gibi aygıt nesnelerine yönelik process handle açılışlarını izleyin.
- Kopyalanmış bir key-container dosyasının kullanılabilir özel anahtar materyalini kurtarmaya yetmemesi için, düzgün yapılandırılmış HSM veya TPM destekli, dışa aktarılamayan CA anahtarlarını tercih edin.
- CA anahtarı yolu dışındaki uygulama sırları için DPAPI veya DPAPI-NG, kopyalanmış bir veri dosyasını kullanıcıya, makineye, gruba veya başka bir yetkili principal'a bağlayarak yetersiz hâle getirebilir. Bu, ele geçirilmiş principal'ın zaten erişebildiği düz metni korumaz.<sup>[[4]](#references)</sup>
- Upload, temp ve çıkarma yollarını çalıştırılamaz ve birbirinden ayrı tutun (bu zincirin post-exploitation aşamasında sıklıkla eşlik eden web bağlamı savunması).

## References

- [1] [Microsoft – Birim bakım görevlerini gerçekleştirme (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (CA anahtarını okumak için SeManageVolumePrivilege kullanımı → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` fiziksel diskleri ve birimleri](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Kriptografi API'si: Next Generation ve DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
