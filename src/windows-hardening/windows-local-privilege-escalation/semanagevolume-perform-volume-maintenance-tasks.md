# SeManageVolumePrivilege: Ham birim erişimi ile rastgele dosya okuma

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows kullanıcı hakkı: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Sahipleri defragmentasyon, birim oluşturma/kaldırma ve bakım I/O'su gibi düşük seviyeli birim işlemlerini gerçekleştirebilir. Saldırganlar için kritik olan nokta: bu hak, ham birim cihazı tutamacılarını (ör. \\.\C:) açmaya ve NTFS dosya ACL'lerini atlayan doğrudan disk I/O'su yapmaya izin verir. Ham erişimle, dosya sisteminin yapısını çevrimdışı olarak ayrıştırarak veya blok/cluster düzeyinde okuyan yardımcı araçları kullanarak, DACL tarafından engellense bile hacimdeki herhangi bir dosyanın byte'larını kopyalayabilirsiniz.

Varsayılan: Sunucularda ve etki alanı denetleyicilerinde Administrators.

## Kötüye kullanım senaryoları

- Disk cihazını okuyarak ACL'leri atlayıp rastgele dosya okuma (ör. %ProgramData%\Microsoft\Crypto\RSA\MachineKeys ve %ProgramData%\Microsoft\Crypto\Keys altındaki makine özel anahtarları, registry hiveları, DPAPI masterkeys, SAM, ntds.dit (VSS üzerinden) gibi sistem korumalı hassas materyalleri exfiltrate etmek, vb.).
- Kilitli/ayrıcalıklı yolları (C:\Windows\System32\…) atlamak için ham cihazdan doğrudan byte kopyalamak.
- AD CS ortamlarında, CA’nın anahtar materyalini (machine key store) exfiltrate edip “Golden Certificates” basarak PKINIT aracılığıyla herhangi bir domain principal’ın taklit edilmesi. Aşağıdaki bağlantıya bakın.

Not: Yardımcı araçlara güvenmiyorsanız NTFS yapıları için bir ayrıştırıcıya ihtiyacınız olacaktır. Birçok hazır araç ham erişimi soyutlar.

## Pratik teknikler

- Ham birim tutamacı açıp cluster'ları oku:

<details>
<summary>Genişletmek için tıklayın</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
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

- Ham birimden belirli dosyaları kurtarmak için NTFS uyumlu bir araç kullanın:
- RawCopy/RawCopy64 (kullanımdaki dosyaların sektör düzeyinde kopyası)
- FTK Imager or The Sleuth Kit (salt okunur imaj oluşturma, sonra dosyaları carve etme)
- vssadmin/diskshadow + shadow copy, ardından hedef dosyayı snapshot'tan kopyalayın (VSS oluşturabiliyorsanız; genellikle admin gerektirir ama SeManageVolumePrivilege'e sahip aynı operatörlerde yaygın olarak mevcuttur)

Hedeflenecek tipik hassas yollar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Enterprise CA’nın makine anahtar deposundan private key’i okuyabiliyorsanız, rastgele principal’lar için client‑auth sertifikaları oluşturabilir ve PKINIT/Schannel üzerinden kimlik doğrulayabilirsiniz. Bu genellikle Golden Certificate olarak anılır. Bakınız:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) atamasını yalnızca güvenilen adminlerle sıkı şekilde sınırlayın.
- Sensitive Privilege Use’u ve \\.\C:, \\.\PhysicalDrive0 gibi aygıt nesnelerine yönelik process handle open’larını izleyin.
- HSM/TPM-backed CA anahtarları veya DPAPI-NG tercih edin; böylece ham dosya okumaları anahtar materyalini kullanılabilir biçimde geri kazanamaz.
- Yükleme, temp ve extraction yollarını yürütülebilir olmayan ve ayrı konumlarda tutun (genellikle bu zincirle ilişkili web bağlamlı savunma, post‑exploitation aşamasında eşleştirilir).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
