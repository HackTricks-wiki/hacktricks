# SeManageVolumePrivilege: Herhangi bir dosyanın okunması için ham hacim erişimi

{{#include ../../banners/hacktricks-training.md}}

## Genel bakış

Windows kullanıcı hakkı: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Sahipleri defragmentasyon, hacim oluşturma/kaldırma ve bakım IO'su gibi düşük seviyeli hacim işlemlerini gerçekleştirebilir. Saldırganlar açısından kritik olarak, bu hak ham hacim aygıt tutacaklarını (örn. \\.\C:) açmaya ve NTFS file ACL'lerini atlayan doğrudan disk I/O yapmaya izin verir. Ham erişimle, dosya sisteminin yapılarının çevrimdışı ayrıştırılması veya blok/küme düzeyinde okuyan araçlardan yararlanılarak DACL tarafından reddedilse bile hacimdeki herhangi bir dosyanın byte'larını kopyalayabilirsiniz.

Varsayılan: sunucularda ve domain denetleyicilerinde Administrators.

## Kötüye kullanım senaryoları

- Disk aygıtını okuyarak ACL'leri atlayıp herhangi bir dosyayı okuma (örn. %ProgramData%\Microsoft\Crypto\RSA\MachineKeys ve %ProgramData%\Microsoft\Crypto\Keys altındaki makine özel anahtarları, kayıt defteri hive'ları, DPAPI masterkey'leri, SAM, ntds.dit (VSS ile) gibi hassas sistem korumalı materyalleri dışarı aktarmak).
- Kilitlenmiş/ayrıcalıklı yolları (C:\Windows\System32\…) ham aygıttan doğrudan byte kopyalayarak atlamak.
- AD CS ortamlarında, CA'nın anahtar materyalini (makine anahtar deposu) dışarı aktararak “Golden Certificates” oluşturmak ve PKINIT ile herhangi bir domain principal'i taklit etmek. Aşağıdaki linke bakın.

Not: Yardımcı araçlara güvenmiyorsanız NTFS yapıları için hâlâ bir parser gerekir. Birçok hazır araç ham erişimi soyutlar.

## Pratik teknikler

- Ham bir hacim tutamacı açıp kümeleri okuyun:

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

- Ham hacimden belirli dosyaları kurtarmak için NTFS destekli bir araç kullanın:
- RawCopy/RawCopy64 (kullanımdaki dosyaların sektör düzeyinde kopyası)
- FTK Imager or The Sleuth Kit (yalnızca-okunur imaj alma, sonra dosyaları carve etme)
- vssadmin/diskshadow + shadow copy, sonra hedef dosyayı snapshot'tan kopyalayın (VSS oluşturabiliyorsanız; genellikle admin gerektirir ama SeManageVolumePrivilege'e sahip operatörlerde yaygındır)

Hedeflenebilecek tipik hassas yollar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (yerel gizli veriler)
- C:\Windows\NTDS\ntds.dit (domain controller'lar – shadow copy üzerinden)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA sertifikaları/CRL'ler; özel anahtarlar yukarıdaki machine key store'da bulunur)

## AD CS bağlantısı: Forging a Golden Certificate

Enterprise CA'nın machine key store'undan private key'i okuyabiliyorsanız, rastgele prensipaller için client‑auth sertifikaları oluşturabilir ve PKINIT/Schannel ile kimlik doğrulayabilirsiniz. Bu genellikle Golden Certificate olarak adlandırılır. Bakınız:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Bölüm: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Tespit ve güçlendirme

- SeManageVolumePrivilege (Perform volume maintenance tasks) atamalarını yalnızca güvenilen adminlerle ciddi şekilde sınırlayın.
- Sensitive Privilege Use'u ve \\.\C:, \\.\PhysicalDrive0 gibi device object'lere açılan process handle'larını izleyin.
- HSM/TPM destekli CA anahtarlarını veya DPAPI-NG kullanmayı tercih edin, böylece ham dosya okumaları anahtar materyalini kullanılabilir formda geri kazanamaz.
- Upload, temp ve extraction yollarını çalıştırılabilir olmayan ve ayrı dizinler olarak tutun (web bağlamında sıkça bu zincirle eşleşen bir savunmadır).

## Kaynaklar

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
