# SeManageVolumePrivilege: Keyfi dosya okuma için ham birim erişimi

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows kullanıcı hakkı: Birim bakım görevlerini gerçekleştirme (sabit değer: SeManageVolumePrivilege).

Bu hakka sahip kullanıcılar birleştirme, birim oluşturma/kaldırma ve bakım IO'su gibi düşük seviyeli birim işlemlerini gerçekleştirebilir. Saldırganlar açısından kritik nokta, bu hakkın ham birim aygıtı tanıtıcılarının (ör. \\.\C:) açılmasına ve NTFS dosya ACL'lerini atlayan doğrudan disk IO'su gerçekleştirilmesine izin vermesidir. Ham erişim ile, DACL tarafından erişim reddedilmiş olsa bile, dosya sistemi yapılarını çevrimdışı ayrıştırarak veya blok/küme seviyesinde okuma yapan araçlardan yararlanarak birimdeki herhangi bir dosyanın baytlarını kopyalayabilirsiniz.

Varsayılan: Sunucularda ve domain controller'larda Administrators.<sup>[[1]](#references)</sup>

## Kötüye kullanım senaryoları

- Disk aygıtını okuyarak ACL'leri atlayan keyfi dosya okuma (ör. %ProgramData%\Microsoft\Crypto\RSA\MachineKeys ve %ProgramData%\Microsoft\Crypto\Keys altındaki makine özel anahtarları, registry hive'ları, DPAPI masterkey'leri, SAM, VSS aracılığıyla ntds.dit gibi hassas ve sistem tarafından korunan materyalleri exfiltrate etme).
- Baytları doğrudan ham aygıttan kopyalayarak kilitli/ayrıcalıklı yolları (C:\Windows\System32\…) atlama.
- AD CS ortamlarında, “Golden Certificates” üretmek ve PKINIT aracılığıyla herhangi bir domain principal'ını taklit etmek için CA'in anahtar materyalini (makine key store) exfiltrate etme. Aşağıdaki linke bakın.<sup>[[2]](#references)</sup>

Not: Yardımcı araçlara güvenmiyorsanız NTFS yapılarını ayrıştırmak için yine de bir parser'a ihtiyacınız vardır. Piyasadaki birçok araç ham erişimi soyutlar.

## Uygulamalı teknikler

- Ham birim tanıtıcısı açıp kümeleri okuyun:

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

- Raw volume'dan belirli dosyaları kurtarmak için NTFS-aware bir tool kullanın:
- RawCopy/RawCopy64 (kullanımda olan dosyaların sektör seviyesinde kopyalanması)
- FTK Imager veya The Sleuth Kit (salt okunur imaging, ardından dosyaları carve etme)
- vssadmin/diskshadow + shadow copy, ardından hedef dosyayı snapshot'tan kopyalama (VSS oluşturabiliyorsanız; genellikle admin yetkisi gerektirir, ancak SeManageVolumePrivilege yetkisine sahip olan aynı operatörlerde çoğunlukla kullanılabilir)

Hedeflenecek tipik hassas yollar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (yerel secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – shadow copy aracılığıyla)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys yukarıdaki machine key store'da bulunur)

## AD CS bağlantısı: Golden Certificate Forging

Enterprise CA'nın private key'ini machine key store'dan okuyabiliyorsanız, rastgele principals için client-auth certificates forge edebilir ve PKINIT/Schannel üzerinden authenticate olabilirsiniz. Bu genellikle Golden Certificate olarak adlandırılır.<sup>[[2]](#references)</sup> Bkz.:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Bölüm: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection ve hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) atamasını yalnızca güvenilir admin'lerle sınırlayın.
- Sensitive Privilege Use ve \\.\C:, \\.\PhysicalDrive0 gibi device object'lerine yönelik process handle açma işlemlerini izleyin.
- HSM/TPM-backed CA keys veya DPAPI-NG kullanmayı tercih edin; böylece raw file read işlemleri key material'ı kullanılabilir biçimde kurtaramaz.
- Upload, temp ve extraction path'lerini executable olmayan ve birbirinden ayrılmış şekilde tutun (bu chain post-exploitation ile sıklıkla birlikte kullanılan web context defense).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
