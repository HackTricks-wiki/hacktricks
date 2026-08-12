# SeManageVolumePrivilege: Volume-maintenance abuse and raw-access validation

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows kullanıcı hakkı: Perform volume maintenance tasks (sabit değer: SeManageVolumePrivilege).

Bu hak, birimlerin birleştirilmesi ve birim oluşturma veya kaldırma gibi volume-maintenance işlemlerine izin verir. Microsoft, bu hakkın sahibinin dosyaları başka veriler içeren depolama alanına genişletebilmesinin ve ardından elde edilen baytları okuyup değiştirebilmesinin mümkün olabileceği konusunda uyarır.<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` sahipliğini garantili raw-disk access ile eşdeğer görmeyin. Microsoft, doğrudan erişim için `CreateFile` aracılığıyla fiziksel bir disk veya volume açmanın administrative privileges gerektirdiğini ve normal object/device access kontrollerinin hâlâ geçerli olduğunu belirtir. Belirli bir build veya üründe, arbitrary file read iddiasında bulunmadan önce token, device ACL, istenen access, share flags ve volume state unsurlarının raw handle alınmasına izin verip vermediğini test edin.<sup>[[3]](#references)</sup>

Varsayılan: Sunucularda ve domain controller'larda Administrators.<sup>[[1]](#references)</sup>

## Abuse scenarios

- Hesap gerçekten okunabilir bir raw-volume handle elde edebiliyorsa, NTFS-aware bir parser per-file ACL'lerini bypass edebilir ve allocated cluster'lardan korunan veya locked file'ları kurtarabilir.
- Olası hedefler arasında `C:\Windows\System32` altındaki locked veya ACL-protected content, registry hive'ları, DPAPI master key'leri, SAM ve ayrı olarak bir snapshot veya offline volume üzerinden erişilebildiğinde `ntds.dit` bulunur.
- Certificate services host'larında kullanışlı software-key konumları arasında `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` ve `%ProgramData%\Microsoft\Crypto\Keys` bulunur; bir file'ı kurtarmak yalnızca key material exportable olduğunda ve ayrıca decrypt edilebildiğinde işe yarar.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Bir AD CS host'unda başarıyla kurtarılan **exportable/software-backed** CA private key, Golden Certificate abuse işlemini mümkün kılabilir. Hardware-backed veya non-exportable key tasarımları bu yolu değiştirir.<sup>[[2]](#references)</sup>

Not: Helper tools kullanmıyorsanız NTFS structures için yine de bir parser gerekir. Piyasada bulunan birçok tool raw access işlemini soyutlar.

## Practical techniques

- Raw volume handle açın ve cluster'ları okuyun:

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

- Raw volume'dan belirli dosyaları kurtarmak için NTFS-aware bir tool kullanın:
- RawCopy/RawCopy64 (kullanımda olan dosyaların sector-level kopyalanması)
- FTK Imager veya The Sleuth Kit (salt okunur imaging, ardından dosyaları carve etme)
- vssadmin/diskshadow + shadow copy, ardından hedef dosyayı snapshot'tan kopyalama (VSS oluşturabiliyorsanız; genellikle admin yetkisi gerektirir, ancak SeManageVolumePrivilege sahibi aynı operatörler tarafından çoğunlukla kullanılabilir)

Hedeflenebilecek tipik hassas yollar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (yerel secret'lar)
- C:\Windows\NTDS\ntds.dit (domain controller'lar – shadow copy üzerinden)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificate/CRL'leri; private key'ler yukarıdaki machine key store'da bulunur)

## AD CS bağlantısı: Golden Certificate Forging

Enterprise CA'nın private key'ini machine key store'dan okuyabiliyorsanız, keyfi principal'lar için client-auth certificate'ları forge edebilir ve PKINIT/Schannel üzerinden authenticate olabilirsiniz. Bu genellikle Golden Certificate olarak adlandırılır.<sup>[[2]](#references)</sup> Bkz.:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Bölüm: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection ve hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) atamasını yalnızca güvenilir admin'lerle sınırlayın.
- Sensitive Privilege Use'ı ve \\.\C:, \\.\PhysicalDrive0 gibi device object'lerine yönelik process handle açma işlemlerini monitor edin.
- Kopyalanmış bir key-container dosyasının kullanılabilir private-key materyalini kurtarmak için yeterli olmaması amacıyla, düzgün yapılandırılmış HSM- veya TPM-backed, export edilemeyen CA key'lerini tercih edin.
- CA-key path'i dışındaki application secret'ları için DPAPI veya DPAPI-NG, kopyalanmış bir data file'ını user, machine, group veya başka bir authorized principal'a koruyarak yetersiz hâle getirebilir. Bu, compromised principal tarafından hâlihazırda erişilebilen plaintext'i korumaz.<sup>[[4]](#references)</sup>
- Upload, temp ve extraction path'lerini executable olmayan ve birbirinden ayrılmış şekilde tutun (bu chain post‑exploitation ile sıklıkla birlikte kullanılan web context defense).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
