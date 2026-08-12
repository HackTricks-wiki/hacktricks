# SeManageVolumePrivilege: Misbruik van volume-onderhoud en validasie van raw access

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows-gebruikersreg: Perform volume maintenance tasks (konstante: SeManageVolumePrivilege).

Die reg magtig volume-onderhoudsbedrywighede soos defragmentasie en die skep of verwydering van volumes. Microsoft waarsku dat ’n houer moontlik lêers kan uitbrei na stoorspasie wat ander data bevat en dan die verkreë grepe kan lees of wysig.<sup>[[1]](#references)</sup>

Moenie die besit van `SeManageVolumePrivilege` gelykstel aan gewaarborgde raw-disk access nie. Microsoft dokumenteer dat die opening van ’n fisiese skyf of volume deur `CreateFile` vir direkte toegang administratiewe privileges vereis, en dat normale object/device access checks steeds van toepassing is. Toets op ’n spesifieke build of produk of die token, device ACL, aangevraagde access, share flags en volume state ’n raw handle toelaat voordat jy arbitrêre lêerlees verklaar.<sup>[[3]](#references)</sup>

Verstek: Administrators op servers en domain controllers.<sup>[[1]](#references)</sup>

## Misbruikscenario’s

- Indien die rekening werklik ’n leesbare raw-volume handle kan verkry, kan ’n NTFS-aware parser per-file ACLs omseil en beskermde of geslote lêers uit geallokeerde clusters herwin.
- Moontlike teikens sluit geslote of ACL-beskermde inhoud onder `C:\Windows\System32`, registry hives, DPAPI master keys, die SAM, en—waar dit afsonderlik deur ’n snapshot of offline volume toeganklik is—`ntds.dit` in.
- Op certificate services-hosts sluit nuttige software-key-liggings `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` en `%ProgramData%\Microsoft\Crypto\Keys` in; die herwinning van ’n lêer is slegs nuttig wanneer die key material exportable is en ook decrypted kan word.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Op ’n AD CS-host kan ’n suksesvol herwonne **exportable/software-backed** CA private key Golden Certificate abuse moontlik maak. Hardware-backed of non-exportable key designs verander hierdie pad.<sup>[[2]](#references)</sup>

Nota: Jy benodig steeds ’n parser vir NTFS structures, tensy jy op helper tools staatmaak. Baie off-the-shelf tools abstraheer die raw access.

## Praktiese tegnieke

- Open ’n raw volume handle en lees clusters:

<details>
<summary>Klik om uit te vou</summary>
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

- Gebruik 'n NTFS-bewuste tool om spesifieke lêers vanaf die rou volume te herstel:
- RawCopy/RawCopy64 (sektorvlak-kopiëring van lêers wat tans gebruik word)
- FTK Imager of The Sleuth Kit (leesalleen-imaging, waarna lêers gecarve kan word)
- vssadmin/diskshadow + shadow copy, en kopieer dan die teikenlêer vanaf die snapshot (indien jy VSS kan skep; dit vereis dikwels admin-toegang, maar is algemeen beskikbaar vir dieselfde operators wat SeManageVolumePrivilege het)

Tipiese sensitiewe paaie om te teiken:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (plaaslike secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA-sertifikate/CRLs; private keys is in die machine key store hierbo)

## AD CS-koppeling: Forging a Golden Certificate

As jy die Enterprise CA se private key uit die machine key store kan lees, kan jy client-auth-sertifikate vir arbitrêre principals forge en via PKINIT/Schannel authenticate. Dit word dikwels 'n Golden Certificate genoem.<sup>[[2]](#references)</sup> Sien:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Afdeling: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection en hardening

- Beperk die toekenning van SeManageVolumePrivilege (Perform volume maintenance tasks) sterk, en ken dit slegs aan trusted admins toe.
- Monitor Sensitive Privilege Use en process handle opens na device objects soos \\.\C:, \\.\PhysicalDrive0.
- Verkies behoorlik gekonfigureerde HSM- of TPM-gesteunde, nie-uitvoerbare CA keys sodat 'n gekopieerde key-container-lêer nie voldoende is om bruikbare private-key-materiaal te herstel nie.
- Vir application secrets buite die CA-key-pad kan DPAPI of DPAPI-NG 'n gekopieerde data-lêer onvoldoende maak deur dit aan 'n user, machine, group of ander gemagtigde principal te beskerm. Dit beskerm nie plaintext wat reeds vir die compromised principal toeganklik is nie.<sup>[[4]](#references)</sup>
- Hou uploads, temp- en extraction-paaie nie-uitvoerbaar en geskei (web context defense wat dikwels saam met hierdie chain post-exploitation gebruik word).

## References

- [1] [Microsoft – Voer volumebyhoudingstake uit (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` fisiese skywe en volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation en DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
