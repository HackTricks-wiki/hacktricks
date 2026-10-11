# SeManageVolumePrivilege: Misbruik van volumeb onderhoud en validering van rou toegang

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows-gebruikersreg: Voer volumeb onderhoudstake uit (konstante: SeManageVolumePrivilege).

Hierdie reg magtig volumeb onderhoudswerksaamhede soos defragmentering en die skep of verwydering van volumes. Microsoft waarsku dat ’n houer moontlik lêers kan uitbrei na berging wat ander data bevat en dan die verkrygde grepe kan lees of wysig.<sup>[[1]](#references)</sup>

Moenie die besit van `SeManageVolumePrivilege` gelykstel aan gewaarborgde toegang tot rou skywe nie. Microsoft dokumenteer dat administratiewe voorregte nodig is om ’n fisiese skyf of volume deur `CreateFile` vir direkte toegang oop te maak, en dat normale toegangsbeheer op objekte/toestelle steeds geld. Toets op ’n spesifieke bouweergawe of produk of die token, toestel-ACL, aangevraagde toegang, deelvlae en volumetoestand ’n rou hanteerder toelaat voordat jy beweer dat enige lêer gelees kan word.<sup>[[3]](#references)</sup>

Verstek: Administrateurs op bedieners en domeinbeheerders.<sup>[[1]](#references)</sup>

## Misbruikscenario’s

- As die rekening werklik ’n leesbare rou-volumel hanterer kan verkry, kan ’n NTFS-bewuste ontleder lêer-ACL’s omseil en beskermde of geslote lêers uit toegewysde clusters herwin.
- Moontlike teikens sluit geslote of ACL-beskermde inhoud onder `C:\Windows\System32`, registerkorwe, DPAPI-meestersleutels, die SAM in, en—waar dit afsonderlik via ’n momentopname of vanlyn volume toeganklik is—`ntds.dit`.
- Op sertifikaatdienstegashere sluit nuttige liggings vir sagtewaresleutels `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` en `%ProgramData%\Microsoft\Crypto\Keys` in; die herwinning van ’n lêer is slegs nuttig wanneer die sleuteldata uitvoerbaar is en ook gedekripteer kan word.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Op ’n AD CS-gasheer kan ’n suksesvol herwonne **uitvoerbare/sagteware-gesteunde** CA-privésleutel misbruik van Golden Certificate moontlik maak. Hardeware-gesteunde of nie-uitvoerbare sleutelontwerpe verander hierdie roete.<sup>[[2]](#references)</sup>
- Sommige volumeb onderhoudnutsgoed gebruik `FSCTL_SD_GLOBAL_CHANGE` om lêerstelsel-ACL-inskrywings te vervang wanneer daardie bewerking toegelaat word. Dit verander toegangsbeheer eerder as om rou blokke passief te lees, kan ’n groot deel van ’n volume raak, en moet aan die hand van die werklike token- en toestelgedrag gevalideer word. Die [toolbron](https://github.com/CsEnox/SeManageVolumeExploit) wys hierdie spesifieke meganisme; die besit van die voorreg alleen bewys nie dat dit sal slaag nie.
- Om lêertoegang deur ACL-veranderinge te verkry, dekripteer nie ’n EFS-geënkripteerde lêer nie. Om steeds gewone teks te verkry, is ’n ooreenstemmende gebruiker- of herstelprivésleutel nodig. Net so hang die uitvoer van ’n sagteware-gesteunde CA-sleutel met [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) daarvan af dat die sleutel plaaslik beskikbaar, uitvoerbaar en toeganklik is.

Let wel: Jy het steeds ’n ontleder vir NTFS-strukture nodig, tensy jy hulpgereedskap gebruik. Baie klaargemaakte nutsgoed hanteer die rou toegang namens jou.

## Praktiese tegnieke

- Maak ’n rou volume-hanteerder oop en lees clusters:

<details>
<summary>Klik om uit te brei</summary>

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

- Gebruik ’n NTFS-aware hulpmiddel om spesifieke lêers vanaf ’n rou volume te herwin:
  - RawCopy/RawCopy64 (sektorvlak-kopie van lêers wat in gebruik is)
  - FTK Imager of The Sleuth Kit (leesalleen-beeldskepping, gevolg deur lêerherwinning)
  - vssadmin/diskshadow + skadukopie, en kopieer dan die teikenlêer vanaf die momentopname (as jy VSS kan skep; vereis dikwels admin-regte, maar is algemeen beskikbaar vir dieselfde operateurs wat SeManageVolumePrivilege het)

Tipiese sensitiewe paaie om te teiken:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (plaaslike geheime)
- C:\Windows\NTDS\ntds.dit (domeinbeheerders – via skadukopie)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA-sertifikate/CRL’s; private sleutels is in die masjiensleutelstoor hierbo)

## AD CS-koppeling: Forging a Golden Certificate

As jy die Enterprise CA se private sleutel uit die masjiensleutelstoor kan lees, kan jy kliëntverifikasiesertifikate vir arbitrêre principals vervals en via PKINIT/Schannel verifieer. Daar word dikwels na dit verwys as ’n Golden Certificate.<sup>[[2]](#references)</sup> Sien:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Afdeling: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Opsporing en verharding

- Beperk die toekenning van SeManageVolumePrivilege (Perform volume maintenance tasks) sterk; ken dit slegs aan vertroude admins toe.
- Monitor Sensitive Privilege Use en proses-handle-openings na toestelobjekte soos \\.\C:, \\.\PhysicalDrive0.
- Verkies behoorlik gekonfigureerde HSM- of TPM-gesteunde, nie-uitvoerbare CA-sleutels, sodat ’n gekopieerde sleutelhouerlêer nie genoeg is om bruikbare private-sleutelmateriaal te herwin nie.
- Vir programgeheime buite die CA-sleutelpad kan DPAPI of DPAPI-NG verseker dat ’n gekopieerde datalêer nie voldoende is nie, deur dit aan ’n gebruiker, masjien, groep of ander gemagtigde principal te beskerm. Dit beskerm nie gewone teks wat reeds vir die gekompromitteerde principal toeganklik is nie.<sup>[[4]](#references)</sup>
- Hou oplaai-, tydelike en onttrekkingspaaie nie-uitvoerbaar en apart (’n verdediging op webkonteksvlak wat dikwels met hierdie post-exploitation-ketting gepaardgaan).

## References

- [1] [Microsoft – Voer volum in standhoudingstake uit (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege gebruik om CA-sleutel te lees → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` fisiese skywe en volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
