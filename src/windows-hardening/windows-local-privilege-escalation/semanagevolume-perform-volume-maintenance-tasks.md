# SeManageVolumePrivilege: zloupotreba održavanja volumena i validacija raw pristupa

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows korisničko pravo: Obavljanje zadataka održavanja volumena (konstanta: SeManageVolumePrivilege).

Ovo pravo odobrava operacije održavanja volumena, kao što su defragmentacija i kreiranje ili uklanjanje volumena. Microsoft upozorava da nosilac ovog prava može biti u mogućnosti da proširi datoteke u prostor za skladištenje koji sadrži druge podatke, a zatim da pročita ili izmeni pribavljene bajtove.<sup>[[1]](#references)</sup>

Nemojte izjednačavati posedovanje `SeManageVolumePrivilege` sa garantovanim raw-disk pristupom. Microsoft navodi da otvaranje fizičkog diska ili volumena preko `CreateFile` za direktan pristup zahteva administratorske privilegije, a uobičajene provere pristupa objektima/uređajima i dalje važe. Na konkretnoj verziji sistema ili proizvodu proverite da li token, ACL uređaja, zatraženi pristup, oznake deljenja i stanje volumena dozvoljavaju raw handle pre nego što tvrdite da je moguće proizvoljno čitanje datoteka.<sup>[[3]](#references)</sup>

Podrazumevano: Administrators na serverima i kontrolerima domena.<sup>[[1]](#references)</sup>

## Scenario zloupotrebe

- Ako nalog zaista može da dobije raw-volume handle sa pravom čitanja, parser koji razume NTFS može zaobići ACL-ove po datotekama i oporaviti zaštićene ili zaključane datoteke iz dodeljenih klastera.
- Moguće mete obuhvataju zaključan ili ACL-om zaštićen sadržaj u okviru `C:\Windows\System32`, registry hive-ove, DPAPI master keys, SAM i — kada je zasebno dostupan putem snapshot-a ili offline volumena — `ntds.dit`.
- Na hostovima sa certificate services, korisne lokacije software-key datoteka obuhvataju `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` i `%ProgramData%\Microsoft\Crypto\Keys`; oporavak datoteke je koristan samo kada je njen ključni materijal exportable i kada se takođe može dešifrovati.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Na AD CS hostu, uspešno oporavljen **exportable/software-backed** CA private key može omogućiti Golden Certificate abuse. Dizajni sa hardware-backed ili non-exportable ključevima menjaju ovaj put.<sup>[[2]](#references)</sup>

Napomena: I dalje vam je potreban parser za NTFS strukture, osim ako se oslanjate na helper tools. Mnogi gotovi alati apstrahuju raw pristup.

## Praktične tehnike

- Otvorite raw volume handle i čitajte klastere:

<details>
<summary>Kliknite da proširite</summary>
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

- Koristite NTFS-aware alat za oporavak određenih datoteka iz raw volumena:
- RawCopy/RawCopy64 (kopiranje datoteka koje se koriste na nivou sektora)
- FTK Imager ili The Sleuth Kit (read-only imaging, a zatim carving datoteka)
- vssadmin/diskshadow + shadow copy, a zatim kopirajte ciljnu datoteku iz snapshot-a (ako možete da kreirate VSS; često je potreban admin, ali je to obično dostupno istim operatorima koji imaju SeManageVolumePrivilege)

Tipične osetljive putanje koje treba ciljati:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne tajne)
- C:\Windows\NTDS\ntds.dit (domain controllers – putem shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certifikati/CRL-ovi; privatni ključevi se nalaze u gore navedenom machine key store-u)

## AD CS veza: Forging a Golden Certificate

Ako možete da pročitate privatni ključ Enterprise CA iz machine key store-a, možete da forge-ujete client-auth certificates za proizvoljne principals i da se autentifikujete putem PKINIT/Schannel. Ovo se često naziva Golden Certificate.<sup>[[2]](#references)</sup> Pogledajte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Odeljak: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detekcija i hardening

- Strogo ograničite dodeljivanje SeManageVolumePrivilege (Perform volume maintenance tasks) samo pouzdanim administratorima.
- Nadgledajte Sensitive Privilege Use i otvaranje process handle-ova prema device objektima kao što su \\.\C:, \\.\PhysicalDrive0.
- Dajte prednost pravilno konfigurisanim HSM- ili TPM-backed, non-exportable CA ključevima, tako da kopirana key-container datoteka nije dovoljna za oporavak upotrebljivog materijala privatnog ključa.
- Za application secrets izvan putanje CA ključa, DPAPI ili DPAPI-NG mogu učiniti kopiranu data datoteku nedovoljnom tako što je štite za korisnika, mašinu, grupu ili drugog ovlašćenog principala. Ovo ne štiti plaintext koji je već dostupan kompromitovanom principalu.<sup>[[4]](#references)</sup>
- Održavajte upload, temp i extraction putanje non-executable i odvojene (web context defense koji se često kombinuje sa ovim chain-om tokom post‑exploitation faze).

## References

- [1] [Microsoft – Obavljanje zadataka održavanja volumena (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege korišćen za čitanje CA ključa → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` fizički diskovi i volumeni](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation i DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
