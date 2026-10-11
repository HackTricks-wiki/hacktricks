# SeManageVolumePrivilege: zloupotreba održavanja volumena i provera sirovog pristupa

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Korisničko pravo u Windows-u: Obavljanje zadataka održavanja volumena (konstanta: SeManageVolumePrivilege).

Ovo pravo ovlašćuje operacije održavanja volumena, kao što su defragmentacija i kreiranje ili uklanjanje volumena. Microsoft upozorava da korisnik koji ima ovo pravo možda može da proširi datoteke tako da obuhvate skladišni prostor koji sadrži druge podatke, a zatim da pročita ili izmeni preuzete bajtove.<sup>[[1]](#references)</sup>

Nemojte izjednačavati posedovanje prava `SeManageVolumePrivilege` sa garantovanim sirovim pristupom disku. Microsoft navodi da je za otvaranje fizičkog diska ili volumena preko `CreateFile` radi direktnog pristupa potrebna administratorska privilegija, a i dalje važe uobičajene provere pristupa objektima/uređajima. Na konkretnoj verziji ili proizvodu proverite da li token, ACL uređaja, zatraženi pristup, zastavice deljenja i stanje volumena dozvoljavaju sirovu ručicu pre nego što tvrdite da je moguće čitati proizvoljne datoteke.<sup>[[3]](#references)</sup>

Podrazumevano: Administratori na serverima i kontrolerima domena.<sup>[[1]](#references)</sup>

## Scenariji zloupotrebe

- Ako nalog zaista može da dobije sirovu ručicu volumena sa dozvolom za čitanje, parser koji poznaje NTFS može da zaobiđe ACL-ove pojedinačnih datoteka i povrati zaštićene ili zaključane datoteke iz alociranih klastera.
- Potencijalne mete obuhvataju zaključan ili ACL-om zaštićen sadržaj u `C:\Windows\System32`, registry hive-ove, DPAPI master ključeve, SAM i — ako im se može zasebno pristupiti preko snapshot-a ili offline volumena — `ntds.dit`.
- Na hostovima sa certificate services, korisne lokacije softverskih ključeva obuhvataju `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` i `%ProgramData%\Microsoft\Crypto\Keys`; povraćena datoteka je korisna samo ako se njen ključni materijal može izvesti i dešifrovati.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Na AD CS hostu, uspešno povraćen privatni CA ključ koji je **moguće izvesti i zasnovan je na softveru** može da omogući zloupotrebu Golden Certificate. Rešenja sa hardverskim ključem ili ključem koji se ne može izvesti menjaju ovaj put.<sup>[[2]](#references)</sup>
- Neki alati za održavanje volumena koriste `FSCTL_SD_GLOBAL_CHANGE` za zamenu ACL unosa u fajl-sistemu, kada je ta operacija dozvoljena. Time se menjaju kontrole pristupa umesto pasivnog čitanja sirovih blokova; može da utiče na veliki deo volumena i mora se proveriti u odnosu na konkretno ponašanje tokena i uređaja. [Izvorni kod alata](https://github.com/CsEnox/SeManageVolumeExploit) prikazuje ovaj konkretan mehanizam; samo posedovanje privilegije ne dokazuje da će uspeti.
- Pristup datotekama dobijen izmenom ACL-ova ne dešifruje datoteku šifrovanu pomoću EFS-a. Za dobijanje otvorenog teksta i dalje je potreban odgovarajući korisnički ili recovery privatni ključ. Isto tako, izvoz softverskog CA ključa pomoću [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) zavisi od toga da li je ključ lokalno dostupan, može da se izveze i dostupan je za pristup.

Napomena: I dalje vam je potreban parser za NTFS strukture, osim ako se oslanjate na pomoćne alate. Mnogi gotovi alati apstrahuju sirovi pristup.

## Praktične tehnike

- Otvorite sirovu ručicu volumena i čitajte klastere:

<details>
<summary>Kliknite da biste proširili</summary>

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

- Koristite alat koji podržava NTFS da biste oporavili određene datoteke sa sirovog volumena:
  - RawCopy/RawCopy64 (kopiranje datoteka koje se koriste na nivou sektora)
  - FTK Imager ili The Sleuth Kit (snimanje samo za čitanje, pa zatim izdvajanje datoteka)
  - vssadmin/diskshadow + shadow copy, pa kopirajte ciljnu datoteku iz snimka (ako možete da napravite VSS; često je potrebna admin privilegija, ali ona je obično dostupna istim operatorima koji imaju SeManageVolumePrivilege)

Tipične osetljive putanje koje treba proveriti:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne tajne)
- C:\Windows\NTDS\ntds.dit (kontroleri domena – putem shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA sertifikati/CRL-ovi; privatni ključevi se nalaze u skladištu mašinskih ključeva iznad)

## Veza sa AD CS: falsifikovanje Golden Certificate-a

Ako možete da pročitate privatni ključ Enterprise CA-a iz skladišta mašinskih ključeva, možete da falsifikujete sertifikate za autentifikaciju klijenta za proizvoljne principals i da se autentifikujete putem PKINIT/Schannel. Ovo se često naziva Golden Certificate.<sup>[[2]](#references)</sup> Pogledajte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Odeljak: „Falsifikovanje sertifikata ukradenim CA sertifikatima (Golden Certificate) – DPERSIST1“).

## Detekcija i ojačavanje bezbednosti

- Strogo ograničite dodelu SeManageVolumePrivilege (Perform volume maintenance tasks) samo na administratore od poverenja.
- Nadgledajte Sensitive Privilege Use i otvaranje handle-ova procesa za objekte uređaja kao što su \\.\C:, \\.\PhysicalDrive0.
- Prednost dajte pravilno konfigurisanim CA ključevima koje podržavaju HSM ili TPM i koji se ne mogu izvesti, tako da kopirana datoteka kontejnera ključa nije dovoljna za oporavak upotrebljivog materijala privatnog ključa.
- Za tajne aplikacija koje nisu povezane sa putanjom CA ključa, DPAPI ili DPAPI-NG mogu učiniti kopiranu datoteku sa podacima nedovoljnom tako što je štite za korisnika, mašinu, grupu ili drugi ovlašćeni principal. Ovo ne štiti običan tekst koji je već dostupan kompromitovanom principalu.<sup>[[4]](#references)</sup>
- Održavajte putanje za otpremanje, privremene datoteke i izdvajanje kao neizvršne i odvojene (odbrana u web kontekstu koja se često kombinuje sa ovim lancem post‑exploitation).

## References

- [1] [Microsoft – Zadaci održavanja volumena (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege korišćen za čitanje CA ključa → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` za fizičke diskove i volumene](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation i DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
