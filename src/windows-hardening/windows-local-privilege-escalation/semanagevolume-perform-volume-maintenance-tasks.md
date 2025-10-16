# SeManageVolumePrivilege: Raw pristup volumenu za proizvoljno čitanje datoteka

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows korisničko pravo: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Nositelji mogu da izvršavaju operacije niskog nivoa nad volumenima kao što su defragmentacija, kreiranje/brisanje volumena i održavanje I/O-a. Kritično za napadače, ovo pravo omogućava otvaranje raw volume device handles (npr. \\.\C:) i slanje direktnih disk I/O operacija koje zaobilaze NTFS file ACLs. Sa raw pristupom možete kopirati bajtove bilo kog fajla na volumenu čak i ako je pristup odbijen DACL-om, parsiranjem filesystem struktura offline ili korišćenjem alata koji čitaju na nivou blokova/klastera.

Podrazumevano: članovi Administrators grupe na serverima i domain controller-ima.

## Scenariji zloupotrebe

- Proizvoljno čitanje fajlova zaobilaženjem ACL-ova čitanjem disk uređaja (npr. eksfiltracija osetljivog sistemskog materijala zaštićenog od strane sistema, kao što su machine private keys under %ProgramData%\Microsoft\Crypto\RSA\MachineKeys and %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, itd.).
- Zaobilaženje zaključanih/privilegovanih putanja (C:\Windows\System32\…) kopiranjem bajtova direktno sa raw uređaja.
- U AD CS okruženjima, eksfiltrirajte CA-ov materijal ključeva (machine key store) kako biste izradili “Golden Certificates” i oponašali bilo koji domain principal via PKINIT. Pogledajte link ispod.

Napomena: I dalje vam je potreban parser za NTFS strukture osim ako se ne oslanjate na pomoćne alate. Mnogi gotovi alati apstrahuju raw pristup.

## Praktične tehnike

- Otvorite raw volume handle i čitajte klastere:

<details>
<summary>Kliknite za proširenje</summary>
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

- Koristite NTFS-aware alat za oporavak specifičnih fajlova sa raw volume:
- RawCopy/RawCopy64 (kopija na nivou sektora datoteka koje su u upotrebi)
- FTK Imager or The Sleuth Kit (izrada image kopije samo za čitanje, zatim iskapanje datoteka)
- vssadmin/diskshadow + shadow copy, zatim kopirajte ciljnu datoteku iz snapshot-a (ako možete da kreirate VSS; često zahteva admin privilegije, ali je obično dostupan istim operatorima koji imaju SeManageVolumePrivilege)

Tipične osetljive putanje za ciljanje:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Ako možete da pročitate Enterprise CA’s private key iz machine key store, možete da forgujete client‑auth certificates za proizvoljne principe i autentifikujete se preko PKINIT/Schannel. Ovo se često naziva Golden Certificate. Pogledajte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detekcija i zaštita

- Strogo ograničite dodelu SeManageVolumePrivilege (Perform volume maintenance tasks) samo pouzdanim administratorima.
- Pratite Sensitive Privilege Use i otvaranja handle-a procesa prema device objektima kao što su \\.\C:, \\.\PhysicalDrive0.
- Preferirajte CA ključeve potpomognute HSM/TPM ili DPAPI-NG kako bi čitanje sirovih fajlova ne moglo da povrati ključni materijal u upotrebljivom obliku.
- Držite uploads, temp i extraction putanje neizvršnim i odvojenim (odbrana u web kontekstu koja se često povezuje sa ovim lancem post‑eksploatacije).

## Reference

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
