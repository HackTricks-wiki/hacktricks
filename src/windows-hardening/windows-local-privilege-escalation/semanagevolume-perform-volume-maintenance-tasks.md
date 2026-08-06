# SeManageVolumePrivilege: Raw pristup volumenu za proizvoljno čitanje datoteka

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Korisničko pravo u Windowsu: Obavljanje zadataka održavanja volumena (konstanta: SeManageVolumePrivilege).

Nosioci ovog prava mogu da obavljaju operacije niskog nivoa nad volumenima, kao što su defragmentacija, kreiranje/uklanjanje volumena i maintenance IO. Za napadače je od ključne važnosti to što ovo pravo omogućava otvaranje raw handles uređaja volumena (npr. \\.\C:) i izdavanje direktnih disk I/O operacija koje zaobilaze NTFS ACL-ove datoteka. Uz raw pristup možete kopirati bajtove bilo koje datoteke na volumenu čak i ako je pristup zabranjen putem DACL-a, analiziranjem struktura filesystema offline ili korišćenjem alata koji čitaju podatke na nivou blokova/klastera.

Podrazumevano: Administratori na serverima i domain controllerima.<sup>[[1]](#references)</sup>

## Scenariji zloupotrebe

- Proizvoljno čitanje datoteka zaobilaženjem ACL-ova čitanjem disk uređaja (npr. eksfiltracija osetljivog materijala zaštićenog sistemom, kao što su privatni ključevi računara u %ProgramData%\Microsoft\Crypto\RSA\MachineKeys i %ProgramData%\Microsoft\Crypto\Keys, registry hive-ovi, DPAPI masterkeys, SAM, ntds.dit putem VSS-a itd.).
- Zaobilaženje zaključanih/privilegovanih putanja (C:\Windows\System32\…) direktnim kopiranjem bajtova sa raw uređaja.
- U AD CS okruženjima, eksfiltracija materijala ključa CA-a (machine key store) radi kreiranja “Golden Certificates” i impersonacije bilo kog domain principal-a putem PKINIT-a. Pogledajte link ispod.<sup>[[2]](#references)</sup>

Napomena: I dalje vam je potreban parser za NTFS strukture, osim ako se oslanjate na pomoćne alate. Mnogi gotovi alati apstrahuju raw pristup.

## Praktične tehnike

- Otvorite raw handle volumena i čitajte klastere:

<details>
<summary>Kliknite za proširivanje</summary>
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

- Koristite alat sa podrškom za NTFS da biste oporavili određene datoteke iz raw volumena:
- RawCopy/RawCopy64 (kopiranje datoteka koje su u upotrebi na nivou sektora)
- FTK Imager ili The Sleuth Kit (imaging samo za čitanje, a zatim carving datoteka)
- vssadmin/diskshadow + shadow copy, a zatim kopirajte ciljnu datoteku iz snapshot-a (ako možete da kreirate VSS; često zahteva admin privilegije, ali je obično dostupno istim operatorima koji imaju SeManageVolumePrivilege)

Tipične osetljive putanje koje treba ciljati:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne tajne)
- C:\Windows\NTDS\ntds.dit (domain controllers – putem shadow copy-ja)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA sertifikati/CRL-ovi; privatni ključevi se nalaze u prethodno navedenom machine key store-u)

## AD CS veza: Forging a Golden Certificate

Ako možete da pročitate privatni ključ Enterprise CA iz machine key store-a, možete da kreirate client-auth sertifikate za proizvoljne principals i da se autentifikujete putem PKINIT/Schannel. Ovo se često naziva Golden Certificate.<sup>[[2]](#references)</sup> Pogledajte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Odeljak: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detekcija i hardening

- Strogo ograničite dodelu SeManageVolumePrivilege (Perform volume maintenance tasks) samo pouzdanim administratorima.
- Nadgledajte Sensitive Privilege Use i otvaranje process handle-ova prema device objektima kao što su \\.\C:, \\.\PhysicalDrive0.
- Dajte prednost CA ključevima zaštićenim pomoću HSM/TPM-a ili DPAPI-NG-u, kako raw čitanje datoteka ne bi moglo da povrati materijal ključa u upotrebljivom obliku.
- Održavajte upload, temp i extraction putanje kao neizvršne i međusobno odvojene (web context defense koji se često kombinuje sa ovim chain-om nakon eksploatacije).

## Reference

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
