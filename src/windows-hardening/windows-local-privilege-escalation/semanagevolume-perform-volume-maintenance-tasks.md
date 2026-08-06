# SeManageVolumePrivilege: Dostęp do surowego woluminu umożliwiający odczyt dowolnych plików

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Uprawnienie użytkownika systemu Windows: Perform volume maintenance tasks (stała: SeManageVolumePrivilege).

Posiadacze tego uprawnienia mogą wykonywać niskopoziomowe operacje na woluminach, takie jak defragmentacja, tworzenie/usuwanie woluminów oraz operacje konserwacyjne IO. Co najważniejsze dla attackerów, uprawnienie to umożliwia otwieranie uchwytów surowych urządzeń woluminów (np. \\.\C:) i wykonywanie bezpośrednich operacji we/wy dysku z pominięciem ACL plików NTFS. Dzięki dostępowi surowemu można kopiować bajty dowolnego pliku z woluminu, nawet jeśli dostęp do niego jest blokowany przez DACL, poprzez analizowanie struktur systemu plików offline lub użycie narzędzi odczytujących dane na poziomie bloków/klastrów.

Domyślnie: Administratorzy na serwerach i kontrolerach domeny.<sup>[[1]](#references)</sup>

## Scenariusze nadużycia

- Dowolny odczyt plików z pominięciem ACL poprzez odczyt urządzenia dyskowego (np. eksfiltracja poufnych materiałów chronionych przez system, takich jak prywatne klucze maszynowe w %ProgramData%\Microsoft\Crypto\RSA\MachineKeys i %ProgramData%\Microsoft\Crypto\Keys, ule rejestru, klucze główne DPAPI, SAM, ntds.dit za pośrednictwem VSS itd.).
- Ominięcie zablokowanych/objętych uprzywilejowanym dostępem ścieżek (C:\Windows\System32\…) poprzez bezpośrednie kopiowanie bajtów z urządzenia surowego.
- W środowiskach AD CS eksfiltracja materiału klucza CA (magazyn kluczy maszyny) w celu tworzenia „Golden Certificates” i podszywania się pod dowolną jednostkę domenową za pośrednictwem PKINIT. Zobacz poniższy link.<sup>[[2]](#references)</sup>

Uwaga: Nadal potrzebny jest parser struktur NTFS, chyba że korzystasz z narzędzi pomocniczych. Wiele gotowych narzędzi ukrywa szczegóły dostępu surowego.

## Praktyczne techniki

- Otwórz uchwyt surowego woluminu i odczytaj klastry:

<details>
<summary>Kliknij, aby rozwinąć</summary>
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

- Use an NTFS-aware tool to recover specific files from raw volume:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Typowe wrażliwe ścieżki do sprawdzenia:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne sekrety)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Powiązanie AD CS: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client-auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate.<sup>[[2]](#references)</sup> See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Wykrywanie i hardening

- Strongly limit assignment of SeManageVolumePrivilege (Perform volume maintenance tasks) to only trusted admins.
- Monitor Sensitive Privilege Use and process handle opens to device objects like \\.\C:, \\.\PhysicalDrive0.
- Prefer HSM/TPM-backed CA keys or DPAPI-NG so that raw file reads cannot recover key material in usable form.
- Keep uploads, temp, and extraction paths non-executable and separated (web context defense that often pairs with this chain post-exploitation).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
