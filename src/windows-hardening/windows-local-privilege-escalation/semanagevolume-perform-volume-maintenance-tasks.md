# SeManageVolumePrivilege: Dostęp do surowego wolumenu w celu dowolnego odczytu plików

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Uprawnienie użytkownika Windows: Wykonywanie czynności konserwacji wolumenu (constant: SeManageVolumePrivilege).

Posiadacze mogą wykonywać operacje niskopoziomowe na wolumenie, takie jak defragmentacja, tworzenie/usuwanie wolumenów oraz operacje konserwacyjne I/O. Co krytyczne dla atakujących, to uprawnienie pozwala na otwieranie surowych uchwytów urządzeń wolumenu (np. \\.\C:) i wykonywanie bezpośredniego I/O dysku omijającego ACL plików NTFS. Mając surowy dostęp możesz skopiować bajty dowolnego pliku na wolumenie nawet jeśli DACL to zabrania, poprzez parsowanie struktur systemu plików offline lub wykorzystanie narzędzi czytających na poziomie bloków/klastrów.

Domyślnie: Administratorzy na serwerach i kontrolerach domeny.

## Scenariusze nadużyć

- Dowolny odczyt plików omijający ACL poprzez czytanie urządzenia dyskowego (np. wyeksfiltrowanie wrażliwych materiałów chronionych przez system, takich jak klucze prywatne maszyny w %ProgramData%\Microsoft\Crypto\RSA\MachineKeys i %ProgramData%\Microsoft\Crypto\Keys, hive rejestru, DPAPI masterkeys, SAM, ntds.dit przez VSS itp.).
- Ominięcie zablokowanych/uprzywilejowanych ścieżek (C:\Windows\System32\…) przez kopiowanie bajtów bezpośrednio z surowego urządzenia.
- W środowiskach AD CS, wyeksfiltrowanie materiału klucza CA (machine key store) w celu wydania „Golden Certificates” i podszycie się pod dowolny podmiot domenowy za pomocą PKINIT. Zobacz link poniżej.

Uwaga: Nadal potrzebujesz parsera struktur NTFS, chyba że polegasz na narzędziach pomocniczych. Wiele gotowych narzędzi abstrahuje dostęp surowy.

## Praktyczne techniki

- Otworzyć uchwyt surowego wolumenu i czytać klastry:

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

- Użyj narzędzia rozumiejącego NTFS do odzyskania konkretnych plików z surowej partycji:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Typowe wrażliwe ścieżki do zaatakowania:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Powiązanie z AD CS: Forging a Golden Certificate

Jeśli potrafisz odczytać prywatny klucz Enterprise CA z machine key store, możesz sfałszować certyfikaty client‑auth dla dowolnych podmiotów i uwierzytelnić się za pomocą PKINIT/Schannel. Często nazywa się to Golden Certificate. Zobacz:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sekcja: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Wykrywanie i zabezpieczenia

- Ogranicz przydzielanie SeManageVolumePrivilege (Perform volume maintenance tasks) wyłącznie do zaufanych administratorów.
- Monitoruj Sensitive Privilege Use oraz otwarcia uchwytów procesów do obiektów urządzeń takich jak \\.\C:, \\.\PhysicalDrive0.
- Preferuj klucze CA wspierane przez HSM/TPM lub DPAPI-NG, aby surowe odczyty plików nie mogły odzyskać materiału klucza w formie możliwej do użycia.
- Utrzymuj katalogi uploadów, temp i ekstrakcji jako niewykonywalne i odseparowane (obrona w kontekście web, która często łączy się z tym łańcuchem po‑eksploatacji).

## Źródła

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
