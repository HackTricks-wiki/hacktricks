# SeManageVolumePrivilege: Surowy dostęp do wolumenu w celu dowolnego odczytu plików

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Uprawnienie użytkownika Windows: Wykonywanie zadań konserwacji wolumenu (stała: SeManageVolumePrivilege).

Posiadacze tego prawa mogą wykonywać operacje niskiego poziomu na wolumenach, takie jak defragmentacja, tworzenie/usuwanie wolumenów oraz operacje IO konserwacyjne. Co istotne z punktu widzenia atakującego, to prawo pozwala na otwieranie surowych uchwytów urządzeń woluminów (np. \\.\C:) i wykonywanie bezpośrednich operacji dyskowych, które omijają ACL-e plików NTFS. Mając surowy dostęp, możesz skopiować bajty dowolnego pliku na wolumenie, nawet jeśli dostęp jest odmówiony przez DACL, analizując struktury systemu plików offline lub korzystając z narzędzi czytających na poziomie bloków/klastrów.

Domyślnie: Administrators na serwerach i kontrolerach domeny.

## Scenariusze nadużyć

- Dowolny odczyt plików z obejściem ACL-i poprzez odczyt urządzenia dyskowego (np. exfiltrate wrażliwe, chronione przez system materiały takie jak prywatne klucze maszyny w %ProgramData%\Microsoft\Crypto\RSA\MachineKeys i %ProgramData%\Microsoft\Crypto\Keys, hivery rejestru, DPAPI masterkeys, SAM, ntds.dit via VSS, itd.).
- Ominięcie zablokowanych/uprzywilejowanych ścieżek (C:\Windows\System32\…) przez kopiowanie bajtów bezpośrednio z surowego urządzenia.
- W środowiskach AD CS, exfiltrate materiał klucza CA (machine key store) w celu wygenerowania “Golden Certificates” i podszycia się pod dowolny principal domeny przez PKINIT. Zobacz link poniżej.

Uwaga: Nadal potrzebujesz parsera struktur NTFS, chyba że polegasz na narzędziach pomocniczych. Wiele gotowych narzędzi abstrakcyjnie udostępnia surowy dostęp.

## Praktyczne techniki

- Otwórz surowy uchwyt wolumenu i czytaj klastry:

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

- Użyj narzędzia rozumiejącego NTFS, aby odzyskać konkretne pliki z surowego woluminu:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (tworzenie obrazu tylko do odczytu, następnie odzyskiwanie plików metodą carvingu)
- vssadmin/diskshadow + shadow copy, następnie skopiuj docelowy plik ze snapshotu (jeśli możesz utworzyć VSS; często wymaga uprawnień administratora, ale zwykle dostępne dla tych samych operatorów, którzy mają SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Powiązanie z AD CS: Forging a Golden Certificate

Jeśli możesz odczytać prywatny klucz Enterprise CA z machine key store, możesz sfałszować certyfikaty client‑auth dla dowolnych podmiotów i uwierzytelnić się przez PKINIT/Schannel. To często nazywane jest Golden Certificate. Zobacz:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sekcja: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Wykrywanie i utwardzanie

- Silnie ogranicz przydzielanie SeManageVolumePrivilege (Perform volume maintenance tasks) tylko do zaufanych administratorów.
- Monitoruj Sensitive Privilege Use oraz otwarcia uchwytów procesów do obiektów urządzeń takich jak \\.\C:, \\.\PhysicalDrive0.
- Preferuj klucze CA zabezpieczone HSM/TPM lub DPAPI-NG, tak aby surowe odczyty plików nie mogły odzyskać materiału klucza w używalnej formie.
- Trzymaj ścieżki uploadów, temp i ekstrakcji jako nie‑wykonywalne i oddzielone (obrona w kontekście web, która często towarzyszy temu łańcuchowi post‑exploitation).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
