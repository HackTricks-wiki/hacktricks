# SeManageVolumePrivilege: nadużycie obsługi woluminów i walidacja dostępu raw

{{#include ../../banners/hacktricks-training.md}}

## Overview

Prawo użytkownika Windows: wykonywanie zadań związanych z obsługą woluminów (stała: SeManageVolumePrivilege).

To prawo zezwala na operacje związane z obsługą woluminów, takie jak defragmentacja oraz tworzenie lub usuwanie woluminów. Microsoft ostrzega, że posiadacz tego prawa może być w stanie rozszerzać pliki na obszar pamięci zawierający inne dane, a następnie odczytywać lub modyfikować uzyskane bajty.<sup>[[1]](#references)</sup>

Nie należy utożsamiać posiadania `SeManageVolumePrivilege` z gwarantowanym dostępem do raw-disk. Microsoft dokumentuje, że otwarcie dysku fizycznego lub woluminu przez `CreateFile` w celu uzyskania bezpośredniego dostępu wymaga uprawnień administratora, a standardowe kontrole dostępu do obiektów/urządzeń nadal mają zastosowanie. W przypadku konkretnego builda lub produktu należy sprawdzić, czy token, ACL urządzenia, żądany dostęp, flagi udostępniania oraz stan woluminu umożliwiają uzyskanie raw handle, zanim ogłosi się możliwość dowolnego odczytu plików.<sup>[[3]](#references)</sup>

Domyślnie: Administrators na serwerach i kontrolerach domeny.<sup>[[1]](#references)</sup>

## Abuse scenarios

- Jeśli konto może faktycznie uzyskać czytelny raw-volume handle, parser obsługujący NTFS może ominąć ACL poszczególnych plików i odzyskać chronione lub zablokowane pliki z przydzielonych klastrów.
- Możliwe cele obejmują zablokowaną zawartość lub zawartość chronioną przez ACL w `C:\Windows\System32`, registry hives, klucze główne DPAPI, SAM oraz — gdy są dostępne osobno przez snapshot lub offline volume — `ntds.dit`.
- Na hostach certificate services przydatne lokalizacje software-key obejmują `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` i `%ProgramData%\Microsoft\Crypto\Keys`; odzyskanie pliku jest przydatne tylko wtedy, gdy jego key material jest exportable i może również zostać odszyfrowany.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Na hoście AD CS pomyślnie odzyskany **exportable/software-backed** CA private key może umożliwić nadużycie Golden Certificate. Konstrukcje kluczy hardware-backed lub non-exportable zmieniają tę ścieżkę.<sup>[[2]](#references)</sup>

Uwaga: nadal potrzebny jest parser struktur NTFS, chyba że korzystasz z helper tools. Wiele gotowych narzędzi abstrahuje raw access.

## Practical techniques

- Otwórz raw volume handle i odczytaj klastry:

<details>
<summary>Kliknij, aby rozwinąć</summary>
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

- Użyj narzędzia obsługującego NTFS, aby odzyskać określone pliki z surowego woluminu:
- RawCopy/RawCopy64 (kopiowanie plików używanych przez system na poziomie sektorów)
- FTK Imager lub The Sleuth Kit (obrazowanie tylko do odczytu, a następnie carving plików)
- vssadmin/diskshadow + shadow copy, a następnie skopiuj docelowy plik z migawki (jeśli możesz utworzyć VSS; często wymaga to uprawnień administratora, ale są one zazwyczaj dostępne dla tych samych operatorów, którzy posiadają SeManageVolumePrivilege)

Typowe wrażliwe ścieżki do sprawdzenia:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne sekrety)
- C:\Windows\NTDS\ntds.dit (kontrolery domeny – za pośrednictwem shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certyfikaty/CRL urzędu certyfikacji; klucze prywatne znajdują się w opisanym powyżej magazynie kluczy komputera)

## Powiązanie z AD CS: Forging a Golden Certificate

Jeśli możesz odczytać klucz prywatny Enterprise CA z magazynu kluczy komputera, możesz podrobić certyfikaty client-auth dla dowolnych podmiotów i uwierzytelniać się za pośrednictwem PKINIT/Schannel. Jest to często określane jako Golden Certificate.<sup>[[2]](#references)</sup> Zobacz:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sekcja: „Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Wykrywanie i hardening

- Ściśle ogranicz przypisywanie SeManageVolumePrivilege (Perform volume maintenance tasks) wyłącznie do zaufanych administratorów.
- Monitoruj Sensitive Privilege Use oraz otwieranie uchwytów procesów do obiektów urządzeń, takich jak \\.\C:, \\.\PhysicalDrive0.
- Preferuj prawidłowo skonfigurowane, oparte na HSM lub TPM, nieeksportowalne klucze CA, aby skopiowanie pliku kontenera klucza nie wystarczało do odzyskania użytecznego materiału klucza prywatnego.
- W przypadku sekretów aplikacji znajdujących się poza ścieżką klucza CA, DPAPI lub DPAPI-NG może sprawić, że skopiowany plik danych będzie niewystarczający, ponieważ chroni go za pomocą użytkownika, komputera, grupy lub innego autoryzowanego podmiotu. Nie chroni to tekstu jawnego, który jest już dostępny dla przejętego podmiotu.<sup>[[4]](#references)</sup>
- Utrzymuj ścieżki przesyłania, plików tymczasowych i ekstrakcji jako niewykonywalne oraz odseparowane (ochrona kontekstu web, która często uzupełnia ten łańcuch post-exploitation).

## References

- [1] [Microsoft – Wykonywanie zadań konserwacji woluminów (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege użyte do odczytu klucza CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
