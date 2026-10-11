# SeManageVolumePrivilege: Nadużycie zadań konserwacji woluminów i weryfikacja dostępu raw

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Uprawnienie użytkownika systemu Windows: Wykonywanie zadań konserwacji woluminów (stała: SeManageVolumePrivilege).

Uprawnienie to zezwala na operacje konserwacji woluminów, takie jak defragmentacja oraz tworzenie lub usuwanie woluminów. Microsoft ostrzega, że osoba posiadająca to uprawnienie może być w stanie rozszerzać pliki na obszar pamięci zawierający inne dane, a następnie odczytywać lub modyfikować uzyskane bajty.<sup>[[1]](#references)</sup>

Nie należy zakładać, że posiadanie `SeManageVolumePrivilege` gwarantuje dostęp do surowego dysku. Microsoft dokumentuje, że otwarcie dysku fizycznego lub woluminu przez `CreateFile` w celu uzyskania bezpośredniego dostępu wymaga uprawnień administratora, a standardowe kontrole dostępu do obiektów i urządzeń nadal obowiązują. W przypadku konkretnej kompilacji lub produktu sprawdź, czy token, lista ACL urządzenia, żądany dostęp, flagi udostępniania i stan woluminu pozwalają uzyskać uchwyt raw, zanim stwierdzisz, że możliwy jest dowolny odczyt plików.<sup>[[3]](#references)</sup>

Domyślnie: administratorzy na serwerach i kontrolerach domeny.<sup>[[1]](#references)</sup>

## Scenariusze nadużyć

- Jeśli konto rzeczywiście może uzyskać uchwyt raw woluminu z prawem odczytu, parser obsługujący NTFS może ominąć ACL poszczególnych plików i odzyskać chronione lub zablokowane pliki z zaalokowanych klastrów.
- Potencjalne cele obejmują zablokowane lub chronione przez ACL dane w `C:\Windows\System32`, ule rejestru, klucze główne DPAPI, SAM oraz — jeśli są osobno dostępne za pośrednictwem migawki lub woluminu offline — `ntds.dit`.
- Na hostach usług certyfikatów przydatne lokalizacje kluczy programowych to `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` i `%ProgramData%\Microsoft\Crypto\Keys`; odzyskanie pliku jest przydatne tylko wtedy, gdy zawarty w nim materiał klucza można wyeksportować i odszyfrować.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Na hoście AD CS skuteczne odzyskanie **eksportowalnego klucza prywatnego CA opartego na oprogramowaniu** może umożliwić nadużycie Golden Certificate. Projekty wykorzystujące klucze sprzętowe lub nieeksportowalne zmieniają tę ścieżkę.<sup>[[2]](#references)</sup>
- Niektóre narzędzia do konserwacji woluminów używają `FSCTL_SD_GLOBAL_CHANGE` do zastępowania wpisów ACL systemu plików, jeśli ta operacja jest dozwolona. Zmienia to kontrolę dostępu, zamiast pasywnie odczytywać surowe bloki, może wpłynąć na dużą część woluminu i wymaga weryfikacji w odniesieniu do rzeczywistego tokenu i zachowania urządzenia. [Kod źródłowy narzędzia](https://github.com/CsEnox/SeManageVolumeExploit) pokazuje ten konkretny mechanizm; samo posiadanie uprawnienia nie dowodzi, że operacja się powiedzie.
- Uzyskanie dostępu do pliku przez zmianę ACL nie odszyfrowuje pliku zaszyfrowanego EFS. Do uzyskania tekstu jawnego nadal potrzebny jest pasujący klucz prywatny użytkownika lub klucz odzyskiwania. Podobnie eksportowanie klucza CA opartego na oprogramowaniu za pomocą [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) zależy od tego, czy klucz jest lokalnie dostępny, eksportowalny i osiągalny.

Uwaga: Nadal potrzebny jest parser struktur NTFS, chyba że korzystasz z narzędzi pomocniczych. Wiele gotowych narzędzi abstrahuje dostęp raw.

## Praktyczne techniki

- Otwórz uchwyt raw woluminu i odczytaj klastry:

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

- Użyj narzędzia obsługującego NTFS, aby odzyskać konkretne pliki z surowego woluminu:
  - RawCopy/RawCopy64 (kopiowanie plików używanych na poziomie sektorów)
  - FTK Imager lub The Sleuth Kit (obrazowanie tylko do odczytu, a następnie odzyskiwanie plików)
  - vssadmin/diskshadow + kopia w tle, a następnie skopiuj docelowy plik z migawki (jeśli możesz utworzyć VSS; często wymaga to uprawnień administratora, ale są one powszechnie dostępne dla tych samych operatorów, którzy mają SeManageVolumePrivilege)

Typowe ścieżki zawierające wrażliwe dane:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokalne sekrety)
- C:\Windows\NTDS\ntds.dit (kontrolery domeny – przez kopię w tle)
- C:\Windows\System32\CertSrv\CertEnroll\ (certyfikaty/CRL urzędu certyfikacji; klucze prywatne znajdują się w powyższym magazynie kluczy komputera)

## Powiązanie z AD CS: podrabianie Golden Certificate

Jeśli możesz odczytać klucz prywatny Enterprise CA z magazynu kluczy komputera, możesz podrobić certyfikaty uwierzytelniania klienta dla dowolnych podmiotów i uwierzytelniać się za pomocą PKINIT/Schannel. Jest to często określane jako Golden Certificate.<sup>[[2]](#references)</sup> Zobacz:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sekcja: „Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Wykrywanie i zabezpieczenia

- Zdecydowanie ogranicz przydzielanie SeManageVolumePrivilege (Perform volume maintenance tasks) wyłącznie do zaufanych administratorów.
- Monitoruj użycie uprawnień wrażliwych i otwieranie uchwytów procesów do obiektów urządzeń, takich jak \\.\C: i \\.\PhysicalDrive0.
- Preferuj prawidłowo skonfigurowane klucze CA oparte na HSM lub TPM i oznaczone jako nieeksportowalne, aby skopiowanie pliku kontenera klucza nie wystarczało do odzyskania użytecznego materiału klucza prywatnego.
- W przypadku sekretów aplikacji poza ścieżką klucza CA, DPAPI lub DPAPI-NG mogą sprawić, że skopiowany plik danych nie wystarczy, ponieważ chronią go dla użytkownika, komputera, grupy lub innego uprawnionego podmiotu. Nie chroni to tekstu jawnego, do którego skompromitowany podmiot ma już dostęp.<sup>[[4]](#references)</sup>
- Utrzymuj ścieżki przesyłania, plików tymczasowych i ekstrakcji jako niewykonywalne oraz odseparowane (zabezpieczenie kontekstu webowego, które często uzupełnia ten łańcuch działań post-exploitation).

## References

- [1] [Microsoft – Wykonywanie zadań konserwacji woluminu (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege użyte do odczytu klucza CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` dla dysków fizycznych i woluminów](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Interfejs Cryptography API: Next Generation i DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
