# Wskaźniki eskalacji przez sesję i usługę dyskową SUSE

{{#include ../../banners/hacktricks-training.md}}

## Autoryzacja sesji SSH za pośrednictwem PAM

CVE-2025-6018 dotyczyła konfiguracji PAM w SUSE 15, w których stos uwierzytelniania SSH ładował `pam_env` przed załadowaniem `pam_systemd` przez stos sesji. Gdy `pam_env` odczytywał plik `.pam_environment` użytkownika, użytkownik mógł podać wartości `XDG_SEAT` i `XDG_VTNR`, które sprawiały, że Polkit traktował sesję SSH jako aktywną fizycznie. Dzięki temu akcja `allow_active=yes` mogła stać się dostępna dla użytkownika zdalnego. Zmienia to autoryzację sesji, ale samo w sobie nie gwarantuje dostępu do roota. SUSE naprawiło domyślne zachowanie dotyczące środowiska użytkownika w `pam` oraz położenie modułu generowane przez `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Sprawdź efektywny łańcuch dołączanych plików `/etc/pam.d/sshd`, kolejność `pam_env.so` i `pam_systemd.so` oraz każdą jawną opcję `user_readenv=1`. Poprawiony pakiet `pam` zmienia ustawienie domyślne, ale jawna opcja nadal może wymuszać odczyt środowiska użytkownika. Nowszy pakiet `pam-config` nie dowodzi, że lokalnie zmodyfikowany lub nieaktualny stos PAM został wygenerowany ponownie. Sprawdź wersję pakietu dostawcy oraz rzeczywistą konfigurację.<sup>[[1]](#references)[[2]](#references)</sup>

## Ścieżka przez usługę dyskową dla aktywnego użytkownika

CVE-2025-6019 była ścieżką eskalacji w `libblockdev`, wykorzystywaną za pośrednictwem `udisks2`: podczas zmiany rozmiaru XFS system plików dostarczony przez atakującego mógł zostać tymczasowo zamontowany bez oczekiwanego ograniczenia `nosuid`. Ta ścieżka wymaga dostępnej usługi UDisks D-Bus, obsługi zmiany rozmiaru XFS, odpowiedniej akcji Polkit dostępnej dla wywołującego oraz podatnej wersji pakietu biblioteki. CVE-2025-6018 to jeden ze sposobów uzyskania sesji aktywnego użytkownika, ale użytkownik, który już ma taką sesję, może niezależnie uzyskać dostęp do ścieżki przez usługę dyskową.<sup>[[3]](#references)</sup>

W ramach pasywnego przeglądu sprawdź metadane usługi UDisks, politykę `org.freedesktop.udisks2.modify-device`, `xfs_growfs` oraz zainstalowany pakiet `libbd_fs2`. SUSE wymienia wersję `libbd_fs2` `2.26-150400.3.5.1` jako naprawioną dla openSUSE Leap 15.6; dokładna naprawiona wersja zależy od produktu. Sama obecność polityki i pakietu to jedynie wskazówki, a nie dowód, że wywołujący może zamontować lub zmienić rozmiar urządzenia. Podczas inwentaryzacji unikaj zmieniania montowań i wywoływania metod D-Bus.<sup>[[3]](#references)</sup>

## References

- [1] [Komunikat SUSE dotyczący CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Aktualizacja zabezpieczeń SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Komunikat SUSE dotyczący CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
