# Wskaźniki eskalacji uprawnień w sesjach SUSE i usługach dyskowych

{{#include ../../banners/hacktricks-training.md}}

## Autoryzacja sesji SSH za pośrednictwem PAM

CVE-2025-6018 dotyczył konfiguracji PAM w SUSE 15, w których stos uwierzytelniania SSH ładował `pam_env` przed załadowaniem `pam_systemd` przez stos sesji. Gdy `pam_env` odczytywał plik `.pam_environment` użytkownika, użytkownik mógł ustawić wartości `XDG_SEAT` i `XDG_VTNR`, przez które Polkit uznawał sesję SSH za aktywną fizycznie. W rezultacie zdalny użytkownik mógł uzyskać dostęp do akcji `allow_active=yes`. Zmienia to autoryzację sesji, ale samo w sobie nie gwarantuje dostępu do roota. SUSE poprawiło domyślne zachowanie dotyczące środowiska użytkownika w `pam` oraz rozmieszczenie modułów generowane przez `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Sprawdź efektywny łańcuch dołączanych plików `/etc/pam.d/sshd`, kolejność `pam_env.so` i `pam_systemd.so` oraz wszystkie jawne opcje `user_readenv=1`. Zaktualizowany pakiet `pam` zmienia domyślne ustawienie, ale jawna opcja nadal może włączać odczyt zmiennych środowiskowych użytkownika. Nowszy pakiet `pam-config` nie dowodzi, że lokalnie zmodyfikowany lub nieaktualny stos PAM został wygenerowany ponownie. Sprawdź zarówno wydanie pakietu dostawcy, jak i faktyczną konfigurację.<sup>[[1]](#references)[[2]](#references)</sup>

## Ścieżka usługi dyskowej dostępna dla aktywnego użytkownika

CVE-2025-6019 dotyczył ścieżki eskalacji uprawnień w `libblockdev`, używanej za pośrednictwem `udisks2`: podczas zmiany rozmiaru systemu plików XFS system plików dostarczony przez atakującego mógł być tymczasowo zamontowany bez oczekiwanego ograniczenia `nosuid`. Ta ścieżka wymaga działającej usługi D-Bus UDisks, obsługi zmiany rozmiaru XFS, odpowiedniej akcji Polkit dostępnej dla użytkownika wywołującego oraz podatnej wersji pakietu biblioteki. CVE-2025-6018 to jeden ze sposobów uzyskania sesji aktywnego użytkownika, ale użytkownik, który już ma taką sesję, może niezależnie skorzystać ze ścieżki usługi dyskowej.<sup>[[3]](#references)</sup>

W ramach pasywnego przeglądu sprawdź metadane usługi UDisks, politykę `org.freedesktop.udisks2.modify-device`, `xfs_growfs` oraz zainstalowany pakiet `libbd_fs2`. SUSE podaje wersję `libbd_fs2` `2.26-150400.3.5.1` jako poprawioną dla openSUSE Leap 15.6; dokładne poprawione wydanie zależy od produktu. Sama obecność polityki i pakietu to wskazówki, a nie dowód, że użytkownik wywołujący może montować lub zmieniać rozmiar urządzenia. Podczas enumeracji nie zmieniaj montowań ani nie wywołuj metod D-Bus.<sup>[[3]](#references)</sup>

## References

- [1] [Komunikat SUSE dotyczący CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Aktualizacja bezpieczeństwa SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Komunikat SUSE dotyczący CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
