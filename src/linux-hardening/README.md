# Utwardzanie Linuxa

{{#include ../banners/hacktricks-training.md}}

Użyj tej sekcji, aby analizować hosty Linux, poznać granice uprawnień i sprawdzić mechanizmy ograniczające dostęp lokalny. Zacznij od [podstaw Linuxa](linux-basics/README.md) i [listy kontrolnej eskalacji uprawnień](main-system-information/linux-privilege-escalation-checklist.md), aby przeprowadzić ogólną ocenę, a następnie przejdź do odpowiedniego tematu poniżej.

- [Podstawy Linuxa](linux-basics/README.md): metodyka eskalacji uprawnień, przydatne polecenia, zmienne środowiskowe i omijanie ograniczeń.
- [Główne informacje o systemie](main-system-information/README.md): jądro, moduły, sudo, zachowanie systemu plików, jails i lista kontrolna eskalacji uprawnień.
- [Informacje o użytkownikach](user-information/README.md): tożsamości i grupy w Linuxie, przekazywanie agenta SSH i integracja z Active Directory.
- [Interesujące pliki i uprawnienia](interesting-files-permissions/README.md): zapisywalne ścieżki, capabilities, zachowanie SUID, NFS, rozwijanie symboli wieloznacznych i SELinux.
- [Informacje o sieci](network-information/README.md): usługi lokalne, gniazda i przykłady exploitacji związane z siecią.
- [Informacje o oprogramowaniu](software-information/README.md): moduły uwierzytelniania i powierzchnie ataku specyficzne dla aplikacji.
- [Procesy, crontab, systemd i D-Bus](processes-crontab-systemd-dbus/README.md): zaplanowane uruchamianie i komunikacja międzyprocesowa.
- [Kontenery i namespaces](containers-namespaces/README.md): środowiska uruchomieniowe, granice izolacji i utwardzanie kontenerów.
- [Post-exploitation](post-exploitation/README.md): wyszukiwanie poświadczeń, utrzymywanie dostępu i dalsze techniki na poziomie hosta.
{{#include ../banners/hacktricks-training.md}}
