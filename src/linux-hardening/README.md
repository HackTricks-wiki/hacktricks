# Utwardzanie Linuksa

{{#include ../banners/hacktricks-training.md}}

Skorzystaj z tej sekcji, aby analizować hosty Linux, zrozumieć granice uprawnień i sprawdzić mechanizmy ograniczające dostęp lokalny. Ogólną ocenę rozpocznij od [podstaw Linuksa](linux-basics/README.md) i [listy kontrolnej privilege escalation](main-system-information/linux-privilege-escalation-checklist.md), a następnie przejdź do odpowiedniego tematu poniżej.

- [Podstawy Linuksa](linux-basics/README.md): metodologia privilege escalation, przydatne polecenia, zmienne środowiskowe i omijanie ograniczeń.
- [Główne informacje o systemie](main-system-information/README.md): kernel, moduły, sudo, zachowanie systemu plików, jails i lista kontrolna privilege escalation.
- [Informacje o użytkownikach](user-information/README.md): tożsamości i grupy w Linuksie, przekazywanie SSH agentów i integracja z Active Directory.
- [Interesujące pliki i uprawnienia](interesting-files-permissions/README.md): ścieżki z prawem zapisu, capabilities, zachowanie SUID, NFS, rozwijanie wildcardów i SELinux.
- [Informacje o sieci](network-information/README.md): usługi lokalne, sockety i przykłady exploitacji związane z siecią.
- [Informacje o oprogramowaniu](software-information/README.md): moduły uwierzytelniania i powierzchnie ataku specyficzne dla aplikacji.
- [Procesy, crontab, systemd i D-Bus](processes-crontab-systemd-dbus/README.md): zaplanowane uruchamianie i komunikacja międzyprocesowa.
- [Post-exploitation](post-exploitation/README.md): wyszukiwanie poświadczeń, persistence i dalsze techniki na poziomie hosta.
{{#include ../banners/hacktricks-training.md}}
