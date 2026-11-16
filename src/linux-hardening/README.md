# Wzmacnianie zabezpieczeń Linuxa

{{#include ../banners/hacktricks-training.md}}

Skorzystaj z tej sekcji, aby badać hosty Linux, poznać granice uprawnień i przejrzeć mechanizmy ograniczające dostęp lokalny. Zacznij od [podstaw Linuxa](linux-basics/README.md) i [listy kontrolnej eskalacji uprawnień](main-system-information/linux-privilege-escalation-checklist.md), aby przeprowadzić ogólną ocenę, a następnie przejdź do odpowiedniego tematu poniżej.

- [Podstawy Linuxa](linux-basics/README.md): metodyka eskalacji uprawnień, przydatne polecenia, zmienne środowiskowe i sposoby omijania ograniczeń.
- [Główne informacje o systemie](main-system-information/README.md): kernel, moduły, sudo, działanie systemu plików, jails i lista kontrolna eskalacji uprawnień.
- [Informacje o użytkownikach](user-information/README.md): tożsamości Linux, grupy, przekazywanie agenta SSH i integracja z Active Directory.
- [Interesujące pliki i uprawnienia](interesting-files-permissions/README.md): zapisywalne ścieżki, capabilities, działanie SUID, NFS, rozwijanie wildcardów i SELinux.
- [Informacje o sieci](network-information/README.md): usługi lokalne, sockety i przykłady exploitacji związane z siecią.
- [Informacje o oprogramowaniu](software-information/README.md): moduły uwierzytelniania i powierzchnie ataku specyficzne dla aplikacji.
- [Procesy, crontab, systemd i D-Bus](processes-crontab-systemd-dbus/README.md): zaplanowane wykonywanie i komunikacja międzyprocesowa.
- [Kontenery i namespaces](containers-namespaces/README.md): runtime’y, granice izolacji i wzmacnianie zabezpieczeń kontenerów.
- [Nadużywanie plików kontroli polityki AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): sprawdź, czy uprzywilejowany helper może zapisywać do pliku kontroli AppArmor otwartego przez użytkownika lokalnego.
- [Post-exploitation](post-exploitation/README.md): wykrywanie poświadczeń, persistence i techniki dalszych działań na poziomie hosta.

W podatnych kernelach otwarcie pliku kontroli polityki AppArmor w securityfs przez nieuprzywilejowanego użytkownika może się powieść, mimo że bezpośredni zapis jest zabroniony. Jeśli uprzywilejowany helper odziedziczy ten plik jako stdout, jego zapis może zmienić załadowaną politykę; jest to odrębna lokalna ścieżka ataku, a nie tylko znalezienie słabego profilu kontenera. Przed testowaniem sprawdź poprawki dostawcy kernela i helpera.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Techniczne ostrzeżenie Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Baza wiedzy o podatności CrackArmor w Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
