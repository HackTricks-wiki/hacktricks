# Interesujące pliki i uprawnienia

{{#include ../../banners/hacktricks-training.md}}

Właściciel pliku, dostęp do zapisu, opcje montowania i uprawnienia do wykonywania mogą zmienić efektywny zakres dostępu lokalnego użytkownika. Zacznij od zidentyfikowania docelowego pliku lub ścieżki wykonywania, a następnie skorzystaj z odpowiedniej strony:

- [SUID, SGID, ACL i pliki wrażliwe](suid-sgid-and-acl-triage.md) przedstawia początkowy workflow dotyczący uprawnień do wykonywania i ukrytych przydziałów dostępu.
- [Dowolny zapis do pliku jako root](write-to-root.md) opisuje, jak zapisy w uprzywilejowanych ścieżkach można wykorzystać do eskalacji.
- [Linux capabilities](linux-capabilities.md) wyjaśnia capabilities przypisane do procesów i plików.
- [Nadużycia bibliotek współdzielonych SUID i linkera](suid-shared-library-and-linker-abuse.md) omawia dynamiczne ładowanie w kontekście uprzywilejowanych plików binarnych.
- [Przykład eskalacji uprawnień przez `ld.so`](ld.so.conf-example.md) opisuje przypadek dotyczący konfiguracji linkera.
- [Błędna konfiguracja NFS `no_root_squash` i `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) omawia mapowanie tożsamości w zdalnym systemie plików.
- [Sztuczki z wildcardami i spare](wildcards-spare-tricks.md) omawia rozwijanie argumentów w uprzywilejowanych poleceniach.
- [SELinux](selinux.md) wyjaśnia egzekwowanie zasad i odpowiednie kroki dochodzeniowe.
{{#include ../../banners/hacktricks-training.md}}
