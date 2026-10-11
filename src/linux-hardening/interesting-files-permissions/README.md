# Interesujące pliki i uprawnienia

{{#include ../../banners/hacktricks-training.md}}

Właściciel pliku, uprawnienia do zapisu, opcje montowania i uprawnienia do wykonywania mogą zmienić zakres działań dostępnych lokalnemu użytkownikowi. Zacznij od wskazania docelowego pliku lub ścieżki wykonania, a następnie skorzystaj z odpowiedniej strony:

- [SUID, SGID, ACL i pliki wrażliwe](suid-sgid-and-acl-triage.md) przedstawia podstawowy proces analizy uprawnień do wykonywania i ukrytych przyznań dostępu.
- [Dowolny zapis do pliku jako root](write-to-root.md) opisuje, jak zapisy do uprzywilejowanych ścieżek mogą prowadzić do eskalacji uprawnień.
- [Linux capabilities](linux-capabilities.md) wyjaśnia capabilities przypisane procesom i plikom.
- [Nadużycia bibliotek współdzielonych i linkera w SUID](suid-shared-library-and-linker-abuse.md) omawia dynamiczne ładowanie w kontekście uprzywilejowanych plików binarnych.
- [Przykład eskalacji uprawnień przez `ld.so`](ld.so.conf-example.md) opisuje przypadek dotyczący konfiguracji linkera.
- [Błędna konfiguracja NFS `no_root_squash` i `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) omawia mapowanie tożsamości w zdalnych systemach plików.
- [Sztuczki z wildcardami i spare](wildcards-spare-tricks.md) omawia rozwijanie argumentów w uprzywilejowanych poleceniach.
- [SELinux](selinux.md) wyjaśnia egzekwowanie polityk i opisuje istotne kroki analizy.

{{#include ../../banners/hacktricks-training.md}}
