# Zanimljive datoteke i dozvole

{{#include ../../banners/hacktricks-training.md}}

Vlasništvo nad datotekama, pristup za pisanje, opcije montiranja i privilegije izvršavanja mogu da promene efektivni domet lokalnog korisnika. Počnite tako što ćete utvrditi ciljnu datoteku ili putanju izvršavanja, a zatim koristite odgovarajuću stranicu:

- [SUID, SGID, ACL-ovi i osetljive datoteke](suid-sgid-and-acl-triage.md) pruža početni postupak za privilegije izvršavanja i skrivene dozvole pristupa.
- [Upisivanje proizvoljnog sadržaja u datoteke kao root](write-to-root.md) opisuje kako se upisivanjem u privilegovane putanje može postići eskalacija privilegija.
- [Linux capabilities](linux-capabilities.md) objašnjava mogućnosti po procesu i datoteci.
- [Zloupotreba deljenih biblioteka i linkera uz SUID](suid-shared-library-and-linker-abuse.md) obrađuje dinamičko učitavanje u kontekstu privilegovanih binarnih datoteka.
- [Primer eskalacije privilegija pomoću `ld.so`](ld.so.conf-example.md) prikazuje slučaj sa konfiguracijom linkera.
- [Pogrešna konfiguracija NFS-a `no_root_squash` i `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) obrađuje mapiranje identiteta na udaljenim sistemima datoteka.
- [Trikovi sa džoker znakovima](wildcards-spare-tricks.md) obrađuju proširivanje argumenata u privilegovanim komandama.
- [SELinux](selinux.md) objašnjava sprovođenje pravila i relevantne korake istrage.
{{#include ../../banners/hacktricks-training.md}}
