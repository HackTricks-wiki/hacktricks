# Zanimljive datoteke i dozvole

{{#include ../../banners/hacktricks-training.md}}

Vlasništvo nad datotekama, pristup za upis, opcije montiranja i izvršne privilegije mogu da promene efektivni doseg lokalnog korisnika. Počnite tako što ćete identifikovati ciljnu datoteku ili putanju izvršavanja, a zatim koristite odgovarajuću stranicu:

- [SUID, SGID, ACL-ovi i osetljive datoteke](suid-sgid-and-acl-triage.md) daje početni postupak za izvršne privilegije i skrivene dodele pristupa.
- [Proizvoljan upis u datoteku kao root](write-to-root.md) opisuje kako se upisom u privilegovane putanje može postići eskalacija.
- [Linux capabilities](linux-capabilities.md) objašnjava capabilities na nivou procesa i datoteke.
- [Zloupotreba SUID deljenih biblioteka i linkera](suid-shared-library-and-linker-abuse.md) obrađuje dinamičko učitavanje oko privilegovanih binarnih datoteka.
- [Primer eskalacije privilegija pomoću `ld.so`](ld.so.conf-example.md) prati slučaj konfiguracije linkera.
- [Pogrešna konfiguracija NFS-a `no_root_squash` i `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) obrađuje mapiranje identiteta na udaljenom sistemu datoteka.
- [Trikovi sa džoker znakom](wildcards-spare-tricks.md) obrađuju proširivanje argumenata u privilegovanim komandama.
- [SELinux](selinux.md) objašnjava sprovođenje pravila i relevantne korake istrage.

{{#include ../../banners/hacktricks-training.md}}
