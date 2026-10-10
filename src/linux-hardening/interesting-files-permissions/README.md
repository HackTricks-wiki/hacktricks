# Zanimljive datoteke i dozvole

{{#include ../../banners/hacktricks-training.md}}

Vlasništvo nad datotekama, pristup za pisanje, opcije montiranja i privilegije izvršavanja mogu da promene efektivni domet lokalnog korisnika. Najpre utvrdite ciljnu datoteku ili putanju izvršavanja, a zatim pogledajte odgovarajuću stranicu:

- [SUID, SGID, ACL-ovi i osetljive datoteke](suid-sgid-and-acl-triage.md) nudi početni postupak za privilegije izvršavanja i skrivene dozvole pristupa.
- [Pisanje proizvoljne datoteke kao root](write-to-root.md) opisuje kako pisanje u privilegovane putanje može da se iskoristi za eskalaciju.
- [Linux mogućnosti](linux-capabilities.md) objašnjava mogućnosti po procesu i po datoteci.
- [Zloupotreba SUID deljenih biblioteka i linkera](suid-shared-library-and-linker-abuse.md) obrađuje dinamičko učitavanje oko privilegovanih binarnih datoteka.
- [Primer eskalacije privilegija pomoću `ld.so`](ld.so.conf-example.md) prati slučaj sa konfiguracijom linkera.
- [Pogrešna konfiguracija NFS-a `no_root_squash` i `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) obrađuje mapiranje identiteta na udaljenim sistemima datoteka.
- [Trikovi sa džoker znakovima](wildcards-spare-tricks.md) obrađuju proširivanje argumenata u privilegovanim komandama.
- [SELinux](selinux.md) objašnjava sprovođenje pravila i relevantne korake istrage.
{{#include ../../banners/hacktricks-training.md}}
