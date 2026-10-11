# Glavne informacije o sistemu

{{#include ../../banners/hacktricks-training.md}}

Pre nego što izaberete tehniku za lokalnu eskalaciju privilegija, proverite kernel hosta, sistem datoteka, privilegovane pomoćne programe i dostupne načine za bekstvo. [Kontrolna lista za eskalaciju privilegija](linux-privilege-escalation-checklist.md) daje sažet redosled postupaka.

- [Procena ranjivosti kernela i izloženost tokom izvršavanja](kernel-vulnerability-assessment.md) proverava primenljivost verzije, dostupnost i aktivne mere zaštite.
- [Kernel moduli i zloupotreba modprobe-a](kernel-modules-and-modprobe.md) obrađuje učitavanje modula i izloženost putanja pomoćnih programa.
- [Zloupotreba sudo komandi](sudo-command-abuse.md) razmatra načine na koje delegirane komande mogu preći granice privilegija.
- [Simboličke i čvrste veze i deskriptori datoteka](filesystem-links-and-file-descriptors.md) obrađuje preusmeravanje putanja i nasleđene ili obrisane, ali otvorene datoteke.
- [Sistem datoteka, inode-ovi i oporavak](filesystem-inodes-and-recovery.md) objašnjava ponašanje sistema datoteka koje može biti korisno tokom istrage.
- [Kontrolna lista: eskalacija privilegija u Linuxu](linux-privilege-escalation-checklist.md) navodi provere hosta i upućuje na detaljniji materijal.
- [Bekstvo iz izolovanih okruženja](escaping-from-limited-bash.md) obrađuje ograničene ljuske i restriktivna okruženja.
- [Materijali o kernelu/LPE/CVE](kernel-lpe-cves/README.md) objedinjuju ciljane tekstove o lokalnoj eskalaciji privilegija i ranjivostima.
{{#include ../../banners/hacktricks-training.md}}
