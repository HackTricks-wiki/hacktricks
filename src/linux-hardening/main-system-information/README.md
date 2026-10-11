# Glavne informacije o sistemu

{{#include ../../banners/hacktricks-training.md}}

Pre nego što odaberete tehniku lokalne eskalacije privilegija, proverite kernel hosta, fajl sistem, privilegovane pomoćne programe i dostupne puteve za bekstvo. [Kontrolna lista za eskalaciju privilegija](linux-privilege-escalation-checklist.md) daje sažet redosled koraka.

- [Procena ranjivosti kernela i izloženost tokom izvršavanja](kernel-vulnerability-assessment.md) proverava primenljivost na verziju builda, dostupnost i aktivne mere zaštite.
- [Kernel moduli i zloupotreba modprobe-a](kernel-modules-and-modprobe.md) obrađuje učitavanje modula i izloženost putanja pomoćnih programa.
- [Zloupotreba sudo komandi](sudo-command-abuse.md) ispituje načine na koje delegirane komande mogu da pređu granice privilegija.
- [Simboličke i čvrste veze i deskriptori fajlova](filesystem-links-and-file-descriptors.md) obrađuje preusmeravanje putanja i nasleđene ili obrisane, ali otvorene fajlove.
- [Fajl sistem, inode-i i oporavak](filesystem-inodes-and-recovery.md) objašnjava ponašanje fajl sistema koje može biti korisno tokom istrage.
- [Kontrolna lista: eskalacija privilegija u Linuxu](linux-privilege-escalation-checklist.md) navodi provere hosta i linkove ka detaljnijem materijalu.
- [Bekstvo iz jail okruženja](escaping-from-limited-bash.md) obrađuje ograničene shell-ove i kontrolisana okruženja.
- [Materijali o kernelu/LPE/CVE-ovima](kernel-lpe-cves/README.md) objedinjuju ciljane analize lokalne eskalacije privilegija i ranjivosti.
{{#include ../../banners/hacktricks-training.md}}
