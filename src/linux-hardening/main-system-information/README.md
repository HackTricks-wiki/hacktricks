# Glavne informacije o sistemu

{{#include ../../banners/hacktricks-training.md}}

Pre nego što izaberete tehniku za lokalnu eskalaciju privilegija, proverite kernel hosta, sistem datoteka, privilegovane pomoćne programe i dostupne načine za izlazak iz ograničenog okruženja. [Kontrolna lista za eskalaciju privilegija](linux-privilege-escalation-checklist.md) pruža sažet redosled koraka.

- [Procena ranjivosti kernela i izloženost tokom izvršavanja](kernel-vulnerability-assessment.md) proverava primenljivost na konkretnu verziju, dostupnost i aktivne mere ublažavanja.
- [Kernel moduli i zloupotreba modprobe-a](kernel-modules-and-modprobe.md) obrađuje učitavanje modula i izloženost putanja pomoćnih programa.
- [Zloupotreba Sudo komandi](sudo-command-abuse.md) razmatra načine na koje delegirane komande mogu preći granice privilegija.
- [Symlinks, hardlinks i deskriptori datoteka](filesystem-links-and-file-descriptors.md) obrađuje preusmeravanje putanja i nasleđene ili obrisane, ali otvorene datoteke.
- [Sistem datoteka, inodes i oporavak](filesystem-inodes-and-recovery.md) objašnjava ponašanje sistema datoteka korisno tokom istrage.
- [Kontrolna lista: eskalacija privilegija u Linuxu](linux-privilege-escalation-checklist.md) navodi provere hosta i upućuje na detaljnije materijale.
- [Izlazak iz jail okruženja](escaping-from-limited-bash.md) obrađuje ograničene ljuske i ograničena okruženja.
- [Materijali o kernelu/LPE/CVE](kernel-lpe-cves/README.md) grupišu detaljne tekstove o lokalnoj eskalaciji privilegija i ranjivostima.
{{#include ../../banners/hacktricks-training.md}}
