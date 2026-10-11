# Kontejneri i namespace-ovi

{{#include ../../banners/hacktricks-training.md}}

Kontejner je Linux proces koji radi uz konfiguraciju izolacije i privilegija. Zajedno procenite runtime, montirane resurse hosta, dodeljene capabilities i podešavanja namespace-ova. [Pregled bezbednosti kontejnera](container-security/README.md) objašnjava ove slojeve i sadrži linkove ka pojedinačnim kontrolama.

- [Eskalacija privilegija preko Containerd-a (`ctr`)](containerd-ctr-privilege-escalation.md) fokusira se na pristup interfejsu za upravljanje Containerd-om.
- [Eskalacija privilegija preko RunC-a](runc-privilege-escalation.md) obrađuje materijal o eskalaciji specifičan za runtime.
- [Bezbednost kontejnera](container-security/README.md) objašnjava runtime-ove, izložene API-je, rizike vezane za slike, osetljiva montiranja, privilegovane kontejnere, procenu i zaštite kao što su namespace-ovi, seccomp i obavezna kontrola pristupa.
{{#include ../../banners/hacktricks-training.md}}
