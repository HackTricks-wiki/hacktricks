# Kontejneri i imenski prostori

{{#include ../../banners/hacktricks-training.md}}

Kontejner je Linux proces koji se izvršava uz konfiguraciju izolacije i privilegija. Zajedno procenite okruženje za izvršavanje, montirane resurse hosta, dodeljene capabilities i podešavanja imenskih prostora. [Pregled bezbednosti kontejnera](container-security/README.md) objašnjava ove slojeve i upućuje na svaku od kontrola.

- [Eskalacija privilegija pomoću Containerd-a (`ctr`)](containerd-ctr-privilege-escalation.md) fokusira se na pristup interfejsu za upravljanje Containerd-om.
- [Eskalacija privilegija pomoću RunC-a](runc-privilege-escalation.md) obrađuje materijal za eskalaciju specifičan za okruženje za izvršavanje.
- [Bezbednost kontejnera](container-security/README.md) objašnjava okruženja za izvršavanje, izložene API-je, rizike vezane za slike, osetljive montirane resurse, privilegovane kontejnere, procenu i zaštite kao što su imenski prostori, seccomp i obavezna kontrola pristupa.
{{#include ../../banners/hacktricks-training.md}}
