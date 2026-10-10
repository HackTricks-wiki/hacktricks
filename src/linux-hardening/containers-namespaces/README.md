# Kontejneri i prostori imena

{{#include ../../banners/hacktricks-training.md}}

Kontejner je Linux proces koji se izvršava uz konfiguraciju izolacije i privilegija. Proceni okruženje za izvršavanje, montirane resurse hosta, dodeljene capabilities i podešavanja prostora imena zajedno. [Pregled bezbednosti kontejnera](container-security/README.md) objašnjava ove slojeve i povezuje ih sa pojedinačnim kontrolama.

- [Eskalacija privilegija preko Containerd-a (`ctr`)](containerd-ctr-privilege-escalation.md) bavi se pristupom interfejsu za upravljanje containerd-om.
- [Eskalacija privilegija preko RunC-a](runc-privilege-escalation.md) obrađuje materijal o eskalaciji specifičan za okruženje za izvršavanje.
- [Bezbednost kontejnera](container-security/README.md) objašnjava okruženja za izvršavanje, izložene API-je, rizike slika, osetljive montirane resurse, privilegovane kontejnere, procenu i zaštite kao što su prostori imena, seccomp i obavezna kontrola pristupa.
{{#include ../../banners/hacktricks-training.md}}
