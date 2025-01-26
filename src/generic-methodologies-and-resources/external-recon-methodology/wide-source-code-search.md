# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Cilj ove stranice je da nabroji **platforme koje omogućavaju pretragu koda** (literalno ili regex) u hiljadama/milionima repozitorijuma na jednoj ili više platformi.

Ovo pomaže u nekoliko slučajeva da **pronađete provale informacija** ili obrasce **ranjivosti**.

- [**Sourcebot**](https://www.sourcebot.dev/): Alat za pretragu otvorenog koda. Indeksirajte i pretražujte hiljade vaših repozitorijuma kroz moderan veb interfejs.
- [**SourceGraph**](https://sourcegraph.com/search): Pretražujte u milionima repozitorijuma. Postoji besplatna verzija i verzija za preduzeća (sa 15 dana besplatno). Podržava regex.
- [**Github Search**](https://github.com/search): Pretražujte na Github-u. Podržava regex.
- Možda je takođe korisno proveriti i [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Pretražujte u Gitlab projektima. Podržava regex.
- [**SearchCode**](https://searchcode.com/): Pretražujte kod u milionima projekata.

> [!WARNING]
> Kada tražite provale u repozitorijumu i pokrenete nešto poput `git log -p`, ne zaboravite da mogu postojati **druge grane sa drugim commit-ima** koje sadrže tajne!

{{#include ../../banners/hacktricks-training.md}}
