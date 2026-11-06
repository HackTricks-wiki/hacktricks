# Crypto CTF - razno

{{#include ../../banners/hacktricks-training.md}}

Ovaj odeljak obuhvata tehnike koje se pojavljuju u kriptografskim izazovima, ali se ne uklapaju jasno ni u jednu drugu kategoriju.

## Ezoterični jezici

### Tehnika

Koristite ovaj postupak kada izazov zahteva pokretanje programa napisanog na ezoteričnom jeziku i dekodiranje njegovog izlaza.

Ako dobijete kod koji ne liči na standardni programski jezik:

- Identifikujte jezik pretragom karakterističnog tokena ili niza instrukcija.
- Koristite online interpreter ili Docker image.
- Ako je izlaz neobičan, potražite dodatne slojeve kodiranja ili kompresije nakon izvršavanja.

Korisni indeks jezika je Esolang wiki.<sup>[[1]](#references)</sup> Za uobičajene slojeve kodiranja i kompresije koristite [Crypto CTF postupak](../ctf-workflow/). Ako je nagoveštaj nevidljiv tekst, a ne izvršna sintaksa, pogledajte [steganografiju teksta](../../stego/text/).

### Eksfiltracija unapred učitanog stanja interpretera

Ako izazov prihvata izvorni kod na ezoteričnom jeziku i pokreće ga u **prilagođenom interpreteru**, pregledajte njegovu početnu memoriju, stek i instrukcije za izlaz pre nego što izvorni kod tretirate kao zagonetku za dekodiranje. Kada interpreter unapred učita tajnu na Befunge stek, kratak program može da ukloni postojeće bajtove sa steka i ispiše ih, bez ikakvog izračunavanja. Ovo zahteva kontrolu nad izvršenim izvornim kodom i izlazni opcode; ne radi u uobičajenom interpreteru sa praznim stekom. U Befunge izazovu, ulaz u nastavku je više puta ispisivao znakove iz flaga koji je unapred učitan na stek obrnutim redosledom.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` pokreće izvršavanje udesno, `,` skida i ispisuje znak, a `<` vraća pokazivač instrukcija na `,`. Proverite ponašanje prilagođenog interpretera pri underflow-u i ograničenju broja instrukcija: navedena implementacija se zaustavlja kada se stek isprazni ili nakon 1.024 instrukcije. Ako se tajna ne nalazi direktno na steku, pregledajte druga inicijalizovana stanja i dostupne instrukcije za ispis/čitanje umesto da pretpostavite standardnu Befunge semantiku.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, wiki o ezoteričnim programskim jezicima](https://esolangs.org/wiki/Main_Page)
- [2] [Izvorni writeup za WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Izvorni kod interpretera za WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Referenca za jezik Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
