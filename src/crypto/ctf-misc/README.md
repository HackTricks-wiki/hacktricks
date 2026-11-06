# Crypto CTF Diverse

{{#include ../../banners/hacktricks-training.md}}

Hierdie afdeling versamel tegnieke wat in kriptografie-uitdagings voorkom, maar nie netjies in die ander kategorieë pas nie.

## Esoteriese tale

### Tegniek

Gebruik hierdie werkvloei wanneer ’n uitdaging vereis dat jy ’n program in ’n esoteriese taal uitvoer en die uitvoer dekodeer.

As ’n uitdaging vir jou kode gee wat nie soos ’n standaardtaal lyk nie:

- Identifiseer die taal deur na ’n kenmerkende teken of instruksievolgorde te soek.
- Gebruik ’n aanlyn interpreter of ’n Docker-image.
- As die uitvoer vreemd is, kyk ná die uitvoering vir lae enkodering of kompressie.

Die Esolang-wiki is ’n nuttige taalindeks.<sup>[[1]](#references)</sup> Gebruik die [Crypto CTF-werkvloei](../ctf-workflow/) vir gewone enkoderings- en kompressielae. As die leidraad onsigbare teks eerder as uitvoerbare sintaksis is, kyk na [tekssteganografie](../../stego/text/).

### Eksfiltrering van voorafgelaaide interpreter-toestand

As ’n uitdaging esoteriese-taalbron aanvaar en dit in ’n **pasgemaakte interpreter** uitvoer, ondersoek die aanvanklike geheue, stack en uitvoerinstruksies voordat jy die bron as ’n dekoderingsraaisel beskou. Wanneer die interpreter ’n geheim vooraf op ’n Befunge-stack laai, kan ’n kort program die bestaande grepe afhaal en druk sonder om dit te bereken. Dit vereis beheer oor die uitgevoerde bron en ’n uitvoer-opcode; dit werk nie met ’n gewone leë interpreter nie. In ’n Befunge-uitdaging het die invoer hieronder herhaaldelik karakters van ’n vlag afgedruk wat in omgekeerde volgorde op die stack voorafgelaai is.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` begin uitvoering na regs, `,` haal ’n karakter van die stapel af en druk dit uit, en `<` stuur die instruksiewyser terug na `,`. Gaan die pasgemaakte interpreter se onderloop- en instruksielimietgedrag na: die aangehaalde implementering stop wanneer die stapel uitgeput is of ná 1 024 instruksies. As die geheim nie direk op die stapel is nie, ondersoek ander geïnisialiseerde toestand en beskikbare uitvoer-/leesinstruksies eerder as om standaard-Befunge-semantiek te aanvaar.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, die esoteriese programmeertale-wiki](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1-oorspronklike writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1-interpreter-bronkode](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge-taalverwysing](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
