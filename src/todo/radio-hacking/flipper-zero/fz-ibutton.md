# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Za osnovne informacije o iButton tehnologiji pogledajte:

{{#ref}}
../ibutton.md
{{#endref}}

## Dizajn

Na sledećoj slici, **plava** oblast prikazuje kako postaviti fizički iButton uz kontakte Flipper Zero uređaja radi očitavanja. **Zelena** oblast prikazuje koji kontakti treba da dodiruju čitač tokom emulacije.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Čitanje

U režimu čitanja, Flipper Zero čeka da ključ dodirne njegove kontakte, detektuje protokol i prikazuje protokol iznad ID-ja ključa. Ugrađena aplikacija podržava Dallas, Cyfral i Metakom ključeve za kontrolu pristupa.<sup>[[2]](#references)</sup>

### Ručno dodavanje

Možete ručno uneti podatke ključa za Dallas, Cyfral i Metakom protokole.<sup>[[2]](#references)</sup>

### Emulacija

Možete emulirati sačuvani ključ, bez obzira na to da li je očitan sa fizičkog ključa ili ručno unet.<sup>[[2]](#references)</sup>

> [!TIP]
> Ako ugrađeni kontakti ne mogu da dosegnu čitač, povežite kontakte za podatke i uzemljenje preko GPIO pinova.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Ukroćavanje iButton ključeva pomoću Flipper Zero uređaja](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Dokumentacija za Flipper Zero - Očitavanje iButton ključeva](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
