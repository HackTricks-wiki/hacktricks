# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Više informacija o iButton tehnologiji potražite ovde:

{{#ref}}
../ibutton.md
{{#endref}}

## Dizajn

Na sledećoj slici **plava** oblast prikazuje kako postaviti fizički iButton na kontakte Flipper Zero uređaja radi očitavanja. **Zelena** oblast prikazuje koji kontakti treba da dodiruju čitač tokom emulacije.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Čitanje

U režimu čitanja, Flipper Zero čeka da ključ dodirne njegove kontakte, detektuje protokol i prikazuje ga iznad ID-a ključa. Ugrađena aplikacija podržava pristupne ključeve Dallas, Cyfral i Metakom.<sup>[[2]](#references)</sup>

### Ručno dodavanje

Možete ručno uneti podatke o ključu za protokole Dallas, Cyfral i Metakom.<sup>[[2]](#references)</sup>

### Emulacija

Možete emulirati sačuvani ključ, bilo da je očitan sa fizičkog ključa ili unet ručno.<sup>[[2]](#references)</sup>

> [!TIP]
> Ako ugrađeni kontakti ne mogu da dosegnu čitač, povežite kontakte za prenos podataka i uzemljenje preko GPIO pinova.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Obuzdavanje iButton ključeva pomoću Flipper Zero uređaja](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Dokumentacija za Flipper Zero - Očitavanje iButton ključeva](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

