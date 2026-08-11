# iButton

{{#include ../../banners/hacktricks-training.md}}

## Uvod

iButton je generički naziv za elektronski identifikacioni ključ smešten u **metalno kućište oblika novčića**. Takođe se naziva Dallas Touch Memory ili kontaktna memorija. Iako se često pogrešno naziva „magnetnim“ ključem, u njemu **nema ničeg magnetnog**. Zapravo, unutra je skriven kompletan **mikročip** koji radi na digitalnom protokolu.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Naziv iButton opisuje izdržljivo kućište oblika novčića i raspored kontakata. Nosači obuhvataju plastične priveske, prstenje i priveske za nošenje oko vrata.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Kada oba kontakta dodirnu čitač, uređaj dobija napajanje i razmenjuje podatke. Ako udubljena geometrija kontakata sprečava da spoljašnji kontakti za uzemljenje ostvare kontakt, naginjanje ključa uz zid čitača može ponovo uspostaviti kontakt.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim ključevi koriste 1-Wire protokol: jedan kontakt za podatke prenosi dvosmerni saobraćaj i može takođe obezbeđivati parazitsko napajanje, dok metalno kućište služi kao povratni kontakt. Controller pokreće transakcije, a uređaj odgovara.<sup>[[2]](#references)</sup>

Kada ključ (Slave) ostvari kontakt sa interfon‑om (Master), čip unutar ključa se uključuje, napaja ga interfon i ključ se inicijalizuje. Nakon toga interfon zahteva ID ključa. U nastavku ćemo detaljnije pogledati ovaj proces.

Flipper može da deluje kao controller prilikom čitanja ključa i kao emulirani uređaj kada čitaču predstavlja sačuvani identifikator.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom ključevi

Za informacije o načinu rada ovih ključeva pogledajte stranicu [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Napadi

iButton uređaji mogu biti napadnuti pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Ukroćavanje iButton-a pomoću Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire komunikacija kroz softver](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
