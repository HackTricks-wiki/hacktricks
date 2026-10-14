# iButton

{{#include ../../banners/hacktricks-training.md}}

## Uvod

iButton je opšti naziv za elektronski identifikacioni ključ smešten u **metalno kućište oblika novčića**. Naziva se i Dallas Touch Memory ili kontaktna memorija. Iako ga često pogrešno nazivaju „magnetnim“ ključem, u njemu nema **ničeg magnetnog**. Unutra je zapravo skriven potpuno funkcionalan **mikročip** koji radi po digitalnom protokolu.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Naziv iButton opisuje izdržljivo kućište oblika novčića i raspored kontakata. Nosači uključuju plastične priveske, prstenje i medaljone.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Kada oba kontakta dodirnu čitač, uređaj dobija napajanje i razmenjuje podatke. Ako udubljeni oblik kontakata sprečava dodir spoljašnjih kontakata za uzemljenje, naginjanje ključa uz zid čitača može ponovo uspostaviti kontakt.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim ključevi koriste 1-Wire protokol: jedan kontakt za podatke prenosi dvosmernu komunikaciju i može istovremeno da obezbeđuje parazitsko napajanje, dok metalno kućište služi kao povratni kontakt. Kontroler pokreće transakcije, a uređaj odgovara.<sup>[[2]](#references)</sup>

Kada ključ (Slave) dodirne interfon (Master), čip unutar ključa se uključuje, napajan interfonom, i ključ se inicijalizuje. Zatim interfon traži ID ključa. U nastavku ćemo detaljnije razmotriti ovaj proces.

Flipper može da služi kao kontroler prilikom čitanja ključa, a i kao emulirani uređaj kada čitaču predstavlja sačuvani identifikator.<sup>[[1]](#references)</sup>

### Dallas, Cyfral i Metakom ključevi

Informacije o tome kako ovi ključevi funkcionišu potražite na stranici [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Napadi

iButton se može napasti pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Ukroćavanje iButton-a pomoću Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire komunikacija putem softvera](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
