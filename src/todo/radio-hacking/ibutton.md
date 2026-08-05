# iButton

{{#include ../../banners/hacktricks-training.md}}

## Uvod

iButton je generički naziv za elektronski identifikacioni ključ smešten u **metalno kućište oblika novčića**. Takođe se naziva **Dallas Touch** Memory ili kontaktna memorija. Iako se često pogrešno naziva „magnetnim“ ključem, u njemu **nema ničeg magnetnog**. Zapravo, unutra je skriven potpuno funkcionalan **mikročip** koji radi na digitalnom protokolu.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton se obično odnosi na fizički oblik ključa i čitača - okrugli novčić sa dva kontakta. Za okvir koji ga okružuje postoji mnogo varijacija, od najčešćeg plastičnog držača sa otvorom do prstenova, privezaka itd.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Kada ključ dođe do čitača, **kontakti dodiruju jedan drugi** i ključ dobija napajanje kako bi **poslao** svoj ID. Ponekad se ključ **ne očita** odmah zato što je **kontaktni PSD interfona veći** nego što bi trebalo da bude. Zbog toga spoljne konture ključa i čitača ne mogu da dodirnu jedna drugu. Ako je to slučaj, moraćete da pritisnete ključ uz jedan od zidova čitača.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas ključevi razmenjuju podatke koristeći 1-wire protokol. Za prenos podataka u oba smera koristi se samo jedan kontakt (!!), od mastera ka slave-u i obrnuto. 1-wire protokol radi prema Master-Slave modelu. U ovoj topologiji Master uvek pokreće komunikaciju, a Slave prati njegova uputstva.

Kada ključ (Slave) stupi u kontakt sa interfonom (Master), čip unutar ključa se uključuje napajanjem koje dobija od interfona i ključ se inicijalizuje. Nakon toga interfon zahteva ID ključa. U nastavku ćemo detaljnije razmotriti ovaj proces.

Flipper može da radi i u Master i u Slave režimu. U režimu čitanja ključa, Flipper se ponaša kao čitač, odnosno radi kao Master. U režimu emulacije ključa, Flipper se pretvara da je ključ i radi u Slave režimu.

### Dallas, Cyfral i Metakom ključevi

Informacije o tome kako ovi ključevi rade potražite na stranici [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Napadi

iButton uređaji mogu biti napadnuti pomoću Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Reference

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
