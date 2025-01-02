# iButton

{{#include ../../banners/hacktricks-training.md}}

## Uvod

iButton je generički naziv za elektronski identifikacioni ključ smešten u **metalnu kutiju u obliku novčića**. Takođe se naziva **Dallas Touch** Memory ili kontaktna memorija. Iako se često pogrešno naziva "magnetnim" ključem, u njemu **nema ničega magnetskog**. U stvari, unutar njega se nalazi potpuno funkcionalni **mikročip** koji radi na digitalnom protokolu.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Obično, iButton podrazumeva fizički oblik ključa i čitača - okrugli novčić sa dva kontakta. Za okvir koji ga okružuje, postoji mnogo varijacija od najčešćeg plastičnog držača sa rupom do prstenova, privjesaka itd.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Kada ključ dođe do čitača, **kontakti se dodiruju** i ključ se napaja da **prenese** svoj ID. Ponekad ključ **nije odmah pročitan** jer je **kontakt PSD interkoma veći** nego što bi trebao biti. Tako spoljašnji konturi ključa i čitača ne mogu da se dodirnu. Ako je to slučaj, moraćete da pritisnete ključ na jednu od zidova čitača.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas ključevi razmenjuju podatke koristeći 1-wire protokol. Sa samo jednim kontaktom za prenos podataka (!!) u oba pravca, od mastera do sluge i obrnuto. 1-wire protokol funkcioniše prema Master-Slave modelu. U ovoj topologiji, Master uvek inicira komunikaciju, a Slave prati njegove instrukcije.

Kada ključ (Slave) kontaktira interkom (Master), čip unutar ključa se uključuje, napajan od strane interkoma, i ključ se inicijalizuje. Nakon toga, interkom zahteva ID ključa. Sledeće, detaljnije ćemo pogledati ovaj proces.

Flipper može raditi i u Master i u Slave režimu. U režimu čitanja ključeva, Flipper deluje kao čitač, to jest, radi kao Master. A u režimu emulacije ključa, flipper se pretvara da je ključ, u Slave režimu.

### Dallas, Cyfral & Metakom ključevi

Za informacije o tome kako ovi ključevi funkcionišu, proverite stranicu [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Napadi

iButtons se mogu napasti sa Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Reference

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
