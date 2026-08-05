# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#id-9wrzi" id="id-9wrzi"></a>

Za informacije o RFID i NFC proverite sledeću stranicu:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Podržane NFC kartice <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Pored NFC kartica, Flipper Zero podržava **druge tipove High-frequency kartica**, kao što su neke **Mifare** Classic i Ultralight kartice, kao i **NTAG**.

Novi tipovi NFC kartica biće dodati na listu podržanih kartica. Flipper Zero podržava sledeće **NFC kartice tipa A** (ISO 14443A):

- **Bankarske kartice (EMV)** — samo čitanje UID, SAK i ATQA vrednosti bez čuvanja.
- **Nepoznate kartice** — čitanje (UID, SAK, ATQA) i emulacija UID vrednosti.

Za **NFC kartice tipa B, tipa F i tipa V**, Flipper Zero može da pročita UID bez čuvanja.

### NFC kartice tipa A <a href="#uvusf" id="uvusf"></a>

#### Bankarska kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero može da pročita samo UID, SAK, ATQA i sačuvane podatke na bankarskim karticama **bez čuvanja**.

Ekran za čitanje bankarske karticeZa bankarske kartice, Flipper Zero može da pročita podatke samo **bez njihovog čuvanja i emulacije**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#id-37eo8" id="id-37eo8"></a>

Kada Flipper Zero **ne može da utvrdi tip NFC kartice**, mogu se **pročitati i sačuvati** samo **UID, SAK i ATQA** vrednosti.

Ekran za čitanje nepoznate karticeZa nepoznate NFC kartice, Flipper Zero može da emulira samo UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipa B, F i V <a href="#wyg51" id="wyg51"></a>

Za **NFC kartice tipa B, F i V**, Flipper Zero može samo da **pročita i prikaže UID** bez njegovog čuvanja.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Radnje

Za uvod u NFC [**pročitajte ovu stranicu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Čitanje

Flipper Zero može da **čita NFC kartice**, međutim, **ne razume sve protokole** zasnovane na ISO 14443. Ipak, pošto je **UID atribut niskog nivoa**, možete se naći u situaciji u kojoj je **UID već pročitan, ali je protokol prenosa podataka visokog nivoa i dalje nepoznat**. Možete da pročitate, emulirate i ručno unesete UID koristeći Flipper za primitivne čitače koji koriste UID za autorizaciju.<sup>[[1]](#references)</sup>

#### Čitanje UID vrednosti NASPRAM čitanja podataka iznutra <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

U Flipper-u, čitanje kartica frekvencije 13.56 MHz može se podeliti na dva dela:<sup>[[1]](#references)</sup>

- **Čitanje niskog nivoa** — čita samo UID, SAK i ATQA. Flipper pokušava da na osnovu ovih podataka pročitanih sa kartice pretpostavi protokol visokog nivoa. Ne možete biti 100% sigurni u ovo, jer je to samo pretpostavka zasnovana na određenim faktorima.
- **Čitanje visokog nivoa** — čita podatke iz memorije kartice koristeći određeni protokol visokog nivoa. To može biti čitanje podataka na Mifare Ultralight kartici, čitanje sektora sa Mifare Classic kartice ili čitanje atributa kartice sa PayPass/Apple Pay kartice.

### Specifično čitanje

Ako Flipper Zero nije u mogućnosti da pronađe tip kartice na osnovu podataka niskog nivoa, u odeljku `Extra Actions` možete izabrati `Read Specific Card Type` i **ručno** **navesti tip kartice koji želite da pročitate**.

#### EMV bankarske kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Osim jednostavnog čitanja UID vrednosti, sa bankarske kartice možete izvući mnogo više podataka. Moguće je **dobiti puni broj kartice** (16 cifara na prednjoj strani kartice), **datum važenja**, a u nekim slučajevima čak i **ime vlasnika**, zajedno sa spiskom **najnovijih transakcija**.\
Međutim, na ovaj način **ne možete pročitati CVV** (3 cifre na poleđini kartice). Takođe, **bankarske kartice su zaštićene od replay attacks**, pa njihovo kopiranje pomoću Flipper-a, a zatim pokušaj emulacije radi plaćanja, neće funkcionisati.<sup>[[1]](#references)</sup>

## Reference

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
