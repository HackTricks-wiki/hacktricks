# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Za informacije o RFID i NFC pogledajte sledeću stranicu:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Podržane NFC kartice <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Pored NFC kartica, Flipper Zero podržava **druge tipove visokofrekventnih kartica** kao što su nekoliko **Mifare** Classic i Ultralight i **NTAG**.

Novi tipovi NFC kartica biće dodati na listu podržanih kartica. Flipper Zero podržava sledeće **tipove NFC kartica A** (ISO 14443A):

- **Bankovne kartice (EMV)** — samo čitanje UID, SAK i ATQA bez čuvanja.
- **Nepoznate kartice** — čitanje (UID, SAK, ATQA) i emulacija UID.

Za **NFC kartice tipa B, tipa F i tipa V**, Flipper Zero može da pročita UID bez čuvanja.

### NFC kartice tip A <a href="#uvusf" id="uvusf"></a>

#### Bankovna kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero može da pročita samo UID, SAK, ATQA i sačuvane podatke na bankovnim karticama **bez čuvanja**.

Ekran za čitanje bankovnih karticaFlipper Zero može da pročita podatke na bankovnim karticama **bez čuvanja i emulacije**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#id-37eo8" id="id-37eo8"></a>

Kada Flipper Zero **nije u mogućnosti da odredi tip NFC kartice**, tada se može **pročitati i sačuvati samo UID, SAK i ATQA**.

Ekran za čitanje nepoznatih karticaZa nepoznate NFC kartice, Flipper Zero može da emulira samo UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipa B, F i V <a href="#wyg51" id="wyg51"></a>

Za **NFC kartice tipa B, F i V**, Flipper Zero može samo **pročitati i prikazati UID** bez čuvanja.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Akcije

Za uvod o NFC [**pročitajte ovu stranicu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Čitanje

Flipper Zero može **čitati NFC kartice**, međutim, **ne razume sve protokole** koji se zasnivaju na ISO 14443. Ipak, pošto je **UID niska atribut**, možete se naći u situaciji kada je **UID već pročitan, ali je visoko nivo protokol prenosa podataka još uvek nepoznat**. Možete čitati, emulirati i ručno unositi UID koristeći Flipper za primitivne čitače koji koriste UID za autorizaciju.

#### Čitanje UID VS Čitanje Podataka Unutra <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

U Flipperu, čitanje 13.56 MHz oznaka može se podeliti na dva dela:

- **Nisko nivo čitanje** — čita samo UID, SAK i ATQA. Flipper pokušava da pogodi visoko nivo protokol na osnovu ovih podataka pročitanih sa kartice. Ne možete biti 100% sigurni u ovo, jer je to samo pretpostavka zasnovana na određenim faktorima.
- **Visoko nivo čitanje** — čita podatke iz memorije kartice koristeći specifičan visoko nivo protokol. To bi bilo čitanje podataka na Mifare Ultralight, čitanje sektora sa Mifare Classic, ili čitanje atributa kartice sa PayPass/Apple Pay.

### Čitaj Specifično

U slučaju da Flipper Zero nije u mogućnosti da pronađe tip kartice iz niskonivo podataka, u `Dodatnim Akcijama` možete odabrati `Pročitaj Specifičan Tip Kartice` i **ručno** **naznačiti tip kartice koju želite da pročitate**.

#### EMV Bankovne Kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Pored jednostavnog čitanja UID, možete izvući mnogo više podataka sa bankovne kartice. Moguće je **dobiti puni broj kartice** (16 cifara na prednjoj strani kartice), **datum važenja**, i u nekim slučajevima čak i **ime vlasnika** zajedno sa listom **najnovijih transakcija**.\
Međutim, **ne možete pročitati CVV na ovaj način** (3 cifre na poleđini kartice). Takođe, **bankovne kartice su zaštićene od replay napada**, tako da kopiranje sa Flipperom i zatim pokušaj emulacije za plaćanje ne će uspeti.

## Reference

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
