# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#id-9wrzi" id="id-9wrzi"></a>

Informacije o RFID-u i NFC-u potražite na sledećoj stranici:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Podržane NFC kartice <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Pored NFC kartica, Flipper Zero podržava **i druge vrste visokofrekventnih kartica**, kao što su neke **Mifare** Classic i Ultralight, kao i **NTAG** kartice.

Lista mogućnosti u nastavku opisuje firmware dokumentovan u originalnom članku i ne treba je smatrati potpunim prikazom trenutno podržanih kartica. Firmware za Flipper je vremenom dodao protokole i promenio NFC funkcionalnost; proverite aktuelnu zvaničnu dokumentaciju za instalirani firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bankovne kartice (EMV)** — mogu se pročitati samo UID, SAK i ATQA, bez čuvanja.
- **Nepoznate kartice** — mogu se pročitati UID, SAK i ATQA, a UID se može emulirati.

Za **NFC kartice tipa B, F i V**, dokumentovani firmware mogao je da pročita UID, ali bez čuvanja.

### NFC kartice tipa A <a href="#uvusf" id="uvusf"></a>

#### Bankovna kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Dokumentovani firmware mogao je da pročita UID, SAK, ATQA i dostupne podatke o aplikaciji sa bankovne kartice, **bez čuvanja**.

Za ove bankovne kartice, firmware je prikazivao podatke bez čuvanja ili emuliranja kartice.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#id-37eo8" id="id-37eo8"></a>

Kada Flipper Zero **ne može da utvrdi tip NFC kartice**, mogu se **pročitati i sačuvati** samo **UID, SAK i ATQA**.

Za nepoznatu NFC karticu, ovaj režim može da emulira samo njen UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipa B, F i V <a href="#wyg51" id="wyg51"></a>

U firmware-u dokumentovanom u originalnom članku, za NFC kartice tipa B, F i V mogao je samo da se pročita i prikaže identifikator, bez čuvanja.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Radnje

Uvod u NFC potražite na [**read this page**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Čitanje

Flipper Zero može da čita NFC kartice, ali ne podržava svaki protokol višeg nivoa zasnovan na ISO 14443. Zato može da očita UID, SAK i ATQA na niskom nivou, a da pritom ne prepozna protokol aplikacije. Kod jednostavnih sistema za kontrolu pristupa koji proveravaju samo UID, alat može da pročita, ručno unese i emulira taj identifikator; sistemi sa kriptografskom autentifikacijom zahtevaju više od kopiranog UID-a.<sup>[[1]](#references)</sup>

#### Čitanje UID-a NASPRAM čitanja podataka na kartici <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

U Flipper-u, čitanje oznaka od 13,56 MHz može se podeliti na dva dela:<sup>[[1]](#references)</sup>

- **Čitanje na niskom nivou** — čita samo UID, SAK i ATQA. Flipper na osnovu ovih podataka sa kartice pokušava da pretpostavi protokol višeg nivoa. Ovaj rezultat nije potpuno pouzdan, jer je reč samo o pretpostavci zasnovanoj na određenim faktorima.
- **Čitanje na visokom nivou** — čita podatke iz memorije kartice pomoću određenog protokola višeg nivoa. To može biti čitanje podataka sa Mifare Ultralight kartice, čitanje sektora sa Mifare Classic kartice ili čitanje atributa kartice iz PayPass/Apple Pay sistema.

### Čitanje određenog tipa

Ako Flipper Zero ne može da utvrdi tip kartice na osnovu podataka niskog nivoa, u odeljku `Extra Actions` možete izabrati `Read Specific Card Type` i **ručno** **navesti tip kartice koju želite da pročitate**.

#### EMV bankovne kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Stariji firmware za Flipper i kompatibilne EMV kartice mogli su da otkriju više od UID-a, uključujući potencijalno PAN, datum isteka, ime vlasnika kartice ili evidenciju transakcija, ako su ti podaci bili dostupni na kartici. Dostupnost zavisi od kartice, aplikacije i firmware-a. CVV sa magnetne trake, odštampan na kartici, ne može se ovako očitati. Čitanje ovih zapisa takođe ne kopira kriptografsku funkcionalnost za transakcije potrebnu za beskontaktno plaćanje.<sup>[[1]](#references)</sup>

## References

- [1] [Uvod u RFID protokole uz Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Dokumentacija za Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
