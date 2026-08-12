# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#id-9wrzi" id="id-9wrzi"></a>

Za informacije o RFID i NFC proverite sledeću stranicu:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Podržane NFC kartice <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Pored NFC kartica, Flipper Zero podržava **druge tipove kartica visoke frekvencije**, kao što su neke **Mifare** Classic i Ultralight i **NTAG** kartice.

Lista mogućnosti u nastavku opisuje firmware dokumentovan u originalnom članku i ne treba je smatrati trenutnom iscrpnom matricom podrške. Flipper firmware je vremenom dodao protokole i promenio NFC ponašanje; proverite aktuelnu zvaničnu dokumentaciju za instalirani firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bankarske kartice (EMV)** — mogu se pročitati samo UID, SAK i ATQA, bez čuvanja.
- **Nepoznate kartice** — mogu se pročitati UID, SAK i ATQA i emulirati UID.

Za **NFC tipove kartica B, F i V**, dokumentovani firmware je mogao da pročita UID bez njegovog čuvanja.

### NFC kartice tipa A <a href="#uvusf" id="uvusf"></a>

#### Bankarska kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Dokumentovani firmware je mogao da pročita UID, SAK, ATQA i dostupne podatke aplikacije sa bankarske kartice **bez čuvanja**.

Za ove bankarske kartice, firmware je prikazivao podatke bez čuvanja ili emuliranja kartice.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#id-37eo8" id="id-37eo8"></a>

Kada Flipper Zero **ne može da utvrdi tip NFC kartice**, tada se mogu **pročitati i sačuvati** samo **UID, SAK i ATQA**.

Za nepoznatu NFC karticu, ovaj režim može da emulira samo njen UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipova B, F i V <a href="#wyg51" id="wyg51"></a>

U firmware-u dokumentovanom u originalnom članku, kod NFC kartica tipova B, F i V mogao je da se pročita i prikaže samo identifikator, bez njegovog čuvanja.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Radnje

Za uvod u NFC [**pročitajte ovu stranicu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Čitanje

Flipper Zero može da čita NFC kartice, ali ne implementira svaki protokol višeg nivoa izgrađen na ISO 14443. Zbog toga može da dohvati UID, SAK i ATQA niskog nivoa, dok protokol aplikacije ostaje nepoznat. Kod primitivnih sistema kontrole pristupa koji autorizaciju vrše samo na osnovu UID-a, alat može da pročita, ručno unese i emulira taj identifikator; kriptografski autentifikovani sistemi zahtevaju više od kopiranog UID-a.<sup>[[1]](#references)</sup>

#### Čitanje UID-a NASPRAM čitanja podataka unutar kartice <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

U Flipper-u, čitanje tagova frekvencije 13.56 MHz može se podeliti na dva dela:<sup>[[1]](#references)</sup>

- **Čitanje niskog nivoa** — čita samo UID, SAK i ATQA. Flipper pokušava da pogodi protokol višeg nivoa na osnovu ovih podataka pročitanih sa kartice. Ne možete biti 100% sigurni u ovo, jer je to samo pretpostavka zasnovana na određenim faktorima.
- **Čitanje visokog nivoa** — čita podatke iz memorije kartice koristeći određeni protokol višeg nivoa. To može biti čitanje podataka sa Mifare Ultralight kartice, čitanje sektora sa Mifare Classic kartice ili čitanje atributa kartice sa PayPass/Apple Pay kartice.

### Specifično čitanje

Ako Flipper Zero nije u stanju da utvrdi tip kartice na osnovu podataka niskog nivoa, u odeljku `Extra Actions` možete izabrati `Read Specific Card Type` i **ručno** **navesti tip kartice koji želite da pročitate**.

#### EMV bankarske kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Starije verzije Flipper firmware-a i kompatibilne EMV kartice mogle su da izlože više od UID-a, potencijalno uključujući PAN, datum isteka, ime vlasnika kartice ili zapis transakcija, kada su ti zapisi bili dostupni na kartici. Dostupnost zavisi od kartice, aplikacije i firmware-a. CVV sa magnetne trake odštampan na kartici nije dostupan na ovaj način, a čitanje ovih zapisa ne klonira kriptografsku funkcionalnost transakcije potrebnu za beskontaktno plaćanje.<sup>[[1]](#references)</sup>

## References

- [1] [Upoznavanje sa RFID protokolima uz Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero dokumentacija - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
