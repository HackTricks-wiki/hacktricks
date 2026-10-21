# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Napadi na RFID sisteme pomoću Proxmark3

Instalirajte aktivno održavani RRG/Iceman Proxmark3 klijent i odgovarajući firmware, a zatim proverite sintaksu komandi za tu verziju jer su starije komande navedene ispod možda izmenjene.<sup>[[1]](#references)[[5]](#references)</sup>

### Napad na MIFARE Classic 1KB

MIFARE Classic 1K ima **16 sektora**, a svaki sektor sadrži **4 bloka** od po **16 bajtova**. Blok proizvođača 0 sadrži UID/podatke proizvođača i na originalnim NXP karticama je samo za čitanje; posebne klonirane ili „magic“ kartice mogu omogućavati njegovo prepisivanje.<sup>[[1]](#references)[[2]](#references)</sup>\
Za pristup svakom sektoru potrebna su vam **2 ključa** (**A** i **B**), koji se čuvaju u **bloku 3 svakog sektora** (sektorski trailer). Sektorski trailer čuva i **access bitove** koji određuju dozvole za **čitanje i pisanje** za **svaki blok** pri korišćenju jednog od ta 2 ključa.\
Dva ključa su korisna, na primer, za davanje dozvole za čitanje ako znate prvi ključ i za pisanje ako znate drugi.

Može se izvesti nekoliko napada

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

Proxmark3 omogućava i druge radnje, poput **prisluškivanja** komunikacije **od taga ka čitaču**, kako bi se pokušali pronaći osetljivi podaci. Kod ove kartice možete samo da prisluškujete komunikaciju i izračunate korišćeni ključ jer su **korišćene kriptografske operacije slabe**, a poznavanje otvorenog i šifrovanog teksta omogućava da ga izračunate (alatka `mfkey64`).<sup>[[3]](#references)</sup>

#### Brzi postupak za zloupotrebu sačuvane vrednosti na MiFare Classic karticama

Za sekvencu oporavka ključa, poređenja stanja računa, provere polja integriteta i kloniranja UID-a — uključujući transkript Proxmark3 klijenta i ograničenja magic kartica — pogledajte [MiFare Classic offline stored-value tampering](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Sirove komande

IoT sistemi ponekad koriste **nebrendirane ili nekomercijalne tagove**. U tom slučaju možete koristiti Proxmark3 za slanje prilagođenih **sirovih komandi tagovima**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Na osnovu ovih informacija možete pokušati da pronađete informacije o kartici i načinu komunikacije s njom. Proxmark3 omogućava slanje sirovih komandi, kao što je: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 softver dolazi s unapred učitanom listom **automatizovanih skripti** koje možete koristiti za jednostavne zadatke. Da biste dobili celu listu, upotrebite komandu `script list`. Zatim upotrebite komandu `script run`, a za njom naziv skripte:

```
proxmark3> script run mfkeys
```

Možete da napravite skriptu za **fuzz testiranje čitača tagova**: kopirajte podatke sa **važeće kartice**, napišite samo **Lua skriptu** koja **nasumično menja** jedan ili više nasumičnih **bajtova** i proverite da li se **čitač ruši** u bilo kojoj iteraciji.

## References

- [1] [Proxmark3 viki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 viki: HF Magic kartice](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP izjava o Crypto1 u MIFARE Classic karticama](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Iskorišćavanje ranjivosti NFC kartice u KioSoft Stored Value sistemu (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — instalacija za Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
