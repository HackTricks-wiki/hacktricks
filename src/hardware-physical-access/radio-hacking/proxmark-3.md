# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanval op RFID-stelsels met Proxmark3

Installeer die aktief onderhoude RRG/Iceman Proxmark3-kliënt en ooreenstemmende firmware, en bevestig dan die opdragsintaksis met daardie bouweergawe, aangesien ouer opdragte hieronder moontlik verander het.<sup>[[1]](#references)[[5]](#references)</sup>

### Aanval op MIFARE Classic 1KB

MIFARE Classic 1K het **16 sectors**, elk met **4 blocks** van **16 bytes**. Vervaardigerblok 0 bevat die UID-/vervaardigerdata en is leesalleen op egte NXP-kaarte; spesiale kloon- of “magic”-kaarte kan moontlik herskryf word.<sup>[[1]](#references)[[2]](#references)</sup>\
Om toegang tot elke sector te kry, benodig jy **2 keys** (**A** en **B**), wat in **block 3 van elke sector** (die sector trailer) gestoor word. Die sector trailer stoor ook die **access bits** wat die **lees- en skryftoestemmings** vir **elke block** met behulp van die 2 keys bepaal.\
2 keys is nuttig om byvoorbeeld leestoestemming te gee as jy die eerste een ken en skryftoestemming as jy die tweede een ken.

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

Die Proxmark3 laat jou toe om ander aksies uit te voer, soos om **Tag-na-leser-kommunikasie af te luister** om sensitiewe data te probeer vind. Met hierdie kaart kan jy bloot die kommunikasie afluister en die gebruikte sleutel bereken, omdat die **kriptografiese bewerkings wat gebruik word swak is**. As jy die gewone teks en syferteks ken, kan jy dit bereken (`mfkey64`-nutsding).<sup>[[3]](#references)</sup>

#### MiFare Classic: vinnige werkvloei vir misbruik van gestoorde waarde

Vir die sleutelherwinning-, balansvergelykings-, integriteitsveld- en UID-kloningvolgorde—insluitend die Proxmark3-kliënttranskripsie en beperkings van magiese kaarte—sien [MiFare Classic se vanlyn peutering met gestoorde waardes](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Rou opdragte

IoT-stelsels gebruik soms **ongemerkte of nie-kommersiële tags**. In dié geval kan jy Proxmark3 gebruik om pasgemaakte **rou opdragte na die tags te stuur**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Met hierdie inligting kan jy probeer om inligting oor die kaart en die manier waarop jy daarmee kan kommunikeer, te soek. Proxmark3 laat jou toe om rou opdragte te stuur, soos: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-sagteware bevat ’n voorafgelaaide lys **outomatiseringskripte** wat jy kan gebruik om eenvoudige take uit te voer. Gebruik die opdrag `script list` om die volledige lys te kry. Gebruik daarna die opdrag `script run`, gevolg deur die naam van die skrip:

```
proxmark3> script run mfkeys
```

Jy kan ’n skrip skep om **tag-lesers te fuzz**. Nadat jy die data van ’n **geldige kaart** gekopieer het, skryf bloot ’n **Lua-skrip** wat een of meer ewekansige **bytes** lukraak verander en kyk of die **leser** met enige iterasie ineenstort.

## References

- [1] [Proxmark3-wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3-wiki: HF Magic-kaarte](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP-verklaring oor MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Uitbuiting van NFC-kaartkwesbaarheid in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 van RRG/Iceman — Linux-installasie](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
