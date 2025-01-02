# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanval op RFID-stelsels met Proxmark3

Die eerste ding wat jy moet doen is om 'n [**Proxmark3**](https://proxmark.com) te hê en [**die sagteware en sy afhanklikhede te installeer**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Aanval op MIFARE Classic 1KB

Dit het **16 sektore**, elkeen het **4 blokke** en elke blok bevat **16B**. Die UID is in sektor 0 blok 0 (en kan nie verander word nie).\
Om toegang tot elke sektor te verkry, het jy **2 sleutels** (**A** en **B**) wat in **blok 3 van elke sektor** gestoor is (sektor trailer). Die sektor trailer stoor ook die **toegangsbits** wat die **lees en skryf** regte op **elke blok** gee met behulp van die 2 sleutels.\
2 sleutels is nuttig om regte te gee om te lees as jy die eerste een ken en te skryf as jy die tweede een ken (byvoorbeeld).

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
Die Proxmark3 maak dit moontlik om ander aksies uit te voer soos **afluister** 'n **Tag na Leser kommunikasie** om te probeer om sensitiewe data te vind. In hierdie kaart kan jy net die kommunikasie snuffel en die gebruikte sleutel bereken omdat die **kryptografiese operasies wat gebruik word swak is** en deur die plain en cipher teks te ken, kan jy dit bereken (`mfkey64` tool).

### Rauwe Opdragte

IoT-stelsels gebruik soms **nie-gemerkte of nie-kommersiële tags**. In hierdie geval kan jy Proxmark3 gebruik om pasgemaakte **rauwe opdragte na die tags** te stuur.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier om met dit te kommunikeer, te soek. Proxmark3 laat jou toe om rou opdragte te stuur soos: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3 sagteware kom met 'n vooraf gelaaide lys van **outomatiseringsskripte** wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te verkry, gebruik die `script list` opdrag. Gebruik dan die `script run` opdrag, gevolg deur die skrip se naam:
```
proxmark3> script run mfkeys
```
U kan 'n skrif skep om **fuzz tag readers** te doen, so om die data van 'n **geldige kaart** te kopieer, skryf net 'n **Lua-skrif** wat een of meer willekeurige **bytes** randomiseer en kyk of die **leser crash** met enige iterasie. 

{{#include ../../banners/hacktricks-training.md}}
